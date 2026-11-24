#!/usr/bin/env python3
# ============================================================
#  Tool      : OSurge — Advanced Packet Crafter
#  Category  : OForensics / Network Analysis
#  Purpose   : ICMP / TCP / UDP crafting, traceroute,
#              latency measurement, firewall rule validation
#  Developer : khaled.s.haddad
#  Website   : owlsec.org
#  Version   : v1.0
#  Year      : 2026
#
#  Engine    : Scapy (preferred) → raw socket fallback
#  Requires  : pip install scapy   (optional but recommended)
#
#  AUTHORISED NETWORK TESTING USE ONLY
# ============================================================

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import signal
import socket
import statistics
import struct
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

# ─── SCAPY (OPTIONAL) ────────────────────────────────────────
try:
    from scapy.all import (
        IP, ICMP, TCP, UDP, Raw,
        send, sr1, conf as scapy_conf,
    )
    scapy_conf.verb = 0          # silence Scapy globally
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


# ═══════════════════════════════════════════════════════════════════════════════
#  SAFE-MODE TRANSMISSION GUARD  (defensive hardening)
# ───────────────────────────────────────────────────────────────────────────────
#  OSurge ships in SAFE (dry-run) mode by default. Packets are BUILT and
#  SUMMARISED but NOT put on the wire. Live transmission requires BOTH
#  --i-am-authorized AND a typed interactive confirmation.
# ═══════════════════════════════════════════════════════════════════════════════
SAFE_MODE = True
_SUPPRESSED_TX = 0

if HAVE_SCAPY:
    _raw_send = send
    _raw_sr1 = sr1
else:
    _raw_send = None
    _raw_sr1 = None

def _pkt_summary(packet):
    try:
        return packet.summary()
    except Exception:
        try:
            return f"raw:{len(packet)}B"
        except Exception:
            return "packet"

def _safe_warn(packet, count=1):
    global _SUPPRESSED_TX
    _SUPPRESSED_TX += count
    try:
        print(f"  {C.ORANGE}[SAFE-MODE]{C.RESET} suppressed TX "
              f"(x{count}): {_pkt_summary(packet)}")
    except Exception:
        pass

def send(packet, *args, **kwargs):
    """Layer-3 send, gated by SAFE_MODE."""
    if SAFE_MODE:
        cnt = int(kwargs.get("count", 1) or 1)
        _safe_warn(packet, cnt)
        return None
    if _raw_send is None:
        raise RuntimeError("Scapy send unavailable")
    return _raw_send(packet, *args, **kwargs)

def sr1(packet, *args, **kwargs):
    """Single-probe send/receive, gated by SAFE_MODE (returns None when safe)."""
    if SAFE_MODE:
        _safe_warn(packet, 1)
        return None
    if _raw_sr1 is None:
        raise RuntimeError("Scapy sr1 unavailable")
    return _raw_sr1(packet, *args, **kwargs)

def unlock_live_transmission(authorized_flag: bool) -> bool:
    """Leave SAFE_MODE only with --i-am-authorized + typed confirmation."""
    global SAFE_MODE
    if not SAFE_MODE:
        return True
    print()
    print(f"  {C.RED}{C.BOLD}*** LIVE ATTACK TRANSMISSION IS DISABLED (SAFE MODE) ***{C.RESET}")
    if not authorized_flag:
        print(f"  {C.DIM}Re-run with  --i-am-authorized  to enable live transmission on a")
        print(f"  network you own or are explicitly authorized to test.{C.RESET}")
        return False
    print(f"  {C.ORANGE}You passed --i-am-authorized. Live packet injection can disrupt")
    print(f"  production networks and is illegal without written authorization.{C.RESET}")
    try:
        ans = input("  Type exactly  I HAVE AUTHORIZATION  to proceed: ").strip()
    except (EOFError, KeyboardInterrupt):
        ans = ""
    if ans == "I HAVE AUTHORIZATION":
        SAFE_MODE = False
        print(f"  {C.RED}Live transmission ENABLED for this session.{C.RESET}")
        return True
    print(f"  {C.GREEN}Staying in SAFE (dry-run) mode. No packets will be transmitted.{C.RESET}")
    return False

# ─── TERMINAL COLOUR SUPPORT ─────────────────────────────────
_HAS_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def _cc(code: str) -> str:
    return code if _HAS_COLOR else ""

class C:
    RED     = _cc("\033[91m")
    GREEN   = _cc("\033[92m")
    YELLOW  = _cc("\033[93m")
    CYAN    = _cc("\033[96m")
    WHITE   = _cc("\033[97m")
    BOLD    = _cc("\033[1m")
    RESET   = _cc("\033[0m")
    MAGENTA = _cc("\033[95m")
    BLUE    = _cc("\033[94m")
    DIM     = _cc("\033[2m")
    ORANGE  = _cc("\033[38;5;214m")

def color(text: object, clr: str) -> str:
    if not _HAS_COLOR:
        return str(text)
    return clr + str(text) + C.RESET

# ─── VERSION ─────────────────────────────────────────────────
VERSION = "v1.0"
DEV     = "khaled.s.haddad"
SITE    = "owlsec.org"

# ─── LOGGING ─────────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
_log = logging.getLogger("osurge")

# ─── BANNER ──────────────────────────────────────────────────
def banner() -> None:
    print(color(r"""
   ██████╗ ███████╗██╗   ██╗██████╗  ██████╗ ███████╗
  ██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝ ██╔════╝
  ██║   ██║███████╗██║   ██║██████╔╝██║  ███╗█████╗
  ██║   ██║╚════██║██║   ██║██╔══██╗██║   ██║██╔══╝
  ╚██████╔╝███████║╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
""", C.CYAN))
    print(color(f"          OSurge — Advanced Packet Crafter  {VERSION}", C.MAGENTA))
    print(color("    ICMP | TCP | UDP | Flood | Spoof | Traceroute", C.WHITE))
    print()
    engine_str = (
        color("Scapy ✔", C.GREEN)
        if HAVE_SCAPY
        else color("Scapy ✘  (raw-socket fallback)", C.YELLOW)
    )
    print(
        color("  Developer : ", C.DIM) + color(DEV, C.CYAN)
        + color("   |   Website : ", C.DIM) + color(SITE, C.CYAN)
    )
    print(color("  Engine   : ", C.DIM) + engine_str)
    print(color("─" * 62, C.CYAN))
    print()


# ─── HELP ────────────────────────────────────────────────────
def show_help() -> None:
    W   = 60
    bdr = color("║", C.CYAN)

    def _row(inner: str) -> str:
        import re
        vis = len(re.sub(r"\033\[[0-9;]*m", "", inner))
        return bdr + inner + " " * max(W - vis, 0) + bdr

    print()
    print(color("╔" + "═" * W + "╗", C.CYAN))
    print(_row(color("             OSurge — Help & Usage", C.BOLD + C.WHITE)))
    print(color("╠" + "═" * W + "╣", C.CYAN))

    sections = [
        ("DESCRIPTION", [
            "OSurge crafts and sends raw network packets for",
            "authorized testing: latency, firewall validation,",
            "path discovery, and protocol analysis.",
        ]),
        ("MENU", [
            "[1] ICMP Ping      — Custom echo with TTL/size",
            "[2] TCP Probe      — SYN/ACK/FIN/RST with custom port",
            "[3] UDP Probe      — UDP datagram to target port",
            "[4] Flood Mode     — Rapid burst stress test",
            "[5] Traceroute     — TTL-based path discovery",
            "[6] Port Sweep     — TCP SYN sweep across port range",
            "[7] History        — View past session results",
            "[H] Help           — This page",
            "[X] Exit",
        ]),
        ("COMMON OPTIONS", [
            "• Source IP spoofing  (Scapy mode only)",
            "• Custom TTL, TOS, packet size, payload",
            "• TCP flags: SYN / ACK / FIN / RST / PSH / URG",
            "• Fragment: DF bit, MF bit",
            "• JSON stats auto-saved to history",
        ]),
        ("CLI", [
            "--mode icmp|tcp|udp|flood|trace|sweep",
            "--target IP/HOST  --port N  --count N",
            "--ttl N  --size N  --source IP  --flood",
            "--interval F  --timeout F  --no-color",
        ]),
        ("DISCLAIMER", [
            "Use ONLY on networks/systems you own or have",
            "explicit written authorisation to test.",
            "Unauthorised use is illegal and unethical.",
        ]),
    ]

    for title, lines in sections:
        print(_row(color(f"  ┌─ {title}", C.YELLOW)))
        for line in lines:
            print(_row(f"  │  {line}"))
        print(_row(""))
    print(color("╚" + "═" * W + "╝", C.CYAN))
    print()


# ─── HELPERS ─────────────────────────────────────────────────
def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def pause() -> None:
    input(color("\n  [↩] Press Enter to continue...", C.YELLOW))

def print_header(title: str) -> None:
    print()
    print(color("─" * 62, C.CYAN))
    print(color(f"  {title}", C.BOLD + C.CYAN))
    print(color("─" * 62, C.CYAN))

def section(title: str) -> None:
    print()
    print(color(f"  ┌─ {title}", C.YELLOW + C.BOLD))

def alert(msg: str, level: str = "HIGH") -> None:
    clr = (
        C.RED    if level == "HIGH" else
        C.ORANGE if level == "MED"  else
        C.YELLOW
    )
    print(f"  {color(f'[!] {level}:', clr + C.BOLD)} {color(msg, C.WHITE)}")

def ok(msg: str) -> None:
    print(f"  {color('[✔]', C.GREEN)}  {color(msg, C.WHITE)}")

def err(msg: str) -> None:
    print(f"  {color('[✘]', C.RED)}  {color(msg, C.RED)}")

def nfo(msg: str) -> None:
    print(f"  {color('[*]', C.CYAN)}  {color(msg, C.DIM + C.WHITE)}")

def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ts_compact() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def require_root() -> None:
    if os.name != "nt" and os.geteuid() != 0:
        err("OSurge requires root privileges.")
        nfo("Run with: sudo python3 OSurge.py")
        sys.exit(1)

def prompt(label: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    val  = input(
        color("  [»] ", C.YELLOW) + color(f"{label}{hint}: ", C.WHITE)
    ).strip()
    return val if val else default

def prompt_bool(label: str, default: bool = False) -> bool:
    d   = "Y/n" if default else "y/N"
    raw = input(
        color("  [»] ", C.YELLOW) + color(f"{label} [{d}]: ", C.WHITE)
    ).strip().lower()
    if not raw:
        return default
    return raw in ("y", "yes", "1", "true")


# ─── NETWORK UTILITIES ───────────────────────────────────────
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def resolve_host(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        err(f"Could not resolve: {target}")
        return None

def validate_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def validate_port(p: int) -> bool:
    return 1 <= p <= 65535


# ─── CONSTANTS ───────────────────────────────────────────────
IP_PROTO: Dict[str, int] = {"icmp": 1, "tcp": 6, "udp": 17}

TCP_FLAG_MAP: Dict[str, int] = {
    "S": 0x02, "A": 0x10, "F": 0x01,
    "R": 0x04, "P": 0x08, "U": 0x20,
}


# ═══════════════════════════════════════════════════════════════
#   SESSION CONFIG DATACLASS
# ═══════════════════════════════════════════════════════════════

@dataclass
class SessionConfig:
    target:      str   = ""
    protocol:    str   = "icmp"
    count:       int   = 4          # 0 = infinite
    interval:    float = 1.0
    size:        int   = 64
    ttl:         int   = 64
    tos:         int   = 0
    source:      str   = ""         # spoof source IP
    source_port: int   = 0          # 0 = random
    dest_port:   int   = 80
    flags:       Set[str] = field(default_factory=lambda: {"S"})
    window:      int   = 8192
    seq:         int   = 0          # 0 = random
    ack:         int   = 0
    icmp_type:   int   = 8
    icmp_code:   int   = 0
    df:          bool  = False
    flood:       bool  = False
    verbose:     bool  = False
    timeout:     float = 2.0
    payload:     Optional[bytes] = None


# ═══════════════════════════════════════════════════════════════
#   PACKET STATISTICS
# ═══════════════════════════════════════════════════════════════

class PacketStats:
    def __init__(self) -> None:
        self.sent:       int   = 0
        self.received:   int   = 0
        self.bytes_sent: int   = 0
        self.errors:     int   = 0
        self._rtts:      List[float] = []
        self._lock               = threading.Lock()
        self._start:     float = time.monotonic()

    def add_sent(self, size: int) -> None:
        with self._lock:
            self.sent       += 1
            self.bytes_sent += size

    def add_rtt(self, rtt: float) -> None:
        with self._lock:
            self.received += 1
            self._rtts.append(rtt)

    def add_error(self) -> None:
        with self._lock:
            self.errors += 1

    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def rate(self) -> float:
        e = self.elapsed()
        return self.sent / e if e > 0 else 0.0

    @property
    def rtts(self) -> List[float]:
        with self._lock:
            return list(self._rtts)

    def display(self, target: str, protocol: str) -> None:
        rtts    = self.rtts
        elapsed = self.elapsed()
        loss    = ((self.sent - self.received) / max(self.sent, 1)) * 100
        loss_clr = (
            C.GREEN  if loss == 0   else
            C.ORANGE if loss < 50   else
            C.RED
        )

        print()
        print(color("─" * 62, C.CYAN))
        section("Session Statistics")
        rows = [
            ("Target",      target,                                    C.WHITE),
            ("Protocol",    protocol.upper(),                         C.CYAN),
            ("Sent",        str(self.sent),                           C.WHITE),
            ("Received",    str(self.received),                       C.GREEN if self.received else C.DIM),
            ("Bytes Sent",  fmt_bytes(self.bytes_sent),               C.WHITE),
            ("Packet Loss", f"{loss:.1f}%",                           loss_clr),
            ("Rate",        f"{self.rate():.1f} pkt/s",               C.WHITE),
            ("Duration",    f"{elapsed:.3f}s",                        C.DIM),
        ]
        if self.errors:
            rows.append(("Errors", str(self.errors), C.RED))

        for key, val, clr in rows:
            print(f"    {color(key + ' :', C.CYAN):<28} {color(val, clr)}")

        if rtts:
            print()
            rtt_ms = [r * 1000 for r in rtts]
            jitter = statistics.stdev(rtt_ms) if len(rtt_ms) > 1 else 0.0
            print(f"    {color('RTT Min    :', C.CYAN):<28} {color(f'{min(rtt_ms):.3f} ms', C.GREEN)}")
            print(f"    {color('RTT Avg    :', C.CYAN):<28} {color(f'{sum(rtt_ms)/len(rtt_ms):.3f} ms', C.WHITE)}")
            print(f"    {color('RTT Max    :', C.CYAN):<28} {color(f'{max(rtt_ms):.3f} ms', C.RED)}")
            print(f"    {color('RTT Jitter :', C.CYAN):<28} {color(f'{jitter:.3f} ms', C.YELLOW)}")
        print()

    def to_dict(self, target: str, protocol: str) -> dict:
        rtts   = self.rtts
        rtt_ms = [r * 1000 for r in rtts]
        d: dict = {
            "timestamp":  stamp(),
            "target":     target,
            "protocol":   protocol,
            "sent":       self.sent,
            "received":   self.received,
            "bytes_sent": self.bytes_sent,
            "errors":     self.errors,
            "duration_s": round(self.elapsed(), 3),
            "rate_pps":   round(self.rate(), 2),
            "loss_pct":   round(
                (self.sent - self.received) / max(self.sent, 1) * 100, 2
            ),
        }
        if rtt_ms:
            d["rtt_min_ms"]    = round(min(rtt_ms), 3)
            d["rtt_avg_ms"]    = round(sum(rtt_ms) / len(rtt_ms), 3)
            d["rtt_max_ms"]    = round(max(rtt_ms), 3)
            d["rtt_jitter_ms"] = round(
                statistics.stdev(rtt_ms) if len(rtt_ms) > 1 else 0.0, 3
            )
        return d


# ═══════════════════════════════════════════════════════════════
#   SESSION HISTORY
# ═══════════════════════════════════════════════════════════════

HISTORY_FILE = Path.home() / ".osurge_history.json"
HISTORY_LIMIT = 200          # keep last N records


def log_session(record: dict) -> None:
    try:
        history: list = []
        if HISTORY_FILE.exists():
            try:
                history = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                history = []
        history.append(record)
        # Trim to limit
        if len(history) > HISTORY_LIMIT:
            history = history[-HISTORY_LIMIT:]
        HISTORY_FILE.write_text(
            json.dumps(history, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        _log.warning("History write failed: %s", exc)


def show_history() -> None:
    print_header("Session History")
    if not HISTORY_FILE.exists():
        nfo("No history found."); return
    try:
        history: list = json.loads(
            HISTORY_FILE.read_text(encoding="utf-8")
        )
    except Exception:
        err("Could not read history file."); return

    section(f"Records — {len(history)} stored  (showing last 30)")
    print(color(
        f"    {'Timestamp':<21} {'Proto':<6} {'Sent':<7} "
        f"{'Recv':<7} {'Loss':<8} {'Target'}",
        C.DIM,
    ))
    print(color("  " + "─" * 58, C.DIM))

    for e in history[-30:]:
        proto = f"{e.get('protocol', '?').upper():<6}"
        sent  = f"{e.get('sent', 0):<7}"
        recv  = f"{e.get('received', 0):<7}"
        loss  = f"{e.get('loss_pct', '?'):<7}%"
        r_clr = C.GREEN if e.get("received", 0) > 0 else C.DIM
        l_clr = C.GREEN if e.get("loss_pct", 100) == 0 else C.ORANGE
        print(
            f"    {color(e.get('timestamp', '')[:19], C.WHITE)}  "
            f"{color(proto, C.CYAN)}"
            f"{color(sent, C.WHITE)}"
            f"{color(recv, r_clr)}"
            f"{color(loss, l_clr)}"
            f"{color(e.get('target', ''), C.YELLOW)}"
        )
    print()


# ═══════════════════════════════════════════════════════════════
#   PACKET ENGINE — SCAPY
# ═══════════════════════════════════════════════════════════════

def _build_scapy_packet(target_ip: str, cfg: SessionConfig):
    """Build and return a Scapy packet object."""
    src = cfg.source or get_local_ip()
    ip  = IP(
        dst=target_ip,
        src=src,
        ttl=cfg.ttl,
        tos=cfg.tos,
    )
    if cfg.df:
        ip.flags = "DF"

    if cfg.protocol == "icmp":
        layer = ICMP(type=cfg.icmp_type, code=cfg.icmp_code)
    elif cfg.protocol == "tcp":
        flag_val = sum(TCP_FLAG_MAP.get(f, 0) for f in cfg.flags) or 0x02
        layer = TCP(
            dport=cfg.dest_port,
            sport=cfg.source_port or random.randint(1024, 65535),
            flags=flag_val,
            seq=cfg.seq or random.randint(0, 2**32 - 1),
            ack=cfg.ack,
            window=cfg.window,
        )
    else:  # udp
        layer = UDP(
            dport=cfg.dest_port,
            sport=cfg.source_port or random.randint(1024, 65535),
        )

    payload = cfg.payload or os.urandom(max(0, cfg.size - 40))
    return (ip / layer / Raw(load=payload)) if payload else (ip / layer)


def _scapy_send(
    target_ip: str,
    cfg:       SessionConfig,
    stats:     PacketStats,
    stop_evt:  threading.Event,
) -> None:
    try:
        pkt = _build_scapy_packet(target_ip, cfg)
    except Exception as exc:
        err(f"Packet build failed: {exc}")
        stop_evt.set()
        return

    while not stop_evt.is_set():
        try:
            # For TCP/UDP floods, rebuild with new random sport each time
            if cfg.flood and cfg.protocol != "icmp":
                pkt = _build_scapy_packet(target_ip, cfg)

            t0 = time.monotonic()
            send(pkt, verbose=False)
            stats.add_sent(len(pkt))

            if cfg.protocol == "icmp" and not cfg.flood:
                ans = sr1(pkt, timeout=cfg.timeout, verbose=False)
                if ans:
                    stats.add_rtt(time.monotonic() - t0)

        except Exception as exc:
            stats.add_error()
            if cfg.verbose:
                err(str(exc))

        if cfg.count and stats.sent >= cfg.count:
            stop_evt.set()
            break

        if not cfg.flood:
            time.sleep(cfg.interval)


# ═══════════════════════════════════════════════════════════════
#   PACKET ENGINE — RAW SOCKET FALLBACK
# ═══════════════════════════════════════════════════════════════

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def _build_raw_packet(target_ip: str, cfg: SessionConfig) -> bytes:
    src_ip   = cfg.source or get_local_ip()
    ip_id    = random.randint(1, 65535)
    proto_n  = IP_PROTO.get(cfg.protocol, 1)
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(target_ip)
    df_flag  = (1 << 14) if cfg.df else 0

    if cfg.protocol == "tcp":
        sport    = cfg.source_port or random.randint(1024, 65535)
        dport    = cfg.dest_port
        seq      = cfg.seq or random.randint(0, 2**32 - 1)
        flag_val = sum(TCP_FLAG_MAP.get(f, 0) for f in cfg.flags) or 2
        tcp_hdr  = struct.pack(
            "!HHLLBBHHH",
            sport, dport, seq, cfg.ack,
            (5 << 4), flag_val, cfg.window, 0, 0,
        )
        transport = tcp_hdr
    elif cfg.protocol == "udp":
        sport     = cfg.source_port or random.randint(1024, 65535)
        dport     = cfg.dest_port
        udp_hdr   = struct.pack("!HHHH", sport, dport, 8, 0)
        transport = udp_hdr
    else:  # icmp
        icmp_hdr  = struct.pack(
            "!BBHHH",
            cfg.icmp_type, cfg.icmp_code,
            0, random.randint(1, 65535), 1,
        )
        cs        = _checksum(icmp_hdr)
        icmp_hdr  = struct.pack(
            "!BBHHH",
            cfg.icmp_type, cfg.icmp_code,
            cs, random.randint(1, 65535), 1,
        )
        transport = icmp_hdr

    payload   = cfg.payload or os.urandom(max(0, cfg.size - 20 - len(transport)))
    body      = transport + (payload if isinstance(payload, bytes) else payload.encode())
    total_len = 20 + len(body)

    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) + 5, cfg.tos, total_len, ip_id,
        df_flag, cfg.ttl, proto_n, 0,
        ip_saddr, ip_daddr,
    )
    return ip_hdr + body


def _socket_send(
    target_ip: str,
    cfg:       SessionConfig,
    stats:     PacketStats,
    stop_evt:  threading.Event,
) -> None:
    while not stop_evt.is_set():
        try:
            pkt  = _build_raw_packet(target_ip, cfg)
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW,
                IP_PROTO.get(cfg.protocol, 1),
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            if SAFE_MODE:
                _safe_warn(pkt, 1)
                sock.close()
            else:
                sock.sendto(pkt, (target_ip, 0))
                stats.add_sent(len(pkt))
                sock.close()
        except PermissionError:
            err("Raw socket requires root privileges.")
            stop_evt.set()
            break
        except Exception as exc:
            stats.add_error()
            if cfg.verbose:
                err(str(exc))

        if cfg.count and stats.sent >= cfg.count:
            stop_evt.set()
            break

        if not cfg.flood:
            time.sleep(cfg.interval)


# ═══════════════════════════════════════════════════════════════
#   PROGRESS BAR THREAD
# ═══════════════════════════════════════════════════════════════

def _progress_loop(
    stats:    PacketStats,
    cfg:      SessionConfig,
    stop_evt: threading.Event,
) -> None:
    count = cfg.count
    while not stop_evt.is_set():
        sent = stats.sent
        rate = stats.rate()
        recv = stats.received

        if count > 0:
            pct    = min(sent / count, 1.0)
            filled = int(pct * 30)
            bar    = (
                color("█" * filled,       C.CYAN)
                + color("░" * (30 - filled), C.DIM)
            )
            sys.stdout.write(
                f"\r  {color('[»]', C.CYAN)} {bar}  "
                f"{color(str(sent), C.WHITE)}/{color(str(count), C.DIM)} "
                f"recv={color(str(recv), C.GREEN)}  "
                f"{color(f'{rate:.1f} pkt/s', C.DIM)}   "
            )
        else:
            sys.stdout.write(
                f"\r  {color('[»]', C.CYAN)}  "
                f"sent={color(str(sent), C.WHITE)}  "
                f"recv={color(str(recv), C.GREEN)}  "
                f"{color(fmt_bytes(stats.bytes_sent), C.DIM)}  "
                f"{color(f'{rate:.1f} pkt/s', C.CYAN)}   "
            )
        sys.stdout.flush()
        time.sleep(0.2)
    print()


# ═══════════════════════════════════════════════════════════════
#   CORE RUN SESSION
# ═══════════════════════════════════════════════════════════════

def run_session(cfg: SessionConfig) -> PacketStats:
    """
    Execute a packet session.
    Returns PacketStats after completion.
    """
    target_ip = resolve_host(cfg.target)
    if not target_ip:
        return PacketStats()

    stats    = PacketStats()
    stop_evt = threading.Event()

    send_fn: Callable = _scapy_send if HAVE_SCAPY else _socket_send

    # ── Config display ────────────────────────────────────────
    print()
    print(color("─" * 62, C.CYAN))
    section("Session Config")
    display_rows = [
        ("Target",    target_ip + (f"  ({cfg.target})" if cfg.target != target_ip else ""), C.WHITE + C.BOLD),
        ("Protocol",  cfg.protocol.upper(),   C.CYAN),
    ]
    if cfg.source:
        display_rows.append(("Source (spoofed)", cfg.source, C.YELLOW))
    if cfg.protocol in ("tcp", "udp"):
        display_rows.append(("Port", str(cfg.dest_port), C.WHITE))
    if cfg.protocol == "tcp":
        display_rows.append(("Flags", "".join(sorted(cfg.flags)), C.YELLOW))
    display_rows += [
        ("Size",     f"{cfg.size} bytes",  C.WHITE),
        ("TTL",      str(cfg.ttl),         C.WHITE),
        ("Count",    str(cfg.count) if cfg.count else color("∞  infinite", C.DIM), C.WHITE),
        ("Interval", f"{cfg.interval}s",   C.DIM),
        ("Flood",    color("yes  (burst mode)", C.ORANGE) if cfg.flood else color("no", C.DIM), ""),
        ("Engine",   color("Scapy", C.GREEN) if HAVE_SCAPY else color("raw socket", C.YELLOW), ""),
    ]
    for key, val, clr in display_rows:
        print(f"    {color(key + ' :', C.CYAN):<28} {color(val, clr) if clr else val}")

    print()
    print(color("  [*] Press Ctrl+C to stop\n", C.DIM))

    # ── Threads ───────────────────────────────────────────────
    send_t = threading.Thread(
        target=send_fn,
        args=(target_ip, cfg, stats, stop_evt),
        daemon=True,
    )
    prog_t = threading.Thread(
        target=_progress_loop,
        args=(stats, cfg, stop_evt),
        daemon=True,
    )

    try:
        send_t.start()
        prog_t.start()
        while send_t.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(color("\n  [!] Interrupted by user.", C.YELLOW))
    finally:
        stop_evt.set()
        send_t.join(timeout=3)

    stats.display(cfg.target, cfg.protocol)

    record = stats.to_dict(cfg.target, cfg.protocol)
    log_session(record)

    if prompt_bool("Export stats to JSON?", default=False):
        fname = f"osurge_{target_ip.replace('.','_')}_{cfg.protocol}_{ts_compact()}.json"
        try:
            Path(fname).write_text(json.dumps(record, indent=2), encoding="utf-8")
            ok(f"Saved: {fname}")
        except OSError as exc:
            err(f"Export failed: {exc}")

    return stats


# ═══════════════════════════════════════════════════════════════
#   COMMON OPTION COLLECTOR
# ═══════════════════════════════════════════════════════════════

def ask_common() -> SessionConfig:
    cfg = SessionConfig()

    raw = prompt("Packet count [0=infinite]", "4")
    cfg.count = int(raw) if raw.isdigit() else 4

    raw = prompt("Interval seconds", "1")
    try:    cfg.interval = float(raw)
    except: cfg.interval = 1.0

    raw = prompt("Packet size bytes", "64")
    cfg.size = int(raw) if raw.isdigit() else 64

    raw = prompt("TTL", "64")
    cfg.ttl = int(raw) if raw.isdigit() else 64

    raw = prompt("TOS / DSCP byte [0]", "0")
    try:    cfg.tos = int(raw, 0)
    except: cfg.tos = 0

    src = prompt("Spoof source IP [leave blank to skip]")
    if src:
        if validate_ip(src):
            cfg.source = src
        else:
            alert("Invalid IP — source spoofing skipped.", "MED")

    cfg.verbose = prompt_bool("Verbose errors?", default=False)
    cfg.df      = prompt_bool("Set DF (Don't Fragment) bit?", default=False)
    cfg.timeout = 2.0
    return cfg


# ═══════════════════════════════════════════════════════════════
#   MODULES
# ═══════════════════════════════════════════════════════════════

def _get_target() -> Optional[str]:
    t = prompt("Target IP or hostname")
    if not t:
        err("No target provided.")
        return None
    return t


def module_icmp() -> None:
    print_header("ICMP Ping")
    print()
    t = _get_target()
    if not t: return

    cfg          = ask_common()
    cfg.target   = t
    cfg.protocol = "icmp"

    raw = prompt("ICMP type [8=echo]", "8")
    cfg.icmp_type = int(raw) if raw.isdigit() else 8
    cfg.icmp_code = 0
    cfg.flood     = prompt_bool("Flood mode?", default=False)

    run_session(cfg)


def module_tcp() -> None:
    print_header("TCP Probe")
    print()
    t = _get_target()
    if not t: return

    raw = prompt("Destination port", "80")
    try:
        port = int(raw)
        if not validate_port(port):
            raise ValueError
    except ValueError:
        err("Invalid port."); return

    print()
    print(color("  [*] TCP Flags:", C.DIM))
    flag_names = [
        ("1", "S", "SYN"), ("2", "A", "ACK"), ("3", "F", "FIN"),
        ("4", "R", "RST"), ("5", "P", "PSH"), ("6", "U", "URG"),
    ]
    for num, code, name in flag_names:
        print(f"  {color(f'[{num}]', C.GREEN)}  {color(code, C.WHITE)}  {color(name, C.DIM)}")
    print()

    flags_r = prompt("Flag numbers (e.g. 1 for SYN, 12 for SYN+ACK)", "1")
    flag_map = {"1": "S", "2": "A", "3": "F", "4": "R", "5": "P", "6": "U"}
    flags    = {flag_map[c] for c in flags_r if c in flag_map} or {"S"}

    raw_sp = prompt("Source port [0=random]", "0")
    try:   src_port = int(raw_sp)
    except: src_port = 0

    cfg             = ask_common()
    cfg.target      = t
    cfg.protocol    = "tcp"
    cfg.dest_port   = port
    cfg.flags       = flags
    cfg.source_port = src_port
    cfg.window      = 8192
    cfg.flood       = prompt_bool("Flood mode?", default=False)

    run_session(cfg)


def module_udp() -> None:
    print_header("UDP Probe")
    print()
    t = _get_target()
    if not t: return

    raw = prompt("Destination port", "53")
    try:
        port = int(raw)
        if not validate_port(port):
            raise ValueError
    except ValueError:
        err("Invalid port."); return

    cfg           = ask_common()
    cfg.target    = t
    cfg.protocol  = "udp"
    cfg.dest_port = port

    pl = prompt("Custom payload string [blank = random bytes]")
    cfg.payload = pl.encode() if pl else None
    cfg.flood   = prompt_bool("Flood mode?", default=False)

    run_session(cfg)


def module_flood() -> None:
    print_header("Flood Mode — Packet Burst")
    print()
    alert("Use ONLY on systems you own or have explicit authorisation to test.", "HIGH")
    print()

    t = _get_target()
    if not t: return

    print()
    choices = [
        ("1", "ICMP", "ICMP echo burst"),
        ("2", "TCP",  "TCP SYN burst"),
        ("3", "UDP",  "UDP datagram burst"),
    ]
    for num, proto, desc in choices:
        print(
            f"  {color(f'[{num}]', C.GREEN)}  "
            f"{color(proto, C.WHITE)}  "
            f"{color('─ ' + desc, C.DIM)}"
        )
    print()

    proto_r  = prompt("Protocol [1-3]", "1")
    proto    = {"1": "icmp", "2": "tcp", "3": "udp"}.get(proto_r, "icmp")

    port = 80
    if proto != "icmp":
        raw = prompt("Destination port", "80")
        try:
            port = int(raw)
            if not validate_port(port):
                port = 80
        except ValueError:
            pass

    raw = prompt("Packet count [0=infinite]", "0")
    count = int(raw) if raw.isdigit() else 0

    raw = prompt("Packet size bytes", "64")
    size = int(raw) if raw.isdigit() else 64

    src = prompt("Spoof source IP [blank to skip]")

    cfg             = SessionConfig()
    cfg.target      = t
    cfg.protocol    = proto
    cfg.dest_port   = port
    cfg.count       = count
    cfg.size        = size
    cfg.ttl         = 64
    cfg.interval    = 0.0
    cfg.source      = src if src and validate_ip(src) else ""
    cfg.flood       = True
    cfg.flags       = {"S"}
    cfg.icmp_type   = 8
    cfg.icmp_code   = 0
    cfg.timeout     = 1.0

    run_session(cfg)


def module_traceroute() -> None:
    print_header("Traceroute — TTL-based Path Discovery")
    print()

    t = _get_target()
    if not t: return

    ip = resolve_host(t)
    if not ip: return

    raw = prompt("Max hops", "30")
    max_hops = int(raw) if raw.isdigit() else 30

    raw = prompt("Timeout per hop (seconds)", "2")
    try:    hop_timeout = float(raw)
    except: hop_timeout = 2.0

    print()
    print(color("─" * 62, C.CYAN))
    section(f"Traceroute  →  {ip}")
    print(color(
        f"    {'Hop':<5} {'IP':<18} {'RTT':>10}   Host",
        C.DIM,
    ))
    print(color("  " + "─" * 55, C.DIM))

    if not HAVE_SCAPY:
        alert("Traceroute requires Scapy.  pip install scapy", "MED")
        return

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=ip, ttl=ttl) / ICMP()
        t0  = time.monotonic()
        try:
            ans = sr1(pkt, timeout=hop_timeout, verbose=False)
            rtt_ms = (time.monotonic() - t0) * 1000

            if ans:
                hop_ip  = ans.src
                rtt_col = (
                    C.GREEN  if rtt_ms < 50  else
                    C.YELLOW if rtt_ms < 150 else
                    C.RED
                )
                rtt_str = color(f"{rtt_ms:>8.2f} ms", rtt_col)
                try:
                    hostname = socket.gethostbyaddr(hop_ip)[0][:28]
                except Exception:
                    hostname = ""
                print(
                    f"    {color(str(ttl) + '.', C.DIM):<8}"
                    f"{color(hop_ip, C.CYAN):<20}"
                    f"{rtt_str}   "
                    f"{color(hostname, C.DIM)}"
                )
                if hop_ip == ip:
                    ok(f"Reached destination in {ttl} hop(s).")
                    break
            else:
                print(f"    {color(str(ttl) + '.', C.DIM):<8}{'* * *'}")

        except KeyboardInterrupt:
            print(color("\n  [!] Stopped.", C.YELLOW))
            break

    print()


def module_port_sweep() -> None:
    print_header("Port Sweep — TCP SYN Sweep")
    print()
    alert("Use ONLY on systems you own or have explicit authorisation.", "HIGH")
    print()

    if not HAVE_SCAPY:
        alert("Port sweep requires Scapy.  pip install scapy", "MED")
        return

    t = _get_target()
    if not t: return
    ip = resolve_host(t)
    if not ip: return

    raw_start = prompt("Start port", "1")
    raw_end   = prompt("End port",   "1024")
    try:
        p_start = max(1, int(raw_start))
        p_end   = min(65535, int(raw_end))
        if p_start > p_end:
            p_start, p_end = p_end, p_start
    except ValueError:
        err("Invalid port range."); return

    raw_t = prompt("Timeout per probe (seconds)", "0.5")
    try:   to = float(raw_t)
    except: to = 0.5

    total  = p_end - p_start + 1
    open_ports: List[int] = []

    print()
    nfo(f"Sweeping {ip}  ports {p_start}–{p_end}  ({total} ports)")
    print()

    try:
        for i, port in enumerate(range(p_start, p_end + 1), 1):
            sys.stdout.write(
                f"\r  {color('[»]', C.CYAN)}  "
                f"{i}/{total}  open={color(str(len(open_ports)), C.GREEN)}  "
                f"port={color(str(port), C.DIM)}" + " " * 10
            )
            sys.stdout.flush()

            pkt = IP(dst=ip) / TCP(dport=port, flags=0x02)
            ans = sr1(pkt, timeout=to, verbose=False)
            if ans and ans.haslayer(TCP):
                flags = ans.getlayer(TCP).flags
                if flags & 0x12:  # SYN-ACK
                    open_ports.append(port)
                    # Send RST to clean up
                    send(IP(dst=ip) / TCP(dport=port, flags=0x04), verbose=False)
    except KeyboardInterrupt:
        print(color("\n  [!] Stopped.", C.YELLOW))

    print()
    print()
    section(f"Open Ports on {ip}")
    if open_ports:
        for p in open_ports:
            try:
                svc = socket.getservbyport(p)
            except Exception:
                svc = "unknown"
            print(
                f"    {color(str(p) + '/tcp', C.GREEN):<20}  "
                f"{color(svc, C.DIM)}"
            )
    else:
        nfo("No open ports found in range.")
    print()



def run_self_test() -> int:
    """Offline sandboxed self-test — builds packets, never transmits."""
    banner()
    print(color("  OSurge Self-Test  (offline / SAFE-MODE)", C.CYAN + C.BOLD))
    print()
    passed = failed = 0
    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; ok(name)
        else:
            failed += 1; err(name)

    check("SAFE_MODE defaults to True", SAFE_MODE is True)
    check("HAVE_SCAPY is bool", isinstance(HAVE_SCAPY, bool))

    cfg = SessionConfig(protocol="icmp", count=1, size=64, flood=False)
    check("SessionConfig builds", cfg.protocol == "icmp")

    # Build packet without sending
    if HAVE_SCAPY:
        try:
            pkt = _build_scapy_packet("127.0.0.1", cfg)
            check("Scapy ICMP packet builds", pkt is not None)
        except Exception as e:
            check(f"Scapy ICMP packet builds ({e})", False)
        # Ensure send is suppressed
        before = _SUPPRESSED_TX
        send(pkt, verbose=False)
        check("SAFE-MODE suppresses send()", _SUPPRESSED_TX == before + 1)
    else:
        try:
            raw = _build_raw_packet("127.0.0.1", cfg)
            check("Raw ICMP packet builds", isinstance(raw, (bytes, bytearray)) and len(raw) > 20)
        except Exception as e:
            check(f"Raw ICMP packet builds ({e})", False)

    # Flag map sanity
    check("TCP SYN flag present", TCP_FLAG_MAP.get("S") == 2)

    print()
    if failed == 0:
        ok(f"ALL {passed} CHECKS PASSED — crafter healthy (SAFE-MODE on).")
        return 0
    err(f"{failed} FAILED, {passed} passed.")
    return 1

# ═══════════════════════════════════════════════════════════════
#   CLI NON-INTERACTIVE MODE
# ═══════════════════════════════════════════════════════════════

def cli_main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="osurge",
        description=f"OSurge {VERSION} — Packet Crafter",
    )
    ap.add_argument("--target",   required=False, default="", metavar="HOST")
    ap.add_argument("--mode",     default="icmp",
                    choices=["icmp", "tcp", "udp", "flood", "trace", "sweep"])
    ap.add_argument("--port",     type=int, default=80)
    ap.add_argument("--count",    type=int, default=4)
    ap.add_argument("--size",     type=int, default=64)
    ap.add_argument("--ttl",      type=int, default=64)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--timeout",  type=float, default=2.0)
    ap.add_argument("--source",   default="", metavar="IP")
    ap.add_argument("--flags",    default="S", metavar="FLAGS")
    ap.add_argument("--flood",    action="store_true", default=False)
    ap.add_argument("--no-color", action="store_true", default=False)
    ap.add_argument("--version",  action="version",
                    version=f"OSurge {VERSION} — {SITE}")

    args = ap.parse_args(argv)
    if getattr(args, 'self_test', False):
        return run_self_test()
    unlock_live_transmission(getattr(args, 'authorized', False))
    if not args.target:
        err('--target is required (except --self-test)')
        return 2

    if args.no_color:
        for attr in [a for a in dir(C) if not a.startswith("_")]:
            setattr(C, attr, "")

    require_root()
    banner()

    if args.mode in ("trace", "sweep"):
        if args.mode == "trace":
            module_traceroute.__module__  # just call directly
            # Inline quick traceroute
            ip = resolve_host(args.target)
            if not ip: return 1
            if not HAVE_SCAPY:
                err("Traceroute requires Scapy."); return 1
            for ttl in range(1, 31):
                pkt = IP(dst=ip, ttl=ttl) / ICMP()
                ans = sr1(pkt, timeout=args.timeout, verbose=False)
                if ans:
                    print(f"  {ttl:>3}  {ans.src}")
                    if ans.src == ip: break
                else:
                    print(f"  {ttl:>3}  *")
        return 0

    cfg          = SessionConfig()
    cfg.target   = args.target
    cfg.protocol = args.mode if args.mode not in ("flood",) else "icmp"
    cfg.count    = args.count
    cfg.size     = args.size
    cfg.ttl      = args.ttl
    cfg.interval = args.interval
    cfg.timeout  = args.timeout
    cfg.source   = args.source
    cfg.dest_port= args.port
    cfg.flood    = args.flood
    cfg.flags    = set(args.flags.upper())

    run_session(cfg)
    return 0


# ═══════════════════════════════════════════════════════════════
#   MAIN MENU
# ═══════════════════════════════════════════════════════════════

def main_menu() -> None:
    require_root()

    items = [
        ("1", "ICMP Ping",    "Custom echo with TTL/size control",  module_icmp),
        ("2", "TCP Probe",    "TCP with custom flags & port",        module_tcp),
        ("3", "UDP Probe",    "UDP datagram to target port",         module_udp),
        ("4", "Flood Mode",   "Rapid burst stress test",             module_flood),
        ("5", "Traceroute",   "TTL-based path discovery",            module_traceroute),
        ("6", "Port Sweep",   "TCP SYN sweep across port range",     module_port_sweep),
        ("7", "History",      "View past session results",           show_history),
    ]

    while True:
        clear()
        banner()
        print(color(f"  {stamp()}", C.DIM))
        print()

        for num, name, desc, _ in items:
            print(
                f"  {color(f'[{num}]', C.GREEN)}  "
                f"{color(name + ' ' * (18 - len(name)), C.WHITE)}"
                f"{color('─ ' + desc, C.DIM)}"
            )
        print()
        print(f"  {color('[H]', C.YELLOW)}  {color('Help', C.WHITE)}")
        print(f"  {color('[X]', C.RED)}  {color('Exit', C.WHITE)}")
        print()
        print(color("─" * 62, C.CYAN))

        choice = input(color("\n  [»] Select option: ", C.YELLOW)).strip().upper()

        if choice == "X":
            print(color(
                f"\n  [✔] Goodbye! — {SITE}  🦉\n", C.GREEN
            ))
            sys.exit(0)
        elif choice == "H":
            clear(); banner(); show_help(); pause()
        else:
            matched = next(
                ((fn, name) for num, name, _, fn in items if num == choice),
                None,
            )
            if matched:
                fn, name = matched
                clear(); banner()
                try:
                    fn()
                except KeyboardInterrupt:
                    print(color("\n  [!] Interrupted.", C.YELLOW))
                except Exception as exc:
                    _log.exception("Module error")
                    err(f"Error: {exc}")
                pause()
            else:
                err("Invalid option.")
                pause()


# ─── ENTRY POINT ─────────────────────────────────────────────

def _sigint_handler(sig: int, frame: object) -> None:  # noqa: ARG001
    print(color(f"\n\n  [!] Interrupted — {SITE}  🦉\n", C.YELLOW))
    sys.exit(0)


def main() -> None:
    signal.signal(signal.SIGINT, _sigint_handler)

    cli_flags = {"--target", "--mode", "--port", "--count", "--size",
                 "--ttl", "--interval", "--timeout", "--source",
                 "--flags", "--flood", "--no-color", "--version"}
    has_cli = any(
        a in cli_flags or a.startswith("--target=")
        for a in sys.argv[1:]
    )

    if has_cli:
        sys.exit(cli_main())
    else:
        try:
            main_menu()
        except KeyboardInterrupt:
            print(color(f"\n\n  [✔] Terminated — {SITE}  🦉\n", C.YELLOW))
        except SystemExit:
            pass
        except Exception as exc:
            _log.exception("Fatal error")
            err(f"Fatal: {exc}")
            sys.exit(1)


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(run_self_test())
    _auth = "--i-am-authorized" in sys.argv
    # Strip auth flag so argparse/menu logic is undisturbed for interactive
    if _auth and "--target" not in sys.argv:
        sys.argv = [a for a in sys.argv if a != "--i-am-authorized"]
        unlock_live_transmission(True)
    elif "--target" not in sys.argv:
        # Interactive: stay SAFE unless user re-runs with flag
        print(color("  [SAFE-MODE] Live TX disabled. Pass --i-am-authorized to unlock.", C.ORANGE))
    main()
