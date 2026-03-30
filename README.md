# 🦉 OSurge

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-informational?style=flat-square&logo=linux&logoColor=white&color=0a0c10"/>
  <img src="https://img.shields.io/badge/Category-ONetwork%20%2F%20Packet%20Crafting-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Requires-Root-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-2.0-cyan?style=flat-square"/>
</p>

> **OSurge** is an advanced packet crafter — craft and send custom ICMP, TCP, and UDP packets with full control over TTL, flags, source spoofing, payload, and flood mode, for authorised network testing and firewall rule validation.

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on networks and systems you own or have explicit permission to test. Unauthorised packet injection is illegal.

---

## 📌 Overview

OSurge sends raw crafted packets using either **Scapy** (full feature mode) or the Python standard library raw socket fallback. Every session produces live statistics — packets sent, received, packet loss, rate, and RTT — and can be exported as JSON.

---

## 🖥️ Modules

| # | Module | Description |
|---|--------|-------------|
| **[1] ICMP Ping** | Custom ICMP echo with configurable type, code, TTL, size, and flood mode |
| **[2] TCP Probe** | TCP packet with selectable flags (SYN/ACK/FIN/RST/PSH/URG), custom port, and flood mode |
| **[3] UDP Probe** | UDP datagram to a target port with optional custom payload or random data |
| **[4] Flood Mode** | Rapid packet burst — ICMP, TCP SYN, or UDP — configurable count (0 = infinite) |
| **[5] Trace Route** | TTL-based path discovery with per-hop RTT measurement and hostname resolution |
| **[6] History** | View the last 25 sessions from the persistent history log |

---

## ⚙️ Common Options

Every module shares a configurable parameter set:

| Parameter | Default | Description |
|-----------|---------|-------------|
| **Packet count** | `0` (infinite) | Stop after N packets, or run until Ctrl+C |
| **Interval** | `1.0s` | Delay between packets (ignored in flood mode) |
| **Packet size** | `64 bytes` | Total packet size including headers |
| **TTL** | `64` | IP Time-to-Live value |
| **Source IP** | Real IP | Spoof source address (requires Scapy + root) |
| **Flood mode** | Off | Send at maximum rate with no delay |
| **Verbose** | Off | Print errors inline during transmission |

---

## 🚩 TCP Flags

TCP Probe and Flood Mode support any combination of flags:

`SYN` · `ACK` · `FIN` · `RST` · `PSH` · `URG`

---

## 🔀 Dual Engine

| Engine | When Used | Features |
|--------|-----------|----------|
| **Scapy** | When installed | Full packet crafting, source spoofing, ICMP reply capture, fragmentation control (DF bit) |
| **Raw Socket** | Fallback (no Scapy) | Basic ICMP/TCP/UDP sending via stdlib — limited features, no reply capture |

The active engine is displayed in the banner on startup.

---

## 📊 Session Statistics

After every session, OSurge displays and logs:

| Metric | Description |
|--------|-------------|
| **Packets sent** | Total packets transmitted |
| **Packets received** | ICMP replies captured (Scapy mode) |
| **Bytes sent** | Total bytes transmitted |
| **Packet loss** | Percentage of unanswered packets |
| **Rate** | Packets per second (actual throughput) |
| **Duration** | Session elapsed time |
| **RTT Min/Avg/Max** | Round-trip time statistics (ICMP mode) |

---

## 📋 History & Export

- All sessions automatically logged to `~/.osurge_history.json`
- History viewer shows the last 25 sessions: timestamp, protocol, sent, received, target
- After each session, optionally export a JSON file: `osurge_<target>_<protocol>.json`

---

## ⚙️ Requirements

- **Linux** — uses raw sockets
- **Root privileges** — required for all modules
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage

```bash
sudo ./OSurge
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
