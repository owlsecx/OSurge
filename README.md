# 🦉 OSurge

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-OAttack%20/%20Offensive-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OSurge** — Advanced Packet Crafter

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview


OSurge is an advanced packet crafter for ICMP, TCP and UDP that supports traceroute, latency measurement and firewall-rule validation. It uses Scapy when available and falls back to raw sockets, and ships in a safe dry-run mode by default: packets are built and summarised but not transmitted unless you explicitly authorize live sending. It is intended for authorized network testing only.

---

## ✨ Features


- Craft ICMP, TCP and UDP packets with control over port, count, size, TTL, flags and interval
- Traceroute, latency measurement and firewall-rule validation workflows
- Scapy-preferred engine with a raw-socket fallback when Scapy is absent
- SAFE dry-run mode by default; live transmission requires --i-am-authorized plus typed confirmation
- Configurable source address and timeout, with optional flood mode
- Colour toggle for piped output and an interactive menu

---

## ⚙️ Requirements

- **Linux**
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage


```bash
./OSurge --target 10.0.0.5 --mode icmp --count 4
./OSurge --target 10.0.0.5 --mode tcp --port 443 --flags S
./OSurge --target 10.0.0.5 --mode udp --port 53 --size 128 --ttl 32
./OSurge --help
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
