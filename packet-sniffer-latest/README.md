<div align="center">

```
██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
██████╔╝███████║██║     █████╔╝ █████╗     ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║       ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
```

# 🕵️ Packet Sniffer

**A lightweight, cross-platform network packet analyzer built with Python.**  
Capture and analyze live network traffic in real-time — across Windows and Linux.

[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge)](https://github.com/)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()
[![Educational](https://img.shields.io/badge/Purpose-Educational-orange?style=for-the-badge)]()

</div>

---

## 📖 Overview

**Packet Sniffer** is a Python-based network diagnostic tool that captures and decodes packets flowing through your system's network adapters in real time — including Ethernet frames, IPv4/IPv6, TCP, UDP, ICMP, DNS queries, ARP, and HTTP requests. It features colorized output, protocol filtering via CLI flags, and optional JSON logging.

> ⚠️ **Disclaimer:** This tool is intended for **educational purposes and authorized network testing only**. Unauthorized packet sniffing may be illegal. Always ensure you have proper permission before monitoring any network.

---

## ✨ Features

| Feature | Details |
|---|---|
| 📡 Live packet capture | Captures all traffic across active network adapters |
| 🧩 Protocol support | Ethernet · ARP · IPv4 · IPv6 · TCP · UDP · ICMP · DNS · HTTP |
| 🎨 Colorized output | Each protocol has its own color — easy to scan at a glance |
| 🔍 Filtering | Filter by protocol, port, source IP, or destination IP |
| 📝 JSON logging | Save captured packets to an NDJSON log file |
| 🛑 Clean shutdown | Graceful Ctrl+C handling — turns off promiscuous mode safely |
| 🪟 Windows support | Raw socket via `AF_INET` (requires Administrator) |
| 🐧 Linux support | Raw socket via `PF_PACKET` (requires root/sudo) |

---

## 📂 Project Structure

```
📦 packet-sniffer/
 ┣ 📄 sniffer.py          ← Main entry point — CLI args, socket, capture loop
 ┣ 📄 parsers.py          ← Protocol parsers (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, ARP)
 ┣ 📄 display.py          ← Colorized terminal output using colorama
 ┣ 📄 logger.py           ← NDJSON packet logger
 ┣ 📄 requirements.txt    ← Python dependencies
 ┗ 📄 README.md
```

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/packet-sniffer.git
cd packet-sniffer
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🪟 Running on Windows

Open **Command Prompt as Administrator**, navigate to the project folder, and run:

```cmd
python sniffer.py
```

> Right-click CMD → *Run as Administrator*

---

## 🐧 Running on Linux

Open a terminal in the project directory and run with `sudo`:

```bash
sudo python3 sniffer.py
```

---

## 🎛️ CLI Options & Filters

```
usage: sniffer.py [--protocol {tcp,udp,icmp,arp,dns,http,all}]
                  [--port PORT] [--src-ip IP] [--dst-ip IP]
                  [--count N] [--log FILE] [--no-data]
```

| Flag | Description | Example |
|---|---|---|
| `--protocol` | Filter by protocol | `--protocol tcp` |
| `--port` | Filter by port number | `--port 443` |
| `--src-ip` | Only show packets from this IP | `--src-ip 192.168.1.5` |
| `--dst-ip` | Only show packets to this IP | `--dst-ip 8.8.8.8` |
| `--count` | Stop after N packets | `--count 50` |
| `--log` | Save packets to JSON log | `--log capture.json` |
| `--no-data` | Hide raw payload output | `--no-data` |

### Usage Examples

```bash
# Capture everything
python sniffer.py

# Show only TCP on port 443 (HTTPS)
python sniffer.py --protocol tcp --port 443

# Watch DNS queries in real time
python sniffer.py --protocol dns

# Track a specific host
python sniffer.py --src-ip 192.168.1.10

# Capture 100 packets and save to file
python sniffer.py --count 100 --log capture.json

# Show ICMP (ping) traffic only
python sniffer.py --protocol icmp --no-data
```

---

## 📸 Sample Output

```
════════════════════════════════════════════════════════════════════════════════════════
  Packet #1  │  OS: Linux
────────────────────────────────────────────────────────────────────────────────────────
  [ETH]   Dst: FF:FF:FF:FF:FF:FF  Src: A4:C3:F0:85:7D:12  Proto: ARP (0x0806)
  [ARP]   Request   192.168.1.1 (A4:C3:F0:85:7D:12)  →  192.168.1.50 (00:00:00:00:00:00)

════════════════════════════════════════════════════════════════════════════════════════
  Packet #2  │  OS: Linux
────────────────────────────────────────────────────────────────────────────────────────
  [ETH]   Dst: A4:C3:F0:85:7D:12  Src: 3C:22:FB:4A:D1:09  Proto: IPv4 (0x0800)
  [IPv4]  v4  192.168.1.50  →  8.8.8.8  Proto: UDP  TTL: 64  HLen: 20B
  [UDP]   54312  →  53  Length: 32B
  [DNS]   Query  TxID: 0xa1f3  Answers: 0  RCode: OK
         Query:  google.com  (A)

════════════════════════════════════════════════════════════════════════════════════════
  Packet #3  │  OS: Linux
────────────────────────────────────────────────────────────────────────────────────────
  [ETH]   Dst: 3C:22:FB:4A:D1:09  Src: A4:C3:F0:85:7D:12  Proto: IPv4 (0x0800)
  [IPv4]  v4  192.168.1.50  →  142.250.80.46  Proto: TCP  TTL: 64  HLen: 20B
  [TCP]   54910  →  80  Seq: 1482910  Ack: 0  Flags: [SYN]
  [HTTP]  GET /index.html  Host: example.com
```

---

## 🗂️ JSON Log Format

When `--log capture.json` is used, each packet is written as one line of NDJSON:

```json
{"__type": "session_start", "timestamp": "2024-11-01T10:00:00.000"}
{"__type": "packet", "packet_number": 1, "timestamp": "...", "protocol": "DNS", "src_ip": "192.168.1.50", "dst_ip": "8.8.8.8", "src_port": 54312, "dst_port": 53, "dns": {"is_response": false, "questions": ["google.com"]}}
{"__type": "packet", "packet_number": 2, "timestamp": "...", "protocol": "TCP", "src_ip": "192.168.1.50", "dst_ip": "142.250.80.46", "src_port": 54910, "dst_port": 80, "flags": {"SYN": 1}}
{"__type": "session_end", "timestamp": "...", "total_packets": 2}
```

You can process this with `jq`:
```bash
# Show all DNS queries
jq 'select(.protocol == "DNS") | .dns.questions' capture.json

# Show all unique destination IPs
jq 'select(.__type == "packet") | .dst_ip' capture.json | sort -u
```

---

## 🛠️ Built With

| Tool | Purpose |
|---|---|
| `socket` | Raw packet capture |
| `struct` | Binary protocol header parsing |
| `colorama` | Cross-platform terminal colors |
| `argparse` | CLI interface |
| `json` | Packet logging |

---

## 🔒 Ethical Use & Legal Notice

This project is built strictly for:

- 🎓 Educational and learning purposes
- 🔬 Authorized penetration testing
- 🛡️ Network diagnostics on **your own systems only**

**Never use this tool to intercept traffic on networks you do not own or have explicit permission to monitor.**

---

## 📜 Notice

This project is shared for **educational and learning purposes only**.  
Feel free to study the code, but please do not redistribute or use it commercially without permission.

© 2024 [Your Name] — All Rights Reserved.

---

<div align="center">

Made with ❤️ and Python

⭐ **Star this repo if you found it useful!** ⭐

</div>
