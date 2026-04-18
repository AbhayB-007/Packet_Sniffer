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
Capture, inspect, and analyze live network traffic on both Windows and Linux systems.

[![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

</div>

---

## 📖 Overview

**Packet Sniffer** is a Python-based network diagnostic tool that captures and displays packets flowing through your system's network adapters in real time. Whether you're a cybersecurity student, a network engineer, or just a curious developer — this tool gives you a transparent view into the data traveling across your network.

> ⚠️ **Disclaimer:** This tool is intended for **educational purposes and authorized network testing only**. Unauthorized packet sniffing may be illegal. Always ensure you have proper permission before monitoring any network.

---

## ✨ Features

- 📡 **Live packet capture** across all active network adapters
- 🪟 **Windows support** via raw socket access (Administrator required)
- 🐧 **Linux support** via raw socket access (Root required)
- 🔍 **Protocol parsing** — inspect IP headers, TCP/UDP layers, and more
- ⚡ **Lightweight** — no heavy dependencies, pure Python
- 🖥️ **CLI-based output** — simple and readable terminal display

---

## 🚀 Getting Started

### Prerequisites

- Python 3.x installed on your system
- Administrator / Root privileges (required for raw socket access)

---

## 🪟 Windows Installation & Usage

**Step 1** — Clone the repository or copy the source code into a file named `packet-sniffer-windows.py`

```bash
git clone https://github.com/AbhayB-007/Packet_Sniffer.git
```

**Step 2** — Open **Command Prompt as Administrator**

> Right-click on CMD → *Run as Administrator*

**Step 3** — Navigate to the directory where the file is saved

```cmd
cd path\to\packet-sniffer
```

**Step 4** — Run the script

```cmd
python packet-sniffer-windows.py
```

✅ The sniffer will start capturing and printing packets from your network adapters immediately.

---

## 🐧 Linux Installation & Usage

**Step 1** — Clone the repository or copy the source code into a file named `packet-sniffer-linux.py`

```bash
git clone https://github.com/AbhayB-007/Packet_Sniffer.git
```

**Step 2** — Open a terminal in the directory where the file is saved

**Step 3** — Run the script with root privileges

```bash
sudo python3 packet-sniffer-linux.py
```

✅ The sniffer will start capturing and printing packets from your network adapters immediately.

---

## 📸 Sample Output

```
-----------------------------------------------------------------------------------------------
                                 Sniffed Packet No. --> 1
                                 Operating System --> Windows
-----------------------------------------------------------------------------------------------
Ethernet Frame :
1). Destination MAC : 45:00:00:29:D6:9F
2). Source MAC : 40:00:80:06:26:2D
3). Protocol : 127
-----------------------------------------------------------------------------------------------
         -> IPv4 Packet:
                 - 1). Version: 0
                 - 2). Header Length: 0
                 - 3). TTL: 211
                 - 4). Protocol: 136
                 - 5). Source: 234.36.81.211
                 - 6). Target: 233.94.80.16
         -> TCP Segment:
                 - 1). Source Port: 1
                 - 2). Destination Port: 32512
                 - 3). Sequence: 119700
                 - 4). Acknowledgment: 3548928209
                 - Flags:
                         - URG: 1,  ACK: 0,  PSH:0
                         - RST: 1,  SYN: 0,  FIN:0
         -> ICMP Packet:
                 - 1). Type: 0
                 - 2). Code: 1
                 - 3). Checksum: 32512,
                 - ICMP Data:
                         \x00\x01\x7f\x00\x00\x01\xd3\x94\xd3\x88\x58\xd1\xea\x24\x51\xd3\xe9\x5e\x50
                         \x10\x20\xfa\x6b\x91\x00\x00\x00
         -> UDP Segment:
                 - 1). Source Port: 1
                 - 2). Destination Port: 32512
                 - 3). Length: 54164
-----------------------------------------------------------------------------------------------
```

---

## 📂 Project Structure

```
📦 packet-sniffer/
 ┣ 📄 packet-sniffer-windows.py   # Windows version
 ┣ 📄 packet-sniffer-linux.py     # Linux version
 ┗ 📄 README.md
```

---

## 🛠️ Built With

| Tool | Purpose |
|------|---------|
| ![Python](https://img.shields.io/badge/-Python-3776AB?style=flat&logo=python&logoColor=white) | Core language |
| `socket` | Raw packet capture |
| `struct` | Packet header parsing |

---

## 🔒 Ethical Use & Legal Notice

This project is built strictly for:

- 🎓 Educational and learning purposes
- 🔬 Authorized penetration testing
- 🛡️ Network diagnostics on your own systems

**Never use this tool to intercept traffic on networks you do not own or have explicit permission to test.**

---

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 Notice
This project has no license. It is shared for **educational and learning purposes only**.
Feel free to explore the code, but please do not redistribute or use it commercially without permission.

---

<div align="center">

Made with ❤️ and Python

⭐ **Star this repo if you found it useful!** ⭐

</div>
