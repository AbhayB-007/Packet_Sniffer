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
git clone https://github.com/your-username/packet-sniffer.git
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
git clone https://github.com/your-username/packet-sniffer.git
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
=============================================
  Source IP       : 192.168.1.5
  Destination IP  : 142.250.80.46
  Protocol        : TCP
  Source Port     : 54312
  Destination Port: 443
  Data Length     : 128 bytes
=============================================
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

## 📜 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.

---

<div align="center">

Made with ❤️ and Python

⭐ **Star this repo if you found it useful!** ⭐

</div>
