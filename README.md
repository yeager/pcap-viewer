# PCAP Viewer

A GTK4/Adwaita application for analyzing network packet captures (.pcap/.pcapng files) on Linux.

![Screenshot](docs/screenshot.png)

## Features

- Open and browse .pcap and .pcapng files
- Three-pane Wireshark-style layout: packet list, protocol layers, hex dump
- Protocol detection (TCP, UDP, DNS, HTTP, TLS, ICMP, ARP, …)
- Display filter by protocol, IP address, or keyword
- Protocol statistics, top talkers, conversation analysis
- Drag-and-drop file loading
- Internationalized (gettext-based, Transifex translations)

## Install

### From PyPI

```bash
pip install pcap-viewer
```

### From Debian repository

```bash
curl -fsSL https://yeager.github.io/debian-repo/pub.gpg | sudo gpg --dearmor -o /usr/share/keyrings/yeager.gpg
echo "deb [signed-by=/usr/share/keyrings/yeager.gpg] https://yeager.github.io/debian-repo stable main" | sudo tee /etc/apt/sources.list.d/yeager.list
sudo apt update && sudo apt install pcap-viewer
```

### From source

```bash
git clone https://github.com/yeager/pcap-viewer.git
cd pcap-viewer
pip install .
```

## Usage

```bash
pcap-viewer
# or open a file directly:
pcap-viewer capture.pcap
```

## Requirements

- Python 3.10+
- GTK 4, libadwaita
- Scapy

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).
