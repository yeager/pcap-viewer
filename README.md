# PCAP Viewer

A GTK4/Adwaita application for analyzing pcap/pcapng network captures.

## Features

- Open and browse .pcap and .pcapng files
- Three-pane Wireshark-style layout: packet list, protocol layers, hex dump
- Protocol detection (TCP, UDP, DNS, HTTP, TLS, ICMP, ARP, …)
- Display filter by protocol, IP address, or keyword
- Protocol statistics, top talkers, conversation analysis
- Drag-and-drop file loading
- Internationalized (gettext-based)

## Installation

### Debian/Ubuntu

```bash
# Add repository
curl -fsSL https://yeager.github.io/debian-repo/KEY.gpg | sudo gpg --dearmor -o /usr/share/keyrings/yeager-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/yeager-archive-keyring.gpg] https://yeager.github.io/debian-repo stable main" | sudo tee /etc/apt/sources.list.d/yeager.list
sudo apt update
sudo apt install pcap-viewer
```

### Fedora/RHEL

```bash
sudo dnf config-manager --add-repo https://yeager.github.io/rpm-repo/yeager.repo
sudo dnf install pcap-viewer
```

### From source

```bash
pip install .
pcap-viewer
```

## 🌍 Contributing Translations

This app is translated via Transifex. Help translate it into your language!

**[→ Translate on Transifex](https://app.transifex.com/danielnylander/pcap-viewer/)**

Currently supported: Swedish (sv). More languages welcome!

### For Translators
1. Create a free account at [Transifex](https://www.transifex.com)
2. Join the [danielnylander](https://app.transifex.com/danielnylander/) organization
3. Start translating!

Translations are automatically synced via GitHub Actions.
## License

GPL-3.0-or-later — Daniel Nylander <daniel@danielnylander.se>
