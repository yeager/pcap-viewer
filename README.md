# PacketLens

A comprehensive GTK4/Adwaita network analysis suite for pcap/pcapng captures with advanced protocol analysis, file extraction, and security features.

## Features

- **Multi-tab Analysis Interface**: Comprehensive packet analysis across specialized views
- **Packet Browser**: Three-pane Wireshark-style layout with packet list, protocol layers, and hex dump
- **Protocol Statistics**: Detailed breakdown of network protocols and traffic patterns
- **Conversation Analysis**: Track network flows between endpoints with statistics
- **DNS Analysis**: DNS query/response analysis, domain tracking, and DNS-over-HTTPS detection
- **HTTP Analysis**: HTTP request/response extraction, header analysis, and content inspection
- **TLS Analysis**: Certificate inspection, cipher suite analysis, and security assessment
- **File Extraction**: Extract files from HTTP/FTP transfers and email attachments
- **Timeline View**: Chronological visualization of network events
- **Advanced Filtering**: BPF filters with preset combinations
- **Drag-and-Drop**: Easy file loading interface
- **Internationalized**: Multi-language support via gettext

## Installation

### Debian/Ubuntu

```bash
# Add repository
curl -fsSL https://yeager.github.io/debian-repo/KEY.gpg | sudo gpg --dearmor -o /usr/share/keyrings/yeager-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/yeager-archive-keyring.gpg] https://yeager.github.io/debian-repo stable main" | sudo tee /etc/apt/sources.list.d/yeager.list
sudo apt update
sudo apt install packetlens
```

### Fedora/RHEL

```bash
sudo dnf config-manager --add-repo https://yeager.github.io/rpm-repo/yeager.repo
sudo dnf install packetlens
```

### From source

```bash
pip install .
packetlens
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
