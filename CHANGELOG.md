# Changelog

## [0.2.1] — 2026-02-15

### Changed
- Renamed from PCAP Viewer to PacketLens
- New application ID: se.danielnylander.packetlens
- New binary name: packetlens (pcap-viewer still works as alias)
- Professional SVG icon

### Added
- File extraction from network captures
- Conversation tracking and analysis
- Protocol statistics with cairo charts
- DNS query/response log
- TLS handshake inspection
- HTTP request/response decoder
- Timeline and bandwidth graphs
- BPF display filter
- Image preview for extracted files
- Translation heatmap visualization
- Drag & drop file loading

### Fixed
- GTK4 CustomFilter compatibility
- GObject.Property bool default for Ubuntu 26.04

## [0.1.0] — 2025-02-15

### Added

- Initial release
- GTK4/Adwaita three-pane packet viewer
- PCAP and PCAPNG file support via Scapy
- Protocol detection (TCP, UDP, DNS, HTTP, TLS, ICMP, ARP)
- Display filter by protocol, IP, or keyword
- Protocol statistics, top talkers, conversations, DNS queries
- Hex dump with byte highlighting
- Drag-and-drop file loading
- Internationalization support (gettext)
