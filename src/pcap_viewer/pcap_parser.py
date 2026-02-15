"""Scapy-based PCAP/PCAPNG parser with lazy loading support."""

import gettext
from datetime import datetime

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, ARP, Ether

_ = gettext.gettext

PAGE_SIZE = 1000


def get_protocol_name(pkt):
    """Determine the highest-layer protocol name for a packet."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if 80 in (sport, dport):
            return "HTTP"
        if 443 in (sport, dport):
            return "TLS"
        return "TCP"
    if pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if 53 in (sport, dport):
            return "DNS"
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IP):
        return "IP"
    if pkt.haslayer(IPv6):
        return "IPv6"
    return pkt.lastlayer().__class__.__name__


def get_src_dst(pkt):
    """Extract source and destination addresses."""
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    if pkt.haslayer(ARP):
        return pkt[ARP].psrc, pkt[ARP].pdst
    if pkt.haslayer(Ether):
        return pkt[Ether].src, pkt[Ether].dst
    return "", ""


def get_info(pkt):
    """Generate a short info summary for a packet."""
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qr == 0 and dns.qdcount > 0:
            return f"Query: {dns.qd.qname.decode(errors='replace')}"
        if dns.qr == 1:
            return f"Response: {dns.ancount} answers"
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = str(tcp.flags)
        return f"{tcp.sport} → {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack}"
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        return f"{udp.sport} → {udp.dport} Len={udp.len}"
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        return f"Type={icmp.type} Code={icmp.code}"
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        if arp.op == 1:
            return f"Who has {arp.pdst}? Tell {arp.psrc}"
        return f"{arp.psrc} is at {arp.hwsrc}"
    return pkt.summary()


def get_layers(pkt):
    """Return list of (layer_name, [(field, value), ...]) for packet detail tree."""
    layers = []
    layer = pkt
    while layer:
        fields = []
        for f in layer.fields_desc:
            val = layer.getfieldval(f.name)
            if val is not None:
                fields.append((f.name, repr(val)))
        layers.append((layer.__class__.__name__, fields))
        layer = layer.payload if layer.payload and not isinstance(layer.payload, bytes) and layer.payload.__class__.__name__ != "Raw" else None
        if layer and layer.__class__.__name__ == "Padding":
            break
    # Add Raw payload if present
    raw = pkt.getlayer("Raw")
    if raw:
        layers.append(("Data", [("payload", f"{len(raw.load)} bytes")]))
    return layers


class PcapFile:
    """Represents a loaded PCAP file with lazy access."""

    def __init__(self):
        self.packets = None
        self.filepath = None
        self._filtered = None
        self._filter_str = ""

    def load(self, filepath):
        """Load a pcap/pcapng file."""
        self.filepath = filepath
        self.packets = rdpcap(str(filepath))
        self._filtered = None
        self._filter_str = ""

    @property
    def total_count(self):
        if self.packets is None:
            return 0
        return len(self._get_packets())

    def _get_packets(self):
        if self._filtered is not None:
            return self._filtered
        return self.packets

    def apply_filter(self, filter_str):
        """Apply a display filter (protocol-based simple filter)."""
        self._filter_str = filter_str
        if not filter_str or self.packets is None:
            self._filtered = None
            return

        f = filter_str.strip().lower()
        filtered = []
        for pkt in self.packets:
            proto = get_protocol_name(pkt).lower()
            if f == proto:
                filtered.append(pkt)
                continue
            src, dst = get_src_dst(pkt)
            if f in src.lower() or f in dst.lower():
                filtered.append(pkt)
                continue
            if f in pkt.summary().lower():
                filtered.append(pkt)
        self._filtered = filtered

    def get_page(self, page=0):
        """Return a page of parsed packet info dicts."""
        pkts = self._get_packets()
        start = page * PAGE_SIZE
        end = min(start + PAGE_SIZE, len(pkts))
        results = []
        for i in range(start, end):
            pkt = pkts[i]
            src, dst = get_src_dst(pkt)
            results.append({
                "nr": i + 1,
                "time": float(pkt.time),
                "src": src,
                "dst": dst,
                "protocol": get_protocol_name(pkt),
                "length": len(pkt),
                "info": get_info(pkt),
                "raw_packet": pkt,
            })
        return results

    def get_packet(self, index):
        """Get a single packet by index."""
        pkts = self._get_packets()
        if 0 <= index < len(pkts):
            return pkts[index]
        return None

    def get_hex_dump(self, index):
        """Get hex dump string for a packet."""
        pkt = self.get_packet(index)
        if pkt is None:
            return ""
        raw = bytes(pkt)
        return format_hex(raw)


def format_hex(data):
    """Format bytes as hex + ASCII dump."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)
