"""Protocol statistics for PCAP analysis."""

import gettext
from collections import defaultdict

from scapy.all import DNS

from .pcap_parser import get_protocol_name, get_src_dst

_ = gettext.gettext


def compute_stats(packets):
    """Compute statistics from a list of scapy packets.

    Returns dict with:
        protocol_dist: {proto: count}
        top_talkers: [(ip, bytes)]
        conversations: [((src, dst), bytes, count)]
        dns_queries: [(query, count)]
    """
    if not packets:
        return {
            "protocol_dist": {},
            "top_talkers": [],
            "conversations": [],
            "dns_queries": [],
        }

    proto_count = defaultdict(int)
    ip_bytes = defaultdict(int)
    conv_data = defaultdict(lambda: [0, 0])  # [bytes, count]
    dns_q = defaultdict(int)

    for pkt in packets:
        proto = get_protocol_name(pkt)
        proto_count[proto] += 1
        pkt_len = len(pkt)

        src, dst = get_src_dst(pkt)
        if src:
            ip_bytes[src] += pkt_len
        if dst:
            ip_bytes[dst] += pkt_len

        if src and dst:
            key = tuple(sorted([src, dst]))
            conv_data[key][0] += pkt_len
            conv_data[key][1] += 1

        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qdcount > 0 and dns.qd:
                qname = dns.qd.qname.decode(errors="replace").rstrip(".")
                dns_q[qname] += 1

    top_talkers = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:20]
    conversations = sorted(
        [(k, v[0], v[1]) for k, v in conv_data.items()],
        key=lambda x: x[1],
        reverse=True,
    )[:50]
    dns_queries = sorted(dns_q.items(), key=lambda x: x[1], reverse=True)[:50]

    return {
        "protocol_dist": dict(proto_count),
        "top_talkers": top_talkers,
        "conversations": conversations,
        "dns_queries": dns_queries,
    }
