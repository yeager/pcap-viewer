"""TLS/SSL traffic analysis and certificate inspection."""

import gettext
import struct
from datetime import datetime, timezone
from collections import defaultdict

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GObject, Pango

from scapy.all import TCP, Raw

_ = gettext.gettext

# TLS constants
TLS_CONTENT_TYPES = {
    20: "Change Cipher Spec",
    21: "Alert", 
    22: "Handshake",
    23: "Application Data"
}

TLS_HANDSHAKE_TYPES = {
    1: "Client Hello",
    2: "Server Hello", 
    11: "Certificate",
    12: "Server Key Exchange",
    13: "Certificate Request",
    14: "Server Hello Done",
    15: "Certificate Verify",
    16: "Client Key Exchange",
    20: "Finished"
}

TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1", 
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0300: "SSL 3.0"
}

# Common cipher suites
CIPHER_SUITES = {
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256"
}


class TLSConnectionObject(GObject.Object):
    """GObject wrapper for TLS connection data."""

    __gtype_name__ = "TLSConnectionObject"

    def __init__(self, src_addr="", dst_addr="", src_port=0, dst_port=0,
                 sni="", tls_version="", cipher_suite="", cert_subject="",
                 cert_issuer="", cert_expiry="", has_issues=False, issues=""):
        super().__init__()
        self._src_addr = src_addr
        self._dst_addr = dst_addr
        self._src_port = src_port
        self._dst_port = dst_port
        self._sni = sni
        self._tls_version = tls_version
        self._cipher_suite = cipher_suite
        self._cert_subject = cert_subject
        self._cert_issuer = cert_issuer
        self._cert_expiry = cert_expiry
        self._has_issues = has_issues
        self._issues = issues

    @GObject.Property(type=str)
    def src_addr(self):
        return self._src_addr

    @GObject.Property(type=str)
    def dst_addr(self):
        return self._dst_addr

    @GObject.Property(type=int)
    def src_port(self):
        return self._src_port

    @GObject.Property(type=int)
    def dst_port(self):
        return self._dst_port

    @GObject.Property(type=str)
    def sni(self):
        return self._sni

    @GObject.Property(type=str)
    def tls_version(self):
        return self._tls_version

    @GObject.Property(type=str)
    def cipher_suite(self):
        return self._cipher_suite

    @GObject.Property(type=str)
    def cert_subject(self):
        return self._cert_subject

    @GObject.Property(type=str)
    def cert_issuer(self):
        return self._cert_issuer

    @GObject.Property(type=str)
    def cert_expiry(self):
        return self._cert_expiry

    @GObject.Property(type=bool)
    def has_issues(self):
        return self._has_issues

    @GObject.Property(type=str)
    def issues(self):
        return self._issues

    @property
    def connection_id(self):
        return f"{self._src_addr}:{self._src_port} → {self._dst_addr}:{self._dst_port}"


class TLSAnalyzerView(Gtk.Box):
    """Widget for analyzing TLS/SSL connections."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(12)
        self.set_margin_end(12)

        self._tls_connections = []
        self._build_ui()

    def _build_ui(self):
        # Header with analyze button and filters
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header_box.set_halign(Gtk.Align.START)

        self._analyze_btn = Gtk.Button(label=_("Analyze TLS"))
        self._analyze_btn.set_sensitive(False)
        self._analyze_btn.connect("clicked", self._on_analyze_clicked)
        header_box.append(self._analyze_btn)

        # Filter controls
        filter_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        
        filter_label = Gtk.Label(label=_("Filter:"))
        filter_box.append(filter_label)

        self._filter_entry = Gtk.SearchEntry()
        self._filter_entry.set_placeholder_text(_("Search SNI, subject..."))
        self._filter_entry.set_size_request(200, -1)
        self._filter_entry.connect("search-changed", self._on_filter_changed)
        filter_box.append(self._filter_entry)

        # Issues only checkbox
        self._issues_only = Gtk.CheckButton(label=_("Issues only"))
        self._issues_only.connect("toggled", self._on_issues_filter_changed)
        filter_box.append(self._issues_only)

        header_box.append(filter_box)

        self._status_label = Gtk.Label(label=_("No TLS analysis performed yet"))
        self._status_label.add_css_class("dim-label")
        header_box.append(self._status_label)

        self.append(header_box)

        # TLS connections table
        self._tls_store = Gio.ListStore(item_type=TLSConnectionObject)
        self._filter_model = Gtk.FilterListModel(model=self._tls_store)
        
        # Create custom filter
        self._custom_filter = Gtk.CustomFilter(match_func=self._filter_func)
        self._filter_model.set_filter(self._custom_filter)
        
        selection = Gtk.SingleSelection(model=self._filter_model)
        selection.connect("notify::selected", self._on_connection_selected)

        self._column_view = Gtk.ColumnView(model=selection)
        self._column_view.add_css_class("data-table")

        columns = [
            (_("Connection"), "connection_id", 200),
            (_("SNI"), "sni", 150),
            (_("TLS Version"), "tls_version", 80),
            (_("Cipher Suite"), "cipher_suite", 200),
            (_("Issues"), "issues", 150),
        ]

        for title, prop, width in columns:
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._on_col_setup)
            factory.connect("bind", self._on_col_bind, prop)
            col = Gtk.ColumnViewColumn(title=title, factory=factory)
            col.set_fixed_width(width)
            col.set_resizable(True)
            self._column_view.append_column(col)

        scroll = Gtk.ScrolledWindow()
        scroll.set_min_content_height(250)
        scroll.set_child(self._column_view)
        self.append(scroll)

        # Connection details
        details_frame = Gtk.Frame()
        details_frame.set_label(_("Connection Details"))
        
        self._details_view = Gtk.TextView()
        self._details_view.set_editable(False)
        self._details_view.set_cursor_visible(False)
        self._details_view.set_monospace(True)
        self._details_view.add_css_class("tls-details")
        
        details_scroll = Gtk.ScrolledWindow()
        details_scroll.set_min_content_height(200)
        details_scroll.set_vexpand(True)
        details_scroll.set_child(self._details_view)
        details_frame.set_child(details_scroll)
        self.append(details_frame)

        # Statistics
        stats_frame = Gtk.Frame()
        stats_frame.set_label(_("TLS Statistics"))
        
        self._stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        self._stats_box.set_margin_top(12)
        self._stats_box.set_margin_bottom(12)
        self._stats_box.set_margin_start(12)
        self._stats_box.set_margin_end(12)
        
        stats_frame.set_child(self._stats_box)
        self.append(stats_frame)

    def _on_col_setup(self, factory, list_item):
        label = Gtk.Label()
        label.set_halign(Gtk.Align.START)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        list_item.set_child(label)

    def _on_col_bind(self, factory, list_item, prop):
        item = list_item.get_item()
        label = list_item.get_child()
        val = getattr(item, prop)
        
        label.set_text(str(val))
        
        # Color code issues
        if prop == "issues" and val:
            label.add_css_class("error")
        elif prop == "issues" and not val:
            label.set_text(_("None"))
            label.add_css_class("success")

    def _filter_func(self, item):
        """Custom filter function for TLS connections."""
        # Text filter
        filter_text = self._filter_entry.get_text().lower()
        if filter_text:
            searchable_text = f"{item.sni} {item.cert_subject} {item.connection_id}".lower()
            if filter_text not in searchable_text:
                return False
        
        # Issues only filter
        if self._issues_only.get_active() and not item.has_issues:
            return False
                
        return True

    def _on_filter_changed(self, entry):
        """Handle search filter change."""
        self._custom_filter.changed(Gtk.FilterChange.DIFFERENT)

    def _on_issues_filter_changed(self, button):
        """Handle issues only filter change."""
        self._custom_filter.changed(Gtk.FilterChange.DIFFERENT)

    def _on_connection_selected(self, selection, pspec):
        """Handle TLS connection selection."""
        item = selection.get_selected_item()
        if item:
            self._show_connection_details(item)

    def _on_analyze_clicked(self, btn):
        """Analyze TLS connections from loaded packets."""
        if hasattr(self, '_pcap_file') and self._pcap_file.packets:
            self._analyze_tls(self._pcap_file.packets)

    def _show_connection_details(self, conn):
        """Show detailed information for the selected connection."""
        buf = self._details_view.get_buffer()
        
        details = []
        details.append(f"{_('Connection')}: {conn.connection_id}")
        details.append(f"{_('SNI (Server Name)')}: {conn.sni or _('Not available')}")
        details.append(f"{_('TLS Version')}: {conn.tls_version or _('Unknown')}")
        details.append(f"{_('Cipher Suite')}: {conn.cipher_suite or _('Unknown')}")
        details.append("")
        
        if conn.cert_subject:
            details.append(f"{_('Certificate Subject')}: {conn.cert_subject}")
        if conn.cert_issuer:
            details.append(f"{_('Certificate Issuer')}: {conn.cert_issuer}")
        if conn.cert_expiry:
            details.append(f"{_('Certificate Expiry')}: {conn.cert_expiry}")
        
        if conn.has_issues:
            details.append("")
            details.append(f"{_('Issues')}: {conn.issues}")
        
        buf.set_text("\n".join(details))

    def _analyze_tls(self, packets):
        """Analyze TLS traffic from packets."""
        self._tls_store.remove_all()
        self._tls_connections.clear()

        # Group TCP streams that might contain TLS
        tls_streams = defaultdict(list)
        
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                # Look for TLS traffic on common ports or with TLS content
                if tcp.dport in [443, 993, 995, 636, 989, 990] or tcp.sport in [443, 993, 995, 636, 989, 990]:
                    stream_key = (pkt['IP'].src, tcp.sport, pkt['IP'].dst, tcp.dport)
                    tls_streams[stream_key].append(pkt)

        # Analyze each potential TLS stream
        connections_found = 0
        version_counts = defaultdict(int)
        cipher_counts = defaultdict(int)
        issues_count = 0

        for stream_key, stream_packets in tls_streams.items():
            src_addr, src_port, dst_addr, dst_port = stream_key
            
            # Sort packets by sequence number
            stream_packets.sort(key=lambda p: p[TCP].seq)
            
            # Try to find TLS handshake
            tls_info = self._extract_tls_info(stream_packets)
            
            if tls_info:
                # Check for security issues
                issues = []
                
                # Check for weak TLS versions
                if tls_info.get('version') in ['SSL 3.0', 'TLS 1.0']:
                    issues.append(_("Weak TLS version"))
                
                # Check for weak ciphers
                cipher = tls_info.get('cipher_suite', '')
                if any(weak in cipher.upper() for weak in ['RC4', 'MD5', 'NULL', '3DES']):
                    issues.append(_("Weak cipher"))
                
                # Check certificate expiry (simplified)
                if tls_info.get('cert_expired'):
                    issues.append(_("Expired certificate"))
                
                has_issues = len(issues) > 0
                if has_issues:
                    issues_count += 1
                
                conn = TLSConnectionObject(
                    src_addr=src_addr,
                    dst_addr=dst_addr,
                    src_port=src_port,
                    dst_port=dst_port,
                    sni=tls_info.get('sni', ''),
                    tls_version=tls_info.get('version', ''),
                    cipher_suite=tls_info.get('cipher_suite', ''),
                    cert_subject=tls_info.get('cert_subject', ''),
                    cert_issuer=tls_info.get('cert_issuer', ''),
                    cert_expiry=tls_info.get('cert_expiry', ''),
                    has_issues=has_issues,
                    issues="; ".join(issues)
                )
                
                self._tls_store.append(conn)
                self._tls_connections.append(conn)
                connections_found += 1
                
                if tls_info.get('version'):
                    version_counts[tls_info['version']] += 1
                if tls_info.get('cipher_suite'):
                    cipher_counts[tls_info['cipher_suite']] += 1

        # Update statistics
        self._update_statistics(connections_found, version_counts, cipher_counts, issues_count)
        
        # Update status
        self._status_label.set_text(
            _("{connections} TLS connections found").format(connections=connections_found)
        )

    def _extract_tls_info(self, packets):
        """Extract TLS handshake information from packet stream."""
        tls_info = {}
        
        for pkt in packets:
            if not pkt.haslayer(Raw):
                continue
                
            payload = pkt[Raw].load
            
            try:
                # Look for TLS record header (5 bytes)
                if len(payload) < 5:
                    continue
                
                content_type = payload[0]
                version = struct.unpack('>H', payload[1:3])[0]
                length = struct.unpack('>H', payload[3:5])[0]
                
                if content_type not in TLS_CONTENT_TYPES:
                    continue
                
                # Store TLS version
                if version in TLS_VERSIONS:
                    tls_info['version'] = TLS_VERSIONS[version]
                
                # Parse handshake messages
                if content_type == 22 and len(payload) > 5:  # Handshake
                    handshake_data = payload[5:]
                    offset = 0
                    
                    while offset < len(handshake_data) - 4:
                        hs_type = handshake_data[offset]
                        hs_length = struct.unpack('>I', b'\x00' + handshake_data[offset+1:offset+4])[0]
                        
                        if hs_type == 1:  # Client Hello
                            self._parse_client_hello(handshake_data[offset+4:offset+4+hs_length], tls_info)
                        elif hs_type == 2:  # Server Hello
                            self._parse_server_hello(handshake_data[offset+4:offset+4+hs_length], tls_info)
                        elif hs_type == 11:  # Certificate
                            self._parse_certificate(handshake_data[offset+4:offset+4+hs_length], tls_info)
                        
                        offset += 4 + hs_length
                        if offset >= len(handshake_data):
                            break
                            
            except (struct.error, IndexError, ValueError):
                continue
        
        return tls_info if tls_info else None

    def _parse_client_hello(self, data, tls_info):
        """Parse Client Hello message to extract SNI."""
        try:
            if len(data) < 38:
                return
                
            # Skip version (2) + random (32) + session ID length (1)
            offset = 35
            session_id_len = data[34]
            offset += session_id_len
            
            if offset + 2 > len(data):
                return
                
            # Skip cipher suites
            cipher_suites_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2 + cipher_suites_len
            
            if offset + 1 > len(data):
                return
                
            # Skip compression methods
            compression_len = data[offset]
            offset += 1 + compression_len
            
            if offset + 2 > len(data):
                return
                
            # Parse extensions
            extensions_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            while offset < len(data) - 4:
                ext_type = struct.unpack('>H', data[offset:offset+2])[0]
                ext_len = struct.unpack('>H', data[offset+2:offset+4])[0]
                
                if ext_type == 0:  # Server Name Indication
                    sni_data = data[offset+4:offset+4+ext_len]
                    if len(sni_data) > 5:
                        # Skip server name list length (2) + name type (1) + name length (2)
                        name_len = struct.unpack('>H', sni_data[3:5])[0]
                        if len(sni_data) >= 5 + name_len:
                            sni = sni_data[5:5+name_len].decode('utf-8', errors='ignore')
                            tls_info['sni'] = sni
                    break
                
                offset += 4 + ext_len
                
        except (struct.error, IndexError, ValueError, UnicodeDecodeError):
            pass

    def _parse_server_hello(self, data, tls_info):
        """Parse Server Hello message to extract cipher suite."""
        try:
            if len(data) < 38:
                return
                
            # Skip version (2) + random (32) + session ID length (1)
            offset = 35
            session_id_len = data[34]
            offset += session_id_len
            
            if offset + 2 > len(data):
                return
                
            # Get cipher suite
            cipher_suite = struct.unpack('>H', data[offset:offset+2])[0]
            if cipher_suite in CIPHER_SUITES:
                tls_info['cipher_suite'] = CIPHER_SUITES[cipher_suite]
            else:
                tls_info['cipher_suite'] = f"Unknown (0x{cipher_suite:04X})"
                
        except (struct.error, IndexError, ValueError):
            pass

    def _parse_certificate(self, data, tls_info):
        """Parse Certificate message (simplified)."""
        try:
            # This is a very simplified certificate parsing
            # In reality, you'd want to use a proper ASN.1 parser
            if len(data) > 100:
                tls_info['cert_subject'] = _("Certificate present (parsing not implemented)")
                tls_info['cert_issuer'] = _("See certificate details")
                tls_info['cert_expiry'] = _("Unknown")
                
        except Exception:
            pass

    def _update_statistics(self, total_connections, version_counts, cipher_counts, issues_count):
        """Update the statistics display."""
        # Clear existing stats
        while self._stats_box.get_first_child():
            self._stats_box.remove(self._stats_box.get_first_child())

        # Basic stats
        basic_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        basic_box.append(Gtk.Label(label=_("Basic Statistics"), css_classes=["heading"]))
        basic_box.append(Gtk.Label(label=f"{_('Connections')}: {total_connections}", halign=Gtk.Align.START))
        basic_box.append(Gtk.Label(label=f"{_('With Issues')}: {issues_count}", halign=Gtk.Align.START))
        self._stats_box.append(basic_box)

        # TLS versions
        if version_counts:
            versions_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            versions_box.append(Gtk.Label(label=_("TLS Versions"), css_classes=["heading"]))
            
            for version, count in sorted(version_counts.items(), key=lambda x: x[1], reverse=True):
                versions_box.append(Gtk.Label(label=f"{version}: {count}", halign=Gtk.Align.START))
            
            self._stats_box.append(versions_box)

        # Top cipher suites
        if cipher_counts:
            ciphers_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            ciphers_box.append(Gtk.Label(label=_("Top Cipher Suites"), css_classes=["heading"]))
            
            for cipher, count in sorted(cipher_counts.items(), key=lambda x: x[1], reverse=True)[:3]:
                cipher_text = cipher if len(cipher) <= 25 else cipher[:22] + "..."
                ciphers_box.append(Gtk.Label(label=f"{cipher_text}: {count}", halign=Gtk.Align.START))
            
            self._stats_box.append(ciphers_box)

    def update_packets(self, pcap_file):
        """Update with new packets."""
        self._pcap_file = pcap_file
        self._analyze_btn.set_sensitive(pcap_file.packets is not None)
        if not pcap_file.packets:
            self._tls_store.remove_all()
            self._tls_connections.clear()
            self._status_label.set_text(_("No TLS analysis performed yet"))
            # Clear details and statistics
            buf = self._details_view.get_buffer()
            buf.set_text("")
            while self._stats_box.get_first_child():
                self._stats_box.remove(self._stats_box.get_first_child())