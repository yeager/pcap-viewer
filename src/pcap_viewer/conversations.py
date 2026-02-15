"""Conversation tracking for TCP streams and UDP flows."""

import gettext
from collections import defaultdict
from datetime import datetime

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GObject, Pango

from scapy.all import TCP, UDP, IP, IPv6, Raw

from .pcap_parser import get_protocol_name, get_src_dst

_ = gettext.gettext


class ConversationObject(GObject.Object):
    """GObject wrapper for conversation data."""

    __gtype_name__ = "ConversationObject"

    def __init__(self, src_addr="", src_port=0, dst_addr="", dst_port=0, 
                 protocol="", packet_count=0, byte_count=0, duration=0.0, packets=None):
        super().__init__()
        self._src_addr = src_addr
        self._src_port = src_port
        self._dst_addr = dst_addr
        self._dst_port = dst_port
        self._protocol = protocol
        self._packet_count = packet_count
        self._byte_count = byte_count
        self._duration = duration
        self._packets = packets or []

    @GObject.Property(type=str)
    def src_addr(self):
        return self._src_addr

    @GObject.Property(type=int)
    def src_port(self):
        return self._src_port

    @GObject.Property(type=str)
    def dst_addr(self):
        return self._dst_addr

    @GObject.Property(type=int)
    def dst_port(self):
        return self._dst_port

    @GObject.Property(type=str)
    def protocol(self):
        return self._protocol

    @GObject.Property(type=int)
    def packet_count(self):
        return self._packet_count

    @GObject.Property(type=int)
    def byte_count(self):
        return self._byte_count

    @GObject.Property(type=float)
    def duration(self):
        return self._duration

    @property
    def packets(self):
        return self._packets

    @property
    def conversation_id(self):
        return f"{self._src_addr}:{self._src_port} ↔ {self._dst_addr}:{self._dst_port}"


class ConversationView(Gtk.Box):
    """Widget for tracking network conversations."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(12)
        self.set_margin_end(12)

        self._conversations = []
        self._build_ui()

    def _build_ui(self):
        # Header with refresh button
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header_box.set_halign(Gtk.Align.START)

        self._refresh_btn = Gtk.Button(label=_("Analyze Conversations"))
        self._refresh_btn.set_sensitive(False)
        self._refresh_btn.connect("clicked", self._on_refresh_clicked)
        header_box.append(self._refresh_btn)

        self._status_label = Gtk.Label(label=_("No conversations analyzed yet"))
        self._status_label.add_css_class("dim-label")
        header_box.append(self._status_label)

        self.append(header_box)

        # Conversations list
        self._conv_store = Gio.ListStore(item_type=ConversationObject)
        selection = Gtk.SingleSelection(model=self._conv_store)
        selection.connect("notify::selected", self._on_conversation_selected)

        self._column_view = Gtk.ColumnView(model=selection)
        self._column_view.add_css_class("data-table")

        columns = [
            (_("Conversation"), "conversation_id", 250),
            (_("Protocol"), "protocol", 80),
            (_("Packets"), "packet_count", 80),
            (_("Bytes"), "byte_count", 100),
            (_("Duration (s)"), "duration", 100),
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
        scroll.set_min_content_height(200)
        scroll.set_child(self._column_view)
        self.append(scroll)

        # Stream detail view
        detail_label = Gtk.Label(label=_("Stream Data"))
        detail_label.set_halign(Gtk.Align.START)
        detail_label.add_css_class("title-4")
        self.append(detail_label)

        self._stream_view = Gtk.TextView()
        self._stream_view.set_editable(False)
        self._stream_view.set_cursor_visible(False)
        self._stream_view.set_monospace(True)
        self._stream_view.add_css_class("stream-view")

        stream_scroll = Gtk.ScrolledWindow()
        stream_scroll.set_vexpand(True)
        stream_scroll.set_min_content_height(200)
        stream_scroll.set_child(self._stream_view)
        self.append(stream_scroll)

        # Follow stream button
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        btn_box.set_halign(Gtk.Align.END)

        self._follow_btn = Gtk.Button(label=_("Follow Stream"))
        self._follow_btn.set_sensitive(False)
        self._follow_btn.connect("clicked", self._on_follow_clicked)
        btn_box.append(self._follow_btn)

        self.append(btn_box)

    def _on_col_setup(self, factory, list_item):
        label = Gtk.Label()
        label.set_halign(Gtk.Align.START)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        list_item.set_child(label)

    def _on_col_bind(self, factory, list_item, prop):
        item = list_item.get_item()
        label = list_item.get_child()
        val = getattr(item, prop)
        
        if prop == "conversation_id":
            label.set_text(val)
        elif prop == "byte_count":
            label.set_text(self._format_bytes(val))
        elif prop == "duration":
            label.set_text(f"{val:.3f}")
        else:
            label.set_text(str(val))

    def _format_bytes(self, bytes_count):
        """Format byte count in human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_count < 1024:
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024
        return f"{bytes_count:.1f} TB"

    def _on_conversation_selected(self, selection, pspec):
        item = selection.get_selected_item()
        if item:
            self._show_conversation_details(item)
            self._follow_btn.set_sensitive(True)
        else:
            self._follow_btn.set_sensitive(False)

    def _on_refresh_clicked(self, btn):
        """Analyze conversations from loaded packets."""
        if hasattr(self, '_pcap_file') and self._pcap_file.packets:
            self._analyze_conversations(self._pcap_file.packets)

    def _on_follow_clicked(self, btn):
        """Show full stream data for selected conversation."""
        selection = self._column_view.get_model()
        item = selection.get_selected_item()
        if item:
            self._show_stream_data(item)

    def _show_conversation_details(self, conv):
        """Show basic details of the selected conversation."""
        buf = self._stream_view.get_buffer()
        
        details = []
        details.append(f"{_('Conversation')}: {conv.conversation_id}")
        details.append(f"{_('Protocol')}: {conv.protocol}")
        details.append(f"{_('Packets')}: {conv.packet_count}")
        details.append(f"{_('Bytes')}: {self._format_bytes(conv.byte_count)}")
        details.append(f"{_('Duration')}: {conv.duration:.3f} s")
        details.append("")
        details.append(_("Click 'Follow Stream' to see full conversation data"))
        
        buf.set_text("\n".join(details))

    def _show_stream_data(self, conv):
        """Show full stream data for the conversation."""
        buf = self._stream_view.get_buffer()
        
        # Sort packets by timestamp
        packets = sorted(conv.packets, key=lambda p: p.time)
        
        stream_data = []
        stream_data.append(f"{_('Stream')}: {conv.conversation_id}")
        stream_data.append(f"{_('Protocol')}: {conv.protocol}")
        stream_data.append("=" * 60)
        stream_data.append("")
        
        for i, pkt in enumerate(packets):
            timestamp = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]
            src, dst = get_src_dst(pkt)
            
            # Get ports
            src_port = dst_port = ""
            if pkt.haslayer(TCP):
                src_port = str(pkt[TCP].sport)
                dst_port = str(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                src_port = str(pkt[UDP].sport)
                dst_port = str(pkt[UDP].dport)
            
            direction = f"{src}:{src_port} → {dst}:{dst_port}"
            stream_data.append(f"[{timestamp}] {direction}")
            
            # Add payload if present
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
                try:
                    # Try to decode as text
                    text_payload = payload.decode('utf-8', errors='ignore')
                    if text_payload.strip():
                        # Show first 200 characters
                        if len(text_payload) > 200:
                            text_payload = text_payload[:200] + "..."
                        stream_data.append(f"  {text_payload}")
                except:
                    # Show hex if not text
                    hex_payload = payload[:50].hex()
                    if len(payload) > 50:
                        hex_payload += "..."
                    stream_data.append(f"  [{hex_payload}]")
            
            stream_data.append("")
        
        buf.set_text("\n".join(stream_data))

    def _analyze_conversations(self, packets):
        """Analyze packets to find conversations."""
        self._conv_store.remove_all()
        self._conversations.clear()

        # Group packets by conversation
        tcp_streams = defaultdict(list)
        udp_flows = defaultdict(list)
        
        for pkt in packets:
            src, dst = get_src_dst(pkt)
            if not src or not dst:
                continue
                
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                # Create bidirectional stream key
                key = tuple(sorted([(src, tcp.sport), (dst, tcp.dport)]))
                tcp_streams[key].append(pkt)
                
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                # Create bidirectional flow key
                key = tuple(sorted([(src, udp.sport), (dst, udp.dport)]))
                udp_flows[key].append(pkt)

        # Process TCP streams
        for key, stream_packets in tcp_streams.items():
            if len(stream_packets) < 2:  # Skip single packet "conversations"
                continue
                
            (src_addr, src_port), (dst_addr, dst_port) = key
            
            # Calculate statistics
            packet_count = len(stream_packets)
            byte_count = sum(len(pkt) for pkt in stream_packets)
            
            # Calculate duration
            times = [pkt.time for pkt in stream_packets]
            duration = max(times) - min(times)
            
            conv = ConversationObject(
                src_addr=src_addr,
                src_port=src_port,
                dst_addr=dst_addr,
                dst_port=dst_port,
                protocol="TCP",
                packet_count=packet_count,
                byte_count=byte_count,
                duration=duration,
                packets=stream_packets
            )
            
            self._conv_store.append(conv)
            self._conversations.append(conv)

        # Process UDP flows
        for key, flow_packets in udp_flows.items():
            if len(flow_packets) < 2:  # Skip single packet "flows"
                continue
                
            (src_addr, src_port), (dst_addr, dst_port) = key
            
            # Calculate statistics
            packet_count = len(flow_packets)
            byte_count = sum(len(pkt) for pkt in flow_packets)
            
            # Calculate duration
            times = [pkt.time for pkt in flow_packets]
            duration = max(times) - min(times)
            
            conv = ConversationObject(
                src_addr=src_addr,
                src_port=src_port,
                dst_addr=dst_addr,
                dst_port=dst_port,
                protocol="UDP",
                packet_count=packet_count,
                byte_count=byte_count,
                duration=duration,
                packets=flow_packets
            )
            
            self._conv_store.append(conv)
            self._conversations.append(conv)

        conv_count = len(self._conversations)
        self._status_label.set_text(_("{count} conversations found").format(count=conv_count))
        
        # Clear stream view
        buf = self._stream_view.get_buffer()
        buf.set_text(_("Select a conversation to view details"))

    def update_packets(self, pcap_file):
        """Update with new packets."""
        self._pcap_file = pcap_file
        self._refresh_btn.set_sensitive(pcap_file.packets is not None)
        if not pcap_file.packets:
            self._conv_store.remove_all()
            self._conversations.clear()
            self._status_label.set_text(_("No conversations analyzed yet"))
            buf = self._stream_view.get_buffer()
            buf.set_text("")