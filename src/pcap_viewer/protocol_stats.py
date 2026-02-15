"""Protocol statistics with visualization using Cairo."""

import gettext
import math
from collections import defaultdict

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GObject, Pango, Gdk

from .pcap_parser import get_protocol_name, get_src_dst

_ = gettext.gettext

# Color palette for charts
COLORS = [
    (0.2, 0.6, 1.0),    # Blue
    (1.0, 0.4, 0.4),    # Red
    (0.4, 0.8, 0.4),    # Green
    (1.0, 0.8, 0.2),    # Yellow
    (0.8, 0.4, 1.0),    # Purple
    (1.0, 0.6, 0.2),    # Orange
    (0.4, 0.8, 0.8),    # Cyan
    (1.0, 0.4, 0.8),    # Pink
    (0.6, 0.4, 0.2),    # Brown
    (0.6, 0.6, 0.6),    # Gray
]


class StatObject(GObject.Object):
    """GObject wrapper for statistics data."""

    __gtype_name__ = "StatObject"

    def __init__(self, name="", packet_count=0, byte_count=0, percentage=0.0):
        super().__init__()
        self._name = name
        self._packet_count = packet_count
        self._byte_count = byte_count
        self._percentage = percentage

    @GObject.Property(type=str)
    def name(self):
        return self._name

    @GObject.Property(type=int)
    def packet_count(self):
        return self._packet_count

    @GObject.Property(type=int)
    def byte_count(self):
        return self._byte_count

    @GObject.Property(type=float)
    def percentage(self):
        return self._percentage


class ChartWidget(Gtk.DrawingArea):
    """Custom widget for drawing charts using Cairo."""

    def __init__(self):
        super().__init__()
        self.set_size_request(300, 300)
        self.set_draw_func(self._draw)
        
        self._chart_type = "pie"  # "pie" or "bar"
        self._data = []
        self._title = ""

    def set_chart_data(self, data, title="", chart_type="pie"):
        """Set data for the chart."""
        self._data = data
        self._title = title
        self._chart_type = chart_type
        self.queue_draw()

    def _draw(self, area, cr, width, height, user_data):
        """Draw function called by GTK."""
        if not self._data:
            self._draw_empty(cr, width, height)
            return

        if self._chart_type == "pie":
            self._draw_pie_chart(cr, width, height)
        elif self._chart_type == "bar":
            self._draw_bar_chart(cr, width, height)

    def _draw_empty(self, cr, width, height):
        """Draw empty state."""
        cr.set_source_rgb(0.5, 0.5, 0.5)
        cr.select_font_face("Sans", 0, 0)
        cr.set_font_size(14)
        
        text = _("No data to display")
        text_extents = cr.text_extents(text)
        x = (width - text_extents.width) / 2
        y = (height + text_extents.height) / 2
        
        cr.move_to(x, y)
        cr.show_text(text)

    def _draw_pie_chart(self, cr, width, height):
        """Draw a pie chart."""
        if not self._data:
            return

        # Calculate center and radius
        center_x = width / 2
        center_y = height / 2
        radius = min(width, height) * 0.3

        # Draw title
        if self._title:
            cr.set_source_rgb(0, 0, 0)
            cr.select_font_face("Sans", 0, 1)  # Bold
            cr.set_font_size(16)
            
            text_extents = cr.text_extents(self._title)
            x = (width - text_extents.width) / 2
            cr.move_to(x, 30)
            cr.show_text(self._title)

        # Calculate total for percentages
        total = sum(item[1] for item in self._data)
        if total == 0:
            return

        # Draw pie slices
        start_angle = 0
        legend_y = 50

        for i, (label, value) in enumerate(self._data[:len(COLORS)]):
            # Calculate slice angle
            slice_angle = (value / total) * 2 * math.pi
            
            # Set color
            color = COLORS[i % len(COLORS)]
            cr.set_source_rgb(*color)
            
            # Draw slice
            cr.move_to(center_x, center_y)
            cr.arc(center_x, center_y, radius, start_angle, start_angle + slice_angle)
            cr.line_to(center_x, center_y)
            cr.fill()
            
            # Draw slice outline
            cr.set_source_rgb(1, 1, 1)
            cr.set_line_width(2)
            cr.move_to(center_x, center_y)
            cr.arc(center_x, center_y, radius, start_angle, start_angle + slice_angle)
            cr.line_to(center_x, center_y)
            cr.stroke()
            
            # Draw legend
            legend_x = width - 200
            cr.set_source_rgb(*color)
            cr.rectangle(legend_x, legend_y + i * 20, 15, 15)
            cr.fill()
            
            cr.set_source_rgb(0, 0, 0)
            cr.select_font_face("Sans", 0, 0)
            cr.set_font_size(12)
            percentage = (value / total) * 100
            legend_text = f"{label} ({percentage:.1f}%)"
            cr.move_to(legend_x + 20, legend_y + i * 20 + 12)
            cr.show_text(legend_text)
            
            start_angle += slice_angle

    def _draw_bar_chart(self, cr, width, height):
        """Draw a bar chart."""
        if not self._data:
            return

        # Draw title
        title_height = 40
        if self._title:
            cr.set_source_rgb(0, 0, 0)
            cr.select_font_face("Sans", 0, 1)  # Bold
            cr.set_font_size(16)
            
            text_extents = cr.text_extents(self._title)
            x = (width - text_extents.width) / 2
            cr.move_to(x, 25)
            cr.show_text(self._title)

        # Chart area
        chart_width = width - 100
        chart_height = height - title_height - 60
        chart_x = 80
        chart_y = title_height + 10

        # Find maximum value for scaling
        max_value = max(item[1] for item in self._data) if self._data else 1
        if max_value == 0:
            max_value = 1

        # Draw bars
        bar_width = chart_width / len(self._data) * 0.8
        bar_spacing = chart_width / len(self._data) * 0.2

        for i, (label, value) in enumerate(self._data):
            # Calculate bar dimensions
            bar_height = (value / max_value) * chart_height
            x = chart_x + i * (bar_width + bar_spacing)
            y = chart_y + chart_height - bar_height

            # Set color
            color = COLORS[i % len(COLORS)]
            cr.set_source_rgb(*color)
            
            # Draw bar
            cr.rectangle(x, y, bar_width, bar_height)
            cr.fill()
            
            # Draw bar outline
            cr.set_source_rgb(0, 0, 0)
            cr.set_line_width(1)
            cr.rectangle(x, y, bar_width, bar_height)
            cr.stroke()
            
            # Draw label
            cr.set_source_rgb(0, 0, 0)
            cr.select_font_face("Sans", 0, 0)
            cr.set_font_size(10)
            
            # Rotate label for better fit
            cr.save()
            label_x = x + bar_width / 2
            label_y = chart_y + chart_height + 15
            cr.translate(label_x, label_y)
            cr.rotate(-math.pi / 4)
            cr.move_to(0, 0)
            cr.show_text(label)
            cr.restore()

        # Draw axes
        cr.set_source_rgb(0, 0, 0)
        cr.set_line_width(2)
        # Y-axis
        cr.move_to(chart_x, chart_y)
        cr.line_to(chart_x, chart_y + chart_height)
        # X-axis
        cr.move_to(chart_x, chart_y + chart_height)
        cr.line_to(chart_x + chart_width, chart_y + chart_height)
        cr.stroke()


class ProtocolStatsView(Gtk.Box):
    """Widget for displaying protocol statistics and visualizations."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(12)
        self.set_margin_end(12)

        self._stats_data = {}
        self._build_ui()

    def _build_ui(self):
        # Header with analyze button
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header_box.set_halign(Gtk.Align.START)

        self._analyze_btn = Gtk.Button(label=_("Analyze Protocols"))
        self._analyze_btn.set_sensitive(False)
        self._analyze_btn.connect("clicked", self._on_analyze_clicked)
        header_box.append(self._analyze_btn)

        # Chart type selection
        chart_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        chart_label = Gtk.Label(label=_("Chart type:"))
        chart_box.append(chart_label)

        self._chart_combo = Gtk.ComboBoxText()
        self._chart_combo.append_text(_("Pie Chart"))
        self._chart_combo.append_text(_("Bar Chart"))
        self._chart_combo.set_active(0)
        self._chart_combo.connect("changed", self._on_chart_type_changed)
        chart_box.append(self._chart_combo)

        header_box.append(chart_box)

        self._status_label = Gtk.Label(label=_("No analysis performed yet"))
        self._status_label.add_css_class("dim-label")
        header_box.append(self._status_label)

        self.append(header_box)

        # Main content - side by side layout
        main_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        main_box.set_vexpand(True)

        # Left side: Charts
        chart_frame = Gtk.Frame()
        chart_frame.set_label(_("Protocol Distribution"))
        chart_frame.set_hexpand(True)

        self._chart_widget = ChartWidget()
        chart_frame.set_child(self._chart_widget)
        main_box.append(chart_frame)

        # Right side: Statistics tables
        stats_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        stats_box.set_hexpand(True)

        # Protocol statistics table
        proto_frame = Gtk.Frame()
        proto_frame.set_label(_("Protocol Statistics"))

        self._proto_store = Gio.ListStore(item_type=StatObject)
        proto_selection = Gtk.SingleSelection(model=self._proto_store)

        self._proto_view = Gtk.ColumnView(model=proto_selection)
        self._proto_view.add_css_class("data-table")

        columns = [
            (_("Protocol"), "name", 100),
            (_("Packets"), "packet_count", 80),
            (_("Bytes"), "byte_count", 100),
            (_("%"), "percentage", 60),
        ]

        for title, prop, width in columns:
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._on_col_setup)
            factory.connect("bind", self._on_col_bind, prop)
            col = Gtk.ColumnViewColumn(title=title, factory=factory)
            col.set_fixed_width(width)
            col.set_resizable(True)
            self._proto_view.append_column(col)

        proto_scroll = Gtk.ScrolledWindow()
        proto_scroll.set_min_content_height(200)
        proto_scroll.set_child(self._proto_view)
        proto_frame.set_child(proto_scroll)
        stats_box.append(proto_frame)

        # Top talkers table
        talkers_frame = Gtk.Frame()
        talkers_frame.set_label(_("Top Talkers"))

        self._talkers_store = Gio.ListStore(item_type=StatObject)
        talkers_selection = Gtk.SingleSelection(model=self._talkers_store)

        self._talkers_view = Gtk.ColumnView(model=talkers_selection)
        self._talkers_view.add_css_class("data-table")

        talker_columns = [
            (_("IP Address"), "name", 140),
            (_("Bytes"), "byte_count", 100),
            (_("%"), "percentage", 60),
        ]

        for title, prop, width in talker_columns:
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._on_col_setup)
            factory.connect("bind", self._on_col_bind, prop)
            col = Gtk.ColumnViewColumn(title=title, factory=factory)
            col.set_fixed_width(width)
            col.set_resizable(True)
            self._talkers_view.append_column(col)

        talkers_scroll = Gtk.ScrolledWindow()
        talkers_scroll.set_min_content_height(200)
        talkers_scroll.set_child(self._talkers_view)
        talkers_frame.set_child(talkers_scroll)
        stats_box.append(talkers_frame)

        main_box.append(stats_box)
        self.append(main_box)

    def _on_col_setup(self, factory, list_item):
        label = Gtk.Label()
        label.set_halign(Gtk.Align.START)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        list_item.set_child(label)

    def _on_col_bind(self, factory, list_item, prop):
        item = list_item.get_item()
        label = list_item.get_child()
        val = getattr(item, prop)
        
        if prop == "byte_count":
            label.set_text(self._format_bytes(val))
        elif prop == "percentage":
            label.set_text(f"{val:.1f}%")
        else:
            label.set_text(str(val))

    def _format_bytes(self, byte_count):
        """Format byte count in human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if byte_count < 1024:
                return f"{byte_count:.1f} {unit}"
            byte_count /= 1024
        return f"{byte_count:.1f} TB"

    def _on_analyze_clicked(self, btn):
        """Analyze protocol statistics from loaded packets."""
        if hasattr(self, '_pcap_file') and self._pcap_file.packets:
            self._analyze_protocols(self._pcap_file.packets)

    def _on_chart_type_changed(self, combo):
        """Handle chart type change."""
        if not self._stats_data:
            return

        chart_type = "pie" if combo.get_active() == 0 else "bar"
        
        # Update chart with protocol data
        proto_data = [(proto, stats["packet_count"]) 
                     for proto, stats in self._stats_data["protocols"].items()]
        proto_data.sort(key=lambda x: x[1], reverse=True)
        
        self._chart_widget.set_chart_data(
            proto_data[:10],  # Top 10
            _("Protocol Distribution"),
            chart_type
        )

    def _analyze_protocols(self, packets):
        """Analyze protocol statistics from packets."""
        if not packets:
            return

        # Initialize counters
        protocol_stats = defaultdict(lambda: {"packet_count": 0, "byte_count": 0})
        ip_stats = defaultdict(int)
        total_packets = len(packets)
        total_bytes = 0

        # Analyze each packet
        for pkt in packets:
            protocol = get_protocol_name(pkt)
            pkt_len = len(pkt)
            
            protocol_stats[protocol]["packet_count"] += 1
            protocol_stats[protocol]["byte_count"] += pkt_len
            total_bytes += pkt_len
            
            # Track IP addresses
            src, dst = get_src_dst(pkt)
            if src:
                ip_stats[src] += pkt_len
            if dst:
                ip_stats[dst] += pkt_len

        # Store results
        self._stats_data = {
            "protocols": dict(protocol_stats),
            "top_talkers": dict(ip_stats),
            "total_packets": total_packets,
            "total_bytes": total_bytes
        }

        # Update protocol statistics table
        self._proto_store.remove_all()
        for protocol, stats in sorted(protocol_stats.items(), 
                                    key=lambda x: x[1]["packet_count"], reverse=True):
            percentage = (stats["packet_count"] / total_packets) * 100
            stat_obj = StatObject(
                name=protocol,
                packet_count=stats["packet_count"],
                byte_count=stats["byte_count"],
                percentage=percentage
            )
            self._proto_store.append(stat_obj)

        # Update top talkers table
        self._talkers_store.remove_all()
        for ip, bytes_count in sorted(ip_stats.items(), 
                                    key=lambda x: x[1], reverse=True)[:20]:
            percentage = (bytes_count / total_bytes) * 100 if total_bytes > 0 else 0
            talker_obj = StatObject(
                name=ip,
                packet_count=0,  # Not used for talkers
                byte_count=bytes_count,
                percentage=percentage
            )
            self._talkers_store.append(talker_obj)

        # Update chart
        proto_data = [(proto, stats["packet_count"]) 
                     for proto, stats in protocol_stats.items()]
        proto_data.sort(key=lambda x: x[1], reverse=True)
        
        chart_type = "pie" if self._chart_combo.get_active() == 0 else "bar"
        self._chart_widget.set_chart_data(
            proto_data[:10],  # Top 10 protocols
            _("Protocol Distribution"),
            chart_type
        )

        # Update status
        protocol_count = len(protocol_stats)
        self._status_label.set_text(
            _("Analyzed {packets} packets, {protocols} protocols").format(
                packets=total_packets, protocols=protocol_count
            )
        )

    def update_packets(self, pcap_file):
        """Update with new packets."""
        self._pcap_file = pcap_file
        self._analyze_btn.set_sensitive(pcap_file.packets is not None)
        if not pcap_file.packets:
            self._proto_store.remove_all()
            self._talkers_store.remove_all()
            self._stats_data = {}
            self._status_label.set_text(_("No analysis performed yet"))
            self._chart_widget.set_chart_data([], "")