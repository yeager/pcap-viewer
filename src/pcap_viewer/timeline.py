"""Timeline and bandwidth visualization using Cairo."""

import gettext
import math
from datetime import datetime, timedelta
from collections import defaultdict

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GObject, Gdk

from .pcap_parser import get_protocol_name

_ = gettext.gettext

# Colors for different protocols
PROTOCOL_COLORS = {
    'TCP': (0.2, 0.6, 1.0),
    'UDP': (1.0, 0.4, 0.4),
    'HTTP': (0.4, 0.8, 0.4),
    'DNS': (1.0, 0.8, 0.2),
    'TLS': (0.8, 0.4, 1.0),
    'ICMP': (1.0, 0.6, 0.2),
    'ARP': (0.4, 0.8, 0.8),
    'OTHER': (0.6, 0.6, 0.6)
}


class TimelineWidget(Gtk.DrawingArea):
    """Custom widget for drawing timeline and bandwidth graphs."""

    def __init__(self):
        super().__init__()
        self.set_size_request(600, 300)
        self.set_draw_func(self._draw)
        
        self._packets = []
        self._time_buckets = []
        self._max_bandwidth = 0
        self._start_time = 0
        self._end_time = 0
        self._bucket_duration = 1.0  # seconds per bucket
        self._view_mode = "bandwidth"  # "bandwidth" or "packets"
        
        # Mouse interaction
        self._hover_x = -1
        self._hover_info = ""
        
        # Add mouse motion controller
        motion_controller = Gtk.EventControllerMotion()
        motion_controller.connect("motion", self._on_motion)
        motion_controller.connect("leave", self._on_leave)
        self.add_controller(motion_controller)

    def set_packets(self, packets):
        """Set packet data for timeline analysis."""
        self._packets = packets
        self._analyze_timeline()
        self.queue_draw()

    def set_view_mode(self, mode):
        """Set view mode: 'bandwidth' or 'packets'."""
        self._view_mode = mode
        self.queue_draw()

    def set_bucket_duration(self, duration):
        """Set time bucket duration in seconds."""
        self._bucket_duration = duration
        self._analyze_timeline()
        self.queue_draw()

    def _analyze_timeline(self):
        """Analyze packets to create time buckets."""
        self._time_buckets = []
        
        if not self._packets:
            return
            
        # Find time range
        times = [pkt.time for pkt in self._packets]
        self._start_time = min(times)
        self._end_time = max(times)
        
        if self._start_time == self._end_time:
            return
            
        # Create time buckets
        total_duration = self._end_time - self._start_time
        num_buckets = max(1, int(total_duration / self._bucket_duration))
        
        # Initialize buckets
        buckets = []
        for i in range(num_buckets):
            bucket_time = self._start_time + i * self._bucket_duration
            buckets.append({
                'time': bucket_time,
                'packet_count': 0,
                'byte_count': 0,
                'protocols': defaultdict(int)
            })
        
        # Fill buckets with packet data
        for pkt in self._packets:
            bucket_index = min(int((pkt.time - self._start_time) / self._bucket_duration), num_buckets - 1)
            bucket = buckets[bucket_index]
            
            bucket['packet_count'] += 1
            bucket['byte_count'] += len(pkt)
            
            protocol = get_protocol_name(pkt)
            bucket['protocols'][protocol] += 1
        
        self._time_buckets = buckets
        
        # Calculate max bandwidth (bytes per second)
        self._max_bandwidth = max(bucket['byte_count'] / self._bucket_duration 
                                for bucket in buckets) if buckets else 0

    def _draw(self, area, cr, width, height, user_data):
        """Draw the timeline chart."""
        if not self._time_buckets:
            self._draw_empty(cr, width, height)
            return
            
        # Draw background
        cr.set_source_rgb(1, 1, 1)
        cr.rectangle(0, 0, width, height)
        cr.fill()
        
        # Chart margins
        margin_left = 80
        margin_right = 20
        margin_top = 40
        margin_bottom = 60
        
        chart_width = width - margin_left - margin_right
        chart_height = height - margin_top - margin_bottom
        chart_x = margin_left
        chart_y = margin_top
        
        if chart_width <= 0 or chart_height <= 0:
            return
            
        # Draw title
        cr.set_source_rgb(0, 0, 0)
        cr.select_font_face("Sans", 0, 1)  # Bold
        cr.set_font_size(16)
        
        title = _("Bandwidth Over Time") if self._view_mode == "bandwidth" else _("Packets Over Time")
        text_extents = cr.text_extents(title)
        title_x = (width - text_extents.width) / 2
        cr.move_to(title_x, 25)
        cr.show_text(title)
        
        # Draw chart area background
        cr.set_source_rgb(0.98, 0.98, 0.98)
        cr.rectangle(chart_x, chart_y, chart_width, chart_height)
        cr.fill()
        
        # Draw grid lines
        cr.set_source_rgb(0.9, 0.9, 0.9)
        cr.set_line_width(1)
        
        # Vertical grid lines (time)
        time_steps = 5
        for i in range(time_steps + 1):
            x = chart_x + (i * chart_width / time_steps)
            cr.move_to(x, chart_y)
            cr.line_to(x, chart_y + chart_height)
            cr.stroke()
        
        # Horizontal grid lines (values)
        value_steps = 5
        for i in range(value_steps + 1):
            y = chart_y + (i * chart_height / value_steps)
            cr.move_to(chart_x, y)
            cr.line_to(chart_x + chart_width, y)
            cr.stroke()
        
        # Draw data
        if self._view_mode == "bandwidth":
            self._draw_bandwidth_chart(cr, chart_x, chart_y, chart_width, chart_height)
        else:
            self._draw_packet_chart(cr, chart_x, chart_y, chart_width, chart_height)
        
        # Draw axes
        cr.set_source_rgb(0, 0, 0)
        cr.set_line_width(2)
        
        # Y-axis
        cr.move_to(chart_x, chart_y)
        cr.line_to(chart_x, chart_y + chart_height)
        cr.stroke()
        
        # X-axis
        cr.move_to(chart_x, chart_y + chart_height)
        cr.line_to(chart_x + chart_width, chart_y + chart_height)
        cr.stroke()
        
        # Draw axis labels
        self._draw_axis_labels(cr, chart_x, chart_y, chart_width, chart_height)
        
        # Draw hover info
        if self._hover_x >= 0 and self._hover_info:
            self._draw_hover_info(cr, width, height)

    def _draw_empty(self, cr, width, height):
        """Draw empty state."""
        cr.set_source_rgb(0.5, 0.5, 0.5)
        cr.select_font_face("Sans", 0, 0)
        cr.set_font_size(14)
        
        text = _("No packet data to display")
        text_extents = cr.text_extents(text)
        x = (width - text_extents.width) / 2
        y = (height + text_extents.height) / 2
        
        cr.move_to(x, y)
        cr.show_text(text)

    def _draw_bandwidth_chart(self, cr, chart_x, chart_y, chart_width, chart_height):
        """Draw bandwidth over time as a line chart."""
        if not self._time_buckets or self._max_bandwidth == 0:
            return
            
        # Calculate points
        points = []
        for i, bucket in enumerate(self._time_buckets):
            x = chart_x + (i * chart_width / len(self._time_buckets))
            bandwidth = bucket['byte_count'] / self._bucket_duration
            y = chart_y + chart_height - (bandwidth / self._max_bandwidth * chart_height)
            points.append((x, y, bandwidth))
        
        # Draw area under curve
        if len(points) > 1:
            cr.set_source_rgba(0.2, 0.6, 1.0, 0.3)
            cr.move_to(points[0][0], chart_y + chart_height)
            for x, y, _ in points:
                cr.line_to(x, y)
            cr.line_to(points[-1][0], chart_y + chart_height)
            cr.close_path()
            cr.fill()
        
        # Draw line
        cr.set_source_rgb(0.2, 0.6, 1.0)
        cr.set_line_width(2)
        
        if points:
            cr.move_to(points[0][0], points[0][1])
            for x, y, _ in points[1:]:
                cr.line_to(x, y)
            cr.stroke()
        
        # Draw data points
        cr.set_source_rgb(0.1, 0.4, 0.8)
        for x, y, _ in points:
            cr.arc(x, y, 3, 0, 2 * math.pi)
            cr.fill()

    def _draw_packet_chart(self, cr, chart_x, chart_y, chart_width, chart_height):
        """Draw packet count over time as stacked bars by protocol."""
        if not self._time_buckets:
            return
            
        max_packets = max(bucket['packet_count'] for bucket in self._time_buckets)
        if max_packets == 0:
            return
            
        bar_width = chart_width / len(self._time_buckets) * 0.8
        bar_spacing = chart_width / len(self._time_buckets) * 0.2
        
        for i, bucket in enumerate(self._time_buckets):
            x = chart_x + i * (bar_width + bar_spacing)
            
            # Draw stacked bars by protocol
            y_offset = 0
            total_packets = bucket['packet_count']
            
            for protocol, count in bucket['protocols'].items():
                if count == 0:
                    continue
                    
                bar_height = (count / max_packets) * chart_height
                y = chart_y + chart_height - y_offset - bar_height
                
                # Get protocol color
                color = PROTOCOL_COLORS.get(protocol, PROTOCOL_COLORS['OTHER'])
                cr.set_source_rgb(*color)
                
                cr.rectangle(x, y, bar_width, bar_height)
                cr.fill()
                
                # Draw outline
                cr.set_source_rgb(0, 0, 0)
                cr.set_line_width(1)
                cr.rectangle(x, y, bar_width, bar_height)
                cr.stroke()
                
                y_offset += bar_height

    def _draw_axis_labels(self, cr, chart_x, chart_y, chart_width, chart_height):
        """Draw axis labels and tick marks."""
        cr.set_source_rgb(0, 0, 0)
        cr.select_font_face("Sans", 0, 0)
        cr.set_font_size(10)
        
        # Y-axis labels
        if self._view_mode == "bandwidth":
            max_val = self._max_bandwidth
            unit = "B/s"
        else:
            max_val = max(bucket['packet_count'] for bucket in self._time_buckets) if self._time_buckets else 0
            unit = _("packets")
        
        for i in range(6):  # 5 intervals + 0
            value = max_val * (5 - i) / 5
            y = chart_y + (i * chart_height / 5)
            
            if self._view_mode == "bandwidth":
                label = self._format_bandwidth(value)
            else:
                label = f"{int(value)}"
            
            text_extents = cr.text_extents(label)
            cr.move_to(chart_x - text_extents.width - 5, y + text_extents.height / 2)
            cr.show_text(label)
        
        # X-axis labels (time)
        if self._start_time and self._end_time:
            time_range = self._end_time - self._start_time
            
            for i in range(6):  # 5 intervals + start
                time_offset = time_range * i / 5
                timestamp = self._start_time + time_offset
                
                x = chart_x + (i * chart_width / 5)
                y = chart_y + chart_height + 15
                
                # Format time
                dt = datetime.fromtimestamp(timestamp)
                if time_range < 300:  # Less than 5 minutes, show seconds
                    label = dt.strftime("%H:%M:%S")
                elif time_range < 3600:  # Less than 1 hour, show minutes
                    label = dt.strftime("%H:%M")
                else:  # Show hours
                    label = dt.strftime("%H:%M")
                
                text_extents = cr.text_extents(label)
                cr.move_to(x - text_extents.width / 2, y)
                cr.show_text(label)

    def _draw_hover_info(self, cr, width, height):
        """Draw hover information box."""
        if not self._hover_info:
            return
            
        # Info box dimensions
        padding = 8
        line_height = 14
        lines = self._hover_info.split('\n')
        max_width = max(len(line) * 7 for line in lines)  # Approximate width
        box_width = max_width + 2 * padding
        box_height = len(lines) * line_height + 2 * padding
        
        # Position box near hover point
        box_x = min(self._hover_x + 10, width - box_width - 10)
        box_y = 50
        
        # Draw box background
        cr.set_source_rgba(0, 0, 0, 0.8)
        cr.rectangle(box_x, box_y, box_width, box_height)
        cr.fill()
        
        # Draw text
        cr.set_source_rgb(1, 1, 1)
        cr.select_font_face("Sans", 0, 0)
        cr.set_font_size(11)
        
        for i, line in enumerate(lines):
            cr.move_to(box_x + padding, box_y + padding + (i + 1) * line_height)
            cr.show_text(line)

    def _format_bandwidth(self, bytes_per_sec):
        """Format bandwidth in human-readable units."""
        for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if bytes_per_sec < 1024:
                return f"{bytes_per_sec:.1f} {unit}"
            bytes_per_sec /= 1024
        return f"{bytes_per_sec:.1f} TB/s"

    def _on_motion(self, controller, x, y):
        """Handle mouse motion for hover effects."""
        self._hover_x = x
        
        # Calculate which time bucket we're hovering over
        margin_left = 80
        margin_right = 20
        chart_width = self.get_width() - margin_left - margin_right
        
        if x < margin_left or x > self.get_width() - margin_right or not self._time_buckets:
            self._hover_info = ""
            self.queue_draw()
            return
            
        # Calculate bucket index
        relative_x = x - margin_left
        bucket_index = int((relative_x / chart_width) * len(self._time_buckets))
        bucket_index = max(0, min(bucket_index, len(self._time_buckets) - 1))
        
        bucket = self._time_buckets[bucket_index]
        
        # Create hover info
        dt = datetime.fromtimestamp(bucket['time'])
        time_str = dt.strftime("%H:%M:%S")
        
        info_lines = [
            f"{_('Time')}: {time_str}",
            f"{_('Packets')}: {bucket['packet_count']}",
        ]
        
        if self._view_mode == "bandwidth":
            bandwidth = bucket['byte_count'] / self._bucket_duration
            info_lines.append(f"{_('Bandwidth')}: {self._format_bandwidth(bandwidth)}")
        
        # Add protocol breakdown
        if bucket['protocols']:
            info_lines.append(_("Protocols:"))
            for protocol, count in sorted(bucket['protocols'].items(), 
                                        key=lambda x: x[1], reverse=True)[:3]:
                info_lines.append(f"  {protocol}: {count}")
        
        self._hover_info = '\n'.join(info_lines)
        self.queue_draw()

    def _on_leave(self, controller):
        """Handle mouse leaving the widget."""
        self._hover_x = -1
        self._hover_info = ""
        self.queue_draw()


class TimelineView(Gtk.Box):
    """Widget for timeline and bandwidth analysis."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(12)
        self.set_margin_end(12)

        self._packets = []
        self._build_ui()

    def _build_ui(self):
        # Header with controls
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header_box.set_halign(Gtk.Align.START)

        self._analyze_btn = Gtk.Button(label=_("Generate Timeline"))
        self._analyze_btn.set_sensitive(False)
        self._analyze_btn.connect("clicked", self._on_analyze_clicked)
        header_box.append(self._analyze_btn)

        # View mode selection
        view_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        view_label = Gtk.Label(label=_("View:"))
        view_box.append(view_label)

        self._view_combo = Gtk.ComboBoxText()
        self._view_combo.append_text(_("Bandwidth"))
        self._view_combo.append_text(_("Packets"))
        self._view_combo.set_active(0)
        self._view_combo.connect("changed", self._on_view_changed)
        view_box.append(self._view_combo)

        header_box.append(view_box)

        # Time bucket duration
        bucket_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        bucket_label = Gtk.Label(label=_("Time bucket:"))
        bucket_box.append(bucket_label)

        self._bucket_combo = Gtk.ComboBoxText()
        self._bucket_combo.append_text(_("0.1 seconds"))
        self._bucket_combo.append_text(_("1 second"))
        self._bucket_combo.append_text(_("10 seconds"))
        self._bucket_combo.append_text(_("1 minute"))
        self._bucket_combo.set_active(1)
        self._bucket_combo.connect("changed", self._on_bucket_changed)
        bucket_box.append(self._bucket_combo)

        header_box.append(bucket_box)

        self._status_label = Gtk.Label(label=_("No timeline analysis performed yet"))
        self._status_label.add_css_class("dim-label")
        header_box.append(self._status_label)

        self.append(header_box)

        # Timeline widget
        timeline_frame = Gtk.Frame()
        timeline_frame.set_label(_("Traffic Timeline"))
        timeline_frame.set_vexpand(True)

        self._timeline_widget = TimelineWidget()
        timeline_frame.set_child(self._timeline_widget)
        self.append(timeline_frame)

        # Statistics summary
        stats_frame = Gtk.Frame()
        stats_frame.set_label(_("Timeline Statistics"))
        
        self._stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        self._stats_box.set_margin_top(12)
        self._stats_box.set_margin_bottom(12)
        self._stats_box.set_margin_start(12)
        self._stats_box.set_margin_end(12)
        
        stats_frame.set_child(self._stats_box)
        self.append(stats_frame)

    def _on_analyze_clicked(self, btn):
        """Generate timeline from loaded packets."""
        if hasattr(self, '_pcap_file') and self._pcap_file.packets:
            self._analyze_timeline(self._pcap_file.packets)

    def _on_view_changed(self, combo):
        """Handle view mode change."""
        view_mode = "bandwidth" if combo.get_active() == 0 else "packets"
        self._timeline_widget.set_view_mode(view_mode)

    def _on_bucket_changed(self, combo):
        """Handle bucket duration change."""
        durations = [0.1, 1.0, 10.0, 60.0]
        duration = durations[combo.get_active()]
        self._timeline_widget.set_bucket_duration(duration)

    def _analyze_timeline(self, packets):
        """Analyze timeline from packets."""
        self._packets = packets
        self._timeline_widget.set_packets(packets)
        
        if not packets:
            return
            
        # Calculate statistics
        times = [pkt.time for pkt in packets]
        start_time = min(times)
        end_time = max(times)
        duration = end_time - start_time
        
        total_bytes = sum(len(pkt) for pkt in packets)
        avg_bandwidth = total_bytes / duration if duration > 0 else 0
        
        # Protocol distribution
        protocol_counts = defaultdict(int)
        for pkt in packets:
            protocol = get_protocol_name(pkt)
            protocol_counts[protocol] += 1
        
        # Find traffic spikes (buckets with >2x average traffic)
        buckets = self._timeline_widget._time_buckets
        if buckets:
            avg_bucket_bytes = total_bytes / len(buckets)
            spikes = [i for i, bucket in enumerate(buckets) 
                     if bucket['byte_count'] > avg_bucket_bytes * 2]
        else:
            spikes = []
        
        # Update statistics display
        self._update_statistics(duration, total_bytes, avg_bandwidth, 
                              protocol_counts, len(spikes))
        
        # Update status
        self._status_label.set_text(
            _("Timeline generated from {packets} packets over {duration:.1f}s").format(
                packets=len(packets), duration=duration
            )
        )

    def _update_statistics(self, duration, total_bytes, avg_bandwidth, protocol_counts, spike_count):
        """Update the statistics display."""
        # Clear existing stats
        while self._stats_box.get_first_child():
            self._stats_box.remove(self._stats_box.get_first_child())

        # Basic stats
        basic_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        basic_box.append(Gtk.Label(label=_("Basic Statistics"), css_classes=["heading"]))
        basic_box.append(Gtk.Label(label=f"{_('Duration')}: {duration:.1f}s", halign=Gtk.Align.START))
        basic_box.append(Gtk.Label(label=f"{_('Total Data')}: {self._format_bytes(total_bytes)}", halign=Gtk.Align.START))
        basic_box.append(Gtk.Label(label=f"{_('Avg Bandwidth')}: {self._format_bandwidth(avg_bandwidth)}", halign=Gtk.Align.START))
        basic_box.append(Gtk.Label(label=f"{_('Traffic Spikes')}: {spike_count}", halign=Gtk.Align.START))
        self._stats_box.append(basic_box)

        # Protocol distribution
        if protocol_counts:
            proto_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            proto_box.append(Gtk.Label(label=_("Top Protocols"), css_classes=["heading"]))
            
            for protocol, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                proto_box.append(Gtk.Label(label=f"{protocol}: {count}", halign=Gtk.Align.START))
            
            self._stats_box.append(proto_box)

    def _format_bytes(self, byte_count):
        """Format byte count in human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if byte_count < 1024:
                return f"{byte_count:.1f} {unit}"
            byte_count /= 1024
        return f"{byte_count:.1f} TB"

    def _format_bandwidth(self, bytes_per_sec):
        """Format bandwidth in human-readable units."""
        for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if bytes_per_sec < 1024:
                return f"{bytes_per_sec:.1f} {unit}"
            bytes_per_sec /= 1024
        return f"{bytes_per_sec:.1f} TB/s"

    def update_packets(self, pcap_file):
        """Update with new packets."""
        self._pcap_file = pcap_file
        self._analyze_btn.set_sensitive(pcap_file.packets is not None)
        if not pcap_file.packets:
            self._timeline_widget.set_packets([])
            self._status_label.set_text(_("No timeline analysis performed yet"))
            # Clear statistics
            while self._stats_box.get_first_child():
                self._stats_box.remove(self._stats_box.get_first_child())