"""HTTP request/response analysis and decoding."""

import gettext
import re
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GObject, Pango

from scapy.all import TCP, Raw, IP

_ = gettext.gettext

# HTTP status code categories
STATUS_CATEGORIES = {
    1: _("Informational"),
    2: _("Success"),
    3: _("Redirection"),
    4: _("Client Error"),
    5: _("Server Error")
}

# Common HTTP headers for parsing
COMMON_HEADERS = [
    'host', 'user-agent', 'accept', 'accept-language', 'accept-encoding',
    'connection', 'content-type', 'content-length', 'cache-control',
    'cookie', 'set-cookie', 'location', 'referer', 'server'
]


class HTTPTransactionObject(GObject.Object):
    """GObject wrapper for HTTP request/response pairs."""

    __gtype_name__ = "HTTPTransactionObject"

    def __init__(self, timestamp=0.0, method="", url="", status_code=0, 
                 status_text="", content_type="", content_length=0,
                 src_addr="", dst_addr="", request_headers=None, response_headers=None,
                 request_body="", response_body=""):
        super().__init__()
        self._timestamp = timestamp
        self._method = method
        self._url = url
        self._status_code = status_code
        self._status_text = status_text
        self._content_type = content_type
        self._content_length = content_length
        self._src_addr = src_addr
        self._dst_addr = dst_addr
        self._request_headers = request_headers or {}
        self._response_headers = response_headers or {}
        self._request_body = request_body
        self._response_body = response_body

    @GObject.Property(type=float)
    def timestamp(self):
        return self._timestamp

    @GObject.Property(type=str)
    def method(self):
        return self._method

    @GObject.Property(type=str)
    def url(self):
        return self._url

    @GObject.Property(type=int)
    def status_code(self):
        return self._status_code

    @GObject.Property(type=str)
    def status_text(self):
        return self._status_text

    @GObject.Property(type=str)
    def content_type(self):
        return self._content_type

    @GObject.Property(type=int)
    def content_length(self):
        return self._content_length

    @GObject.Property(type=str)
    def src_addr(self):
        return self._src_addr

    @GObject.Property(type=str)
    def dst_addr(self):
        return self._dst_addr

    @property
    def time_formatted(self):
        return datetime.fromtimestamp(self._timestamp).strftime("%H:%M:%S.%f")[:-3]

    @property
    def request_headers(self):
        return self._request_headers

    @property
    def response_headers(self):
        return self._response_headers

    @property
    def request_body(self):
        return self._request_body

    @property
    def response_body(self):
        return self._response_body

    @property
    def host(self):
        return self._request_headers.get('host', self._dst_addr)


class HTTPAnalyzerView(Gtk.Box):
    """Widget for analyzing HTTP traffic."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(12)
        self.set_margin_end(12)

        self._http_transactions = []
        self._build_ui()

    def _build_ui(self):
        # Header with analyze button and filters
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header_box.set_halign(Gtk.Align.START)

        self._analyze_btn = Gtk.Button(label=_("Analyze HTTP"))
        self._analyze_btn.set_sensitive(False)
        self._analyze_btn.connect("clicked", self._on_analyze_clicked)
        header_box.append(self._analyze_btn)

        # Filter controls
        filter_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        
        filter_label = Gtk.Label(label=_("Filter:"))
        filter_box.append(filter_label)

        self._filter_entry = Gtk.SearchEntry()
        self._filter_entry.set_placeholder_text(_("Search URLs, hosts..."))
        self._filter_entry.set_size_request(200, -1)
        self._filter_entry.connect("search-changed", self._on_filter_changed)
        filter_box.append(self._filter_entry)

        # Method filter
        method_label = Gtk.Label(label=_("Method:"))
        filter_box.append(method_label)

        self._method_combo = Gtk.ComboBoxText()
        self._method_combo.append_text(_("All"))
        for method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]:
            self._method_combo.append_text(method)
        self._method_combo.set_active(0)
        self._method_combo.connect("changed", self._on_method_filter_changed)
        filter_box.append(self._method_combo)

        # Status code filter
        status_label = Gtk.Label(label=_("Status:"))
        filter_box.append(status_label)

        self._status_combo = Gtk.ComboBoxText()
        self._status_combo.append_text(_("All"))
        self._status_combo.append_text(_("2xx Success"))
        self._status_combo.append_text(_("3xx Redirect"))
        self._status_combo.append_text(_("4xx Client Error"))
        self._status_combo.append_text(_("5xx Server Error"))
        self._status_combo.set_active(0)
        self._status_combo.connect("changed", self._on_status_filter_changed)
        filter_box.append(self._status_combo)

        header_box.append(filter_box)

        self._status_label = Gtk.Label(label=_("No HTTP analysis performed yet"))
        self._status_label.add_css_class("dim-label")
        header_box.append(self._status_label)

        self.append(header_box)

        # HTTP transactions table
        self._http_store = Gio.ListStore(item_type=HTTPTransactionObject)
        self._filter_model = Gtk.FilterListModel(model=self._http_store)
        
        # Create custom filter
        self._custom_filter = Gtk.CustomFilter(match_func=self._filter_func)
        self._filter_model.set_filter(self._custom_filter)
        
        selection = Gtk.SingleSelection(model=self._filter_model)
        selection.connect("notify::selected", self._on_transaction_selected)

        self._column_view = Gtk.ColumnView(model=selection)
        self._column_view.add_css_class("data-table")

        columns = [
            (_("Time"), "time_formatted", 100),
            (_("Method"), "method", 60),
            (_("Host"), "host", 120),
            (_("URL"), "url", 250),
            (_("Status"), "status_code", 60),
            (_("Content-Type"), "content_type", 150),
            (_("Size"), "content_length", 80),
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
        scroll.set_min_content_height(300)
        scroll.set_child(self._column_view)
        self.append(scroll)

        # Transaction details notebook
        self._notebook = Gtk.Notebook()
        self._notebook.set_vexpand(True)

        # Request tab
        request_scroll = Gtk.ScrolledWindow()
        request_scroll.set_min_content_height(150)
        self._request_view = Gtk.TextView()
        self._request_view.set_editable(False)
        self._request_view.set_cursor_visible(False)
        self._request_view.set_monospace(True)
        request_scroll.set_child(self._request_view)
        
        request_tab = Gtk.Label(label=_("Request"))
        self._notebook.append_page(request_scroll, request_tab)

        # Response tab
        response_scroll = Gtk.ScrolledWindow()
        response_scroll.set_min_content_height(150)
        self._response_view = Gtk.TextView()
        self._response_view.set_editable(False)
        self._response_view.set_cursor_visible(False)
        self._response_view.set_monospace(True)
        response_scroll.set_child(self._response_view)
        
        response_tab = Gtk.Label(label=_("Response"))
        self._notebook.append_page(response_scroll, response_tab)

        # Headers tab
        headers_scroll = Gtk.ScrolledWindow()
        headers_scroll.set_min_content_height(150)
        self._headers_view = Gtk.TextView()
        self._headers_view.set_editable(False)
        self._headers_view.set_cursor_visible(False)
        self._headers_view.set_monospace(True)
        headers_scroll.set_child(self._headers_view)
        
        headers_tab = Gtk.Label(label=_("Headers"))
        self._notebook.append_page(headers_scroll, headers_tab)

        self.append(self._notebook)

    def _on_col_setup(self, factory, list_item):
        label = Gtk.Label()
        label.set_halign(Gtk.Align.START)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        list_item.set_child(label)

    def _on_col_bind(self, factory, list_item, prop):
        item = list_item.get_item()
        label = list_item.get_child()
        
        if prop == "time_formatted":
            label.set_text(item.time_formatted)
        elif prop == "host":
            label.set_text(item.host)
        elif prop == "status_code":
            status_code = getattr(item, "status_code")
            if status_code > 0:
                label.set_text(str(status_code))
                # Color code status
                if 200 <= status_code < 300:
                    label.add_css_class("success")
                elif 300 <= status_code < 400:
                    label.add_css_class("warning") 
                elif status_code >= 400:
                    label.add_css_class("error")
            else:
                label.set_text("-")
        elif prop == "content_length":
            length = getattr(item, "content_length")
            if length > 0:
                label.set_text(self._format_size(length))
            else:
                label.set_text("-")
        else:
            val = getattr(item, prop)
            label.set_text(str(val))

    def _format_size(self, size):
        """Format size in human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _filter_func(self, item):
        """Custom filter function for HTTP transactions."""
        # Text filter
        filter_text = self._filter_entry.get_text().lower()
        if filter_text:
            searchable_text = f"{item.url} {item.host} {item.content_type}".lower()
            if filter_text not in searchable_text:
                return False
        
        # Method filter
        method_filter = self._method_combo.get_active_text()
        if method_filter != _("All") and method_filter != item.method:
            return False
            
        # Status filter
        status_filter = self._status_combo.get_active_text()
        if status_filter != _("All"):
            status_code = item.status_code
            if status_filter == _("2xx Success") and not (200 <= status_code < 300):
                return False
            elif status_filter == _("3xx Redirect") and not (300 <= status_code < 400):
                return False
            elif status_filter == _("4xx Client Error") and not (400 <= status_code < 500):
                return False
            elif status_filter == _("5xx Server Error") and not (500 <= status_code < 600):
                return False
                
        return True

    def _on_filter_changed(self, entry):
        """Handle search filter change."""
        self._custom_filter.changed(Gtk.FilterChange.DIFFERENT)

    def _on_method_filter_changed(self, combo):
        """Handle method filter change."""
        self._custom_filter.changed(Gtk.FilterChange.DIFFERENT)

    def _on_status_filter_changed(self, combo):
        """Handle status filter change."""
        self._custom_filter.changed(Gtk.FilterChange.DIFFERENT)

    def _on_transaction_selected(self, selection, pspec):
        """Handle HTTP transaction selection."""
        item = selection.get_selected_item()
        if item:
            self._show_transaction_details(item)

    def _on_analyze_clicked(self, btn):
        """Analyze HTTP traffic from loaded packets."""
        if hasattr(self, '_pcap_file') and self._pcap_file.packets:
            self._analyze_http(self._pcap_file.packets)

    def _show_transaction_details(self, transaction):
        """Show detailed information for the selected transaction."""
        # Request details
        request_buf = self._request_view.get_buffer()
        request_lines = []
        request_lines.append(f"{transaction.method} {transaction.url} HTTP/1.1")
        
        for header, value in transaction.request_headers.items():
            request_lines.append(f"{header}: {value}")
        
        if transaction.request_body:
            request_lines.append("")
            if self._is_text_content(transaction.request_body):
                request_lines.append(transaction.request_body[:1000])
                if len(transaction.request_body) > 1000:
                    request_lines.append("... (truncated)")
            else:
                request_lines.append(f"[Binary data, {len(transaction.request_body)} bytes]")
        
        request_buf.set_text("\n".join(request_lines))

        # Response details
        response_buf = self._response_view.get_buffer()
        response_lines = []
        
        if transaction.status_code > 0:
            response_lines.append(f"HTTP/1.1 {transaction.status_code} {transaction.status_text}")
            
            for header, value in transaction.response_headers.items():
                response_lines.append(f"{header}: {value}")
            
            if transaction.response_body:
                response_lines.append("")
                if self._is_text_content(transaction.response_body):
                    response_lines.append(transaction.response_body[:1000])
                    if len(transaction.response_body) > 1000:
                        response_lines.append("... (truncated)")
                else:
                    response_lines.append(f"[Binary data, {len(transaction.response_body)} bytes]")
        else:
            response_lines.append(_("No response captured"))
        
        response_buf.set_text("\n".join(response_lines))

        # Headers summary
        headers_buf = self._headers_view.get_buffer()
        headers_lines = []
        
        headers_lines.append(_("REQUEST HEADERS:"))
        headers_lines.append("-" * 50)
        for header, value in transaction.request_headers.items():
            headers_lines.append(f"{header}: {value}")
        
        headers_lines.append("")
        headers_lines.append(_("RESPONSE HEADERS:"))
        headers_lines.append("-" * 50)
        for header, value in transaction.response_headers.items():
            headers_lines.append(f"{header}: {value}")
        
        headers_buf.set_text("\n".join(headers_lines))

    def _is_text_content(self, data):
        """Check if content appears to be text."""
        if isinstance(data, str):
            return True
        try:
            data.decode('utf-8')
            return True
        except:
            return False

    def _analyze_http(self, packets):
        """Analyze HTTP traffic from packets."""
        self._http_store.remove_all()
        self._http_transactions.clear()

        # Group TCP streams that might contain HTTP
        http_streams = defaultdict(list)
        
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                payload = pkt[Raw].load
                
                # Look for HTTP traffic (port 80 or HTTP-like content)
                if (tcp.dport == 80 or tcp.sport == 80 or 
                    b'HTTP/' in payload or 
                    payload.startswith((b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ', b'PATCH '))):
                    
                    stream_key = (pkt['IP'].src, tcp.sport, pkt['IP'].dst, tcp.dport)
                    http_streams[stream_key].append(pkt)

        # Analyze each potential HTTP stream
        transactions_found = 0
        method_counts = defaultdict(int)
        status_counts = defaultdict(int)
        host_counts = defaultdict(int)

        for stream_key, stream_packets in http_streams.items():
            src_addr, src_port, dst_addr, dst_port = stream_key
            
            # Sort packets by sequence number and timestamp
            stream_packets.sort(key=lambda p: (p[TCP].seq, p.time))
            
            # Reassemble stream data
            stream_data = b""
            for pkt in stream_packets:
                if pkt.haslayer(Raw):
                    stream_data += pkt[Raw].load

            # Parse HTTP transactions from stream
            transactions = self._parse_http_stream(stream_data, src_addr, dst_addr, stream_packets[0].time)
            
            for transaction in transactions:
                self._http_store.append(transaction)
                self._http_transactions.append(transaction)
                transactions_found += 1
                
                method_counts[transaction.method] += 1
                if transaction.status_code > 0:
                    status_category = transaction.status_code // 100
                    status_counts[f"{status_category}xx"] += 1
                host_counts[transaction.host] += 1

        # Clear detail views
        for view in [self._request_view, self._response_view, self._headers_view]:
            buf = view.get_buffer()
            buf.set_text(_("Select a transaction to view details"))

        # Update status
        self._status_label.set_text(
            _("{transactions} HTTP transactions found").format(transactions=transactions_found)
        )

    def _parse_http_stream(self, stream_data, src_addr, dst_addr, base_timestamp):
        """Parse HTTP requests and responses from stream data."""
        transactions = []
        
        try:
            stream_str = stream_data.decode('utf-8', errors='ignore')
        except:
            return transactions

        # Split stream into potential HTTP messages
        http_messages = re.split(r'\r?\n\r?\n', stream_str)
        
        current_request = None
        
        for message in http_messages:
            if not message.strip():
                continue
                
            lines = message.split('\n')
            first_line = lines[0].strip()
            
            # Check if this is an HTTP request
            request_match = re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/\d\.\d', first_line)
            if request_match:
                method, url = request_match.groups()
                
                # Parse headers
                headers = {}
                body_start = 0
                for i, line in enumerate(lines[1:], 1):
                    line = line.strip()
                    if not line:
                        body_start = i + 1
                        break
                    if ':' in line:
                        header, value = line.split(':', 1)
                        headers[header.lower().strip()] = value.strip()
                
                # Extract body
                body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ""
                
                current_request = {
                    'timestamp': base_timestamp,
                    'method': method,
                    'url': url,
                    'headers': headers,
                    'body': body,
                    'src_addr': src_addr,
                    'dst_addr': dst_addr
                }
                
            # Check if this is an HTTP response
            response_match = re.match(r'^HTTP/\d\.\d\s+(\d+)\s*(.*)$', first_line)
            if response_match and current_request:
                status_code = int(response_match.group(1))
                status_text = response_match.group(2) or ""
                
                # Parse response headers
                response_headers = {}
                body_start = 0
                for i, line in enumerate(lines[1:], 1):
                    line = line.strip()
                    if not line:
                        body_start = i + 1
                        break
                    if ':' in line:
                        header, value = line.split(':', 1)
                        response_headers[header.lower().strip()] = value.strip()
                
                # Extract response body
                response_body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ""
                
                # Create transaction
                transaction = HTTPTransactionObject(
                    timestamp=current_request['timestamp'],
                    method=current_request['method'],
                    url=current_request['url'],
                    status_code=status_code,
                    status_text=status_text,
                    content_type=response_headers.get('content-type', ''),
                    content_length=int(response_headers.get('content-length', 0)),
                    src_addr=current_request['src_addr'],
                    dst_addr=current_request['dst_addr'],
                    request_headers=current_request['headers'],
                    response_headers=response_headers,
                    request_body=current_request['body'],
                    response_body=response_body
                )
                
                transactions.append(transaction)
                current_request = None
        
        # If we have a request without response, create a transaction anyway
        if current_request:
            transaction = HTTPTransactionObject(
                timestamp=current_request['timestamp'],
                method=current_request['method'],
                url=current_request['url'],
                status_code=0,
                status_text="",
                content_type="",
                content_length=0,
                src_addr=current_request['src_addr'],
                dst_addr=current_request['dst_addr'],
                request_headers=current_request['headers'],
                response_headers={},
                request_body=current_request['body'],
                response_body=""
            )
            transactions.append(transaction)
        
        return transactions

    def update_packets(self, pcap_file):
        """Update with new packets."""
        self._pcap_file = pcap_file
        self._analyze_btn.set_sensitive(pcap_file.packets is not None)
        if not pcap_file.packets:
            self._http_store.remove_all()
            self._http_transactions.clear()
            self._status_label.set_text(_("No HTTP analysis performed yet"))
            # Clear detail views
            for view in [self._request_view, self._response_view, self._headers_view]:
                buf = view.get_buffer()
                buf.set_text("")