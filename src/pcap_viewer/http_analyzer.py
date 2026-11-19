"""HTTP request/response analysis and decoding."""

import gettext
import re
from datetime import datetime

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GObject, Pango

from scapy.all import TCP

from .pcap_parser import get_tcp_endpoints

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


REQUEST_LINE = re.compile(rb"([A-Z]+) (\S+) HTTP/1\.[01]")
RESPONSE_LINE = re.compile(rb"HTTP/1\.[01] ([0-9]{3})(?: (.*))?")


def reassemble_http(segments):
    """Return the contiguous captured bytes, trimming retransmissions."""
    if not segments:
        return b""
    first_seq = segments[0][0]
    ordered = sorted(segments, key=lambda item: (item[0] - first_seq + 2**31) % 2**32)
    start = ordered[0][0]
    data = bytearray()
    for seq, payload in ordered:
        offset = (seq - start) % 2**32
        if offset > len(data):
            break
        data.extend(payload[max(0, len(data) - offset):])
    return bytes(data)


def read_chunked(data, pos):
    body = bytearray()
    while True:
        end = data.find(b"\r\n", pos)
        if end < 0:
            return None
        size_field = data[pos:end].split(b";", 1)[0]
        if not re.fullmatch(rb"[0-9a-fA-F]+", size_field):
            return None
        size = int(size_field, 16)
        pos = end + 2
        if size == 0:
            if data[pos:pos + 2] == b"\r\n":
                return bytes(body), pos + 2
            trailer_end = data.find(b"\r\n\r\n", pos)
            return (bytes(body), trailer_end + 4) if trailer_end >= 0 else None
        if data[pos + size:pos + size + 2] != b"\r\n":
            return None
        body.extend(data[pos:pos + size])
        pos += size + 2


def http_messages(data, *, response=False, request_methods=()):
    """Parse one direction of an HTTP/1.x connection."""
    pos = request_index = 0
    while pos < len(data):
        end = data.find(b"\r\n\r\n", pos)
        if end < 0:
            break
        start_line, *lines = data[pos:end].split(b"\r\n")
        match = (RESPONSE_LINE if response else REQUEST_LINE).fullmatch(start_line)
        if match is None:
            break
        fields = tuple((part or b"").decode("latin-1") for part in match.groups())
        status = int(fields[0]) if response else 0
        headers = {}
        for line in lines:
            key, sep, value = line.partition(b":")
            if sep:
                headers[key.decode("latin-1").lower()] = value.decode("latin-1").strip()
        pos = end + 4
        method = request_methods[request_index] if request_index < len(request_methods) else ""
        tunnel = response and (status == 101 or (method == "CONNECT" and 200 <= status < 300))
        no_body = response and (tunnel or method == "HEAD" or 100 <= status < 200 or status in (204, 304))
        length = headers.get("content-length")
        declared_length = 0
        if length is not None and re.fullmatch(r"[0-9]{1,18}", length):
            declared_length = int(length)
        encoding = headers.get("transfer-encoding", "").lower().split(",")[-1].strip()
        if no_body:
            body = b""
        elif encoding == "chunked":
            chunked = read_chunked(data, pos)
            if chunked is None:
                break
            body, pos = chunked
        elif length is not None:
            if not re.fullmatch(r"[0-9]{1,18}", length):
                break
            body = data[pos:pos + declared_length]
            pos += declared_length
        elif response:
            body, pos = data[pos:], len(data)
        else:
            body = b""
        if not response or status >= 200 or status == 101:
            yield fields, headers, body.decode("utf-8", errors="replace"), declared_length
            request_index += 1
        if tunnel:
            break


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
        self._custom_filter = Gtk.CustomFilter.new(self._filter_func)
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

        connections = []
        active = {}
        for pkt in packets:
            endpoints = get_tcp_endpoints(pkt)
            if endpoints is None:
                continue
            src, dst = endpoints
            tcp = pkt[TCP]
            key = tuple(sorted(endpoints))
            syn = bool(tcp.flags.S)
            syn_id = (src, tcp.seq) if syn and not tcp.flags.A else None
            current = active.get(key)
            if current is None or (syn_id is not None and current[0] != syn_id):
                current = (syn_id, {})
                active[key] = current
                connections.append(current[1])
            payload = bytes(tcp.payload)
            if not payload:
                continue
            _timestamp, segments = current[1].setdefault((src, dst), (float(pkt.time), []))
            segments.append(((tcp.seq + syn) % 2**32, payload))

        for streams in connections:
            reassembled = {key: (timestamp, reassemble_http(segments))
                           for key, (timestamp, segments) in streams.items()}
            for (src, dst), (timestamp, data) in reassembled.items():
                requests = list(http_messages(data))
                if not requests:
                    continue
                methods = [fields[0] for fields, *_ in requests]
                reply = reassembled.get((dst, src), (0, b""))[1]
                responses = iter(http_messages(reply, response=True, request_methods=methods))
                for (method, url), req_headers, req_body, _length in requests:
                    (status, reason), res_headers, res_body, length = next(
                        responses, (("0", ""), {}, "", 0))
                    transaction = HTTPTransactionObject(
                        timestamp=timestamp, method=method, url=url, status_code=int(status),
                        status_text=reason, content_type=res_headers.get("content-type", ""),
                        content_length=length, src_addr=src[0], dst_addr=dst[0],
                        request_headers=req_headers, response_headers=res_headers,
                        request_body=req_body, response_body=res_body,
                    )
                    self._http_store.append(transaction)
                    self._http_transactions.append(transaction)

        for view in (self._request_view, self._response_view, self._headers_view):
            view.get_buffer().set_text(_("Select a transaction to view details"))
        self._status_label.set_text(
            _("{transactions} HTTP transactions found").format(transactions=len(self._http_transactions))
        )

    def update_packets(self, pcap_file):
        """Update with new packets."""
        self._pcap_file = pcap_file
        self._analyze_btn.set_sensitive(pcap_file.packets is not None)
        self._http_store.remove_all()
        self._http_transactions.clear()
        self._status_label.set_text(_("No HTTP analysis performed yet"))
        # Clear detail views
        for view in [self._request_view, self._response_view, self._headers_view]:
            buf = view.get_buffer()
            buf.set_text("")
