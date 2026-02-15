"""DNS query and response analysis."""

import gettext
from collections import defaultdict
from datetime import datetime

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GObject, Pango

from scapy.all import DNS, DNSQR, DNSRR

_ = gettext.gettext

# DNS record types mapping
DNS_TYPES = {
    1: "A",
    2: "NS", 
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    51: "NSEC3PARAM",
    52: "TLSA",
    257: "CAA"
}


class DNSRecordObject(GObject.Object):
    """GObject wrapper for DNS record data."""

    __gtype_name__ = "DNSRecordObject"

    def __init__(self, timestamp=0.0, query_name="", record_type="", response_data="", 
                 ttl=0, rcode="", is_response=True, packet_id=0):
        super().__init__()
        self._timestamp = timestamp
        self._query_name = query_name
        self._record_type = record_type
        self._response_data = response_data
        self._ttl = ttl
        self._rcode = rcode
        self._is_response = is_response
        self._packet_id = packet_id

    @GObject.Property(type=float)
    def timestamp(self):
        return self._timestamp

    @GObject.Property(type=str)
    def query_name(self):
        return self._query_name

    @GObject.Property(type=str)
    def record_type(self):
        return self._record_type

    @GObject.Property(type=str)
    def response_data(self):
        return self._response_data

    @GObject.Property(type=int)
    def ttl(self):
        return self._ttl

    @GObject.Property(type=str)
    def rcode(self):
        return self._rcode

    @GObject.Property(type=bool, default=False)
    def is_response(self):
        return self._is_response

    @GObject.Property(type=int)
    def packet_id(self):
        return self._packet_id

    @property
    def time_formatted(self):
        return datetime.fromtimestamp(self._timestamp).strftime("%H:%M:%S.%f")[:-3]


class DNSAnalyzerView(Gtk.Box):
    """Widget for analyzing DNS queries and responses."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(12)
        self.set_margin_end(12)

        self._dns_records = []
        self._build_ui()

    def _build_ui(self):
        # Header with analyze button and filters
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header_box.set_halign(Gtk.Align.START)

        self._analyze_btn = Gtk.Button(label=_("Analyze DNS"))
        self._analyze_btn.set_sensitive(False)
        self._analyze_btn.connect("clicked", self._on_analyze_clicked)
        header_box.append(self._analyze_btn)

        # Filter controls
        filter_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        
        filter_label = Gtk.Label(label=_("Filter:"))
        filter_box.append(filter_label)

        self._filter_entry = Gtk.SearchEntry()
        self._filter_entry.set_placeholder_text(_("Search domain names..."))
        self._filter_entry.set_size_request(200, -1)
        self._filter_entry.connect("search-changed", self._on_filter_changed)
        filter_box.append(self._filter_entry)

        # Record type filter
        type_label = Gtk.Label(label=_("Type:"))
        filter_box.append(type_label)

        self._type_combo = Gtk.ComboBoxText()
        self._type_combo.append_text(_("All"))
        for type_name in sorted(set(DNS_TYPES.values())):
            self._type_combo.append_text(type_name)
        self._type_combo.set_active(0)
        self._type_combo.connect("changed", self._on_type_filter_changed)
        filter_box.append(self._type_combo)

        # Show only errors checkbox
        self._errors_only = Gtk.CheckButton(label=_("Errors only"))
        self._errors_only.connect("toggled", self._on_errors_filter_changed)
        filter_box.append(self._errors_only)

        header_box.append(filter_box)

        self._status_label = Gtk.Label(label=_("No DNS analysis performed yet"))
        self._status_label.add_css_class("dim-label")
        header_box.append(self._status_label)

        self.append(header_box)

        # DNS records table
        self._dns_store = Gio.ListStore(item_type=DNSRecordObject)
        self._filter_model = Gtk.FilterListModel(model=self._dns_store)
        
        # Create custom filter
        self._custom_filter = Gtk.CustomFilter(match_func=self._filter_func)
        self._filter_model.set_filter(self._custom_filter)
        
        selection = Gtk.SingleSelection(model=self._filter_model)
        selection.connect("notify::selected", self._on_record_selected)

        self._column_view = Gtk.ColumnView(model=selection)
        self._column_view.add_css_class("data-table")

        columns = [
            (_("Time"), "time_formatted", 100),
            (_("Query"), "query_name", 200),
            (_("Type"), "record_type", 60),
            (_("Response"), "response_data", 250),
            (_("TTL"), "ttl", 60),
            (_("Status"), "rcode", 80),
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
        scroll.set_vexpand(True)
        scroll.set_child(self._column_view)
        self.append(scroll)

        # Statistics summary
        stats_frame = Gtk.Frame()
        stats_frame.set_label(_("DNS Statistics"))
        
        self._stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        self._stats_box.set_margin_top(12)
        self._stats_box.set_margin_bottom(12)
        self._stats_box.set_margin_start(12)
        self._stats_box.set_margin_end(12)
        
        # Will be populated with statistics
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
        
        if prop == "time_formatted":
            label.set_text(item.time_formatted)
        elif prop == "ttl":
            ttl_val = getattr(item, "ttl")
            if ttl_val > 0:
                label.set_text(str(ttl_val))
            else:
                label.set_text("-")
        elif prop == "rcode":
            rcode_val = getattr(item, "rcode")
            if not item.is_response:
                label.set_text(_("Query"))
            elif rcode_val == "NOERROR":
                label.set_text(_("OK"))
                label.add_css_class("success")
            elif rcode_val:
                label.set_text(rcode_val)
                label.add_css_class("error")
            else:
                label.set_text("-")
        else:
            val = getattr(item, prop)
            label.set_text(str(val))

    def _filter_func(self, item):
        """Custom filter function for DNS records."""
        # Text filter
        filter_text = self._filter_entry.get_text().lower()
        if filter_text and filter_text not in item.query_name.lower():
            return False
        
        # Type filter
        type_filter = self._type_combo.get_active_text()
        if type_filter != _("All") and type_filter != item.record_type:
            return False
            
        # Errors only filter
        if self._errors_only.get_active():
            if item.is_response and item.rcode == "NOERROR":
                return False
                
        return True

    def _on_filter_changed(self, entry):
        """Handle search filter change."""
        self._custom_filter.changed(Gtk.FilterChange.DIFFERENT)

    def _on_type_filter_changed(self, combo):
        """Handle type filter change."""
        self._custom_filter.changed(Gtk.FilterChange.DIFFERENT)

    def _on_errors_filter_changed(self, button):
        """Handle errors only filter change."""
        self._custom_filter.changed(Gtk.FilterChange.DIFFERENT)

    def _on_record_selected(self, selection, pspec):
        """Handle DNS record selection."""
        item = selection.get_selected_item()
        if item:
            # Could show additional details here
            pass

    def _on_analyze_clicked(self, btn):
        """Analyze DNS records from loaded packets."""
        if hasattr(self, '_pcap_file') and self._pcap_file.packets:
            self._analyze_dns(self._pcap_file.packets)

    def _analyze_dns(self, packets):
        """Analyze DNS queries and responses from packets."""
        self._dns_store.remove_all()
        self._dns_records.clear()

        queries = {}  # Track queries by ID to match with responses
        total_queries = 0
        total_responses = 0
        error_count = 0
        type_counts = defaultdict(int)
        top_domains = defaultdict(int)

        for pkt in packets:
            if not pkt.haslayer(DNS):
                continue

            dns = pkt[DNS]
            timestamp = pkt.time
            
            # Handle queries (QR=0)
            if dns.qr == 0:
                total_queries += 1
                if dns.qdcount > 0:
                    for i in range(dns.qdcount):
                        try:
                            qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                            qtype = dns.qd.qtype
                            qtype_name = DNS_TYPES.get(qtype, str(qtype))
                            
                            # Store query for matching with response
                            queries[dns.id] = {
                                'qname': qname,
                                'qtype': qtype_name,
                                'timestamp': timestamp
                            }
                            
                            # Create query record
                            record = DNSRecordObject(
                                timestamp=timestamp,
                                query_name=qname,
                                record_type=qtype_name,
                                response_data="",
                                ttl=0,
                                rcode="",
                                is_response=False,
                                packet_id=dns.id
                            )
                            
                            self._dns_store.append(record)
                            self._dns_records.append(record)
                            
                            top_domains[qname] += 1
                            type_counts[qtype_name] += 1
                            
                        except Exception as e:
                            continue

            # Handle responses (QR=1) 
            elif dns.qr == 1:
                total_responses += 1
                
                # Get response code
                rcode_names = {
                    0: "NOERROR",
                    1: "FORMERR", 
                    2: "SERVFAIL",
                    3: "NXDOMAIN",
                    4: "NOTIMP",
                    5: "REFUSED"
                }
                rcode = rcode_names.get(dns.rcode, f"RCODE_{dns.rcode}")
                
                if rcode != "NOERROR":
                    error_count += 1

                # Get query info from stored queries
                query_info = queries.get(dns.id, {})
                qname = query_info.get('qname', '')
                qtype = query_info.get('qtype', '')
                
                # Process answer records
                if dns.ancount > 0:
                    try:
                        for i in range(dns.ancount):
                            if hasattr(dns.an, '__iter__'):
                                an = dns.an[i] if i < len(dns.an) else dns.an
                            else:
                                an = dns.an
                            
                            if hasattr(an, 'rrname'):
                                rrname = an.rrname.decode('utf-8', errors='ignore').rstrip('.')
                            else:
                                rrname = qname
                                
                            rrtype = DNS_TYPES.get(getattr(an, 'type', 0), 'Unknown')
                            ttl = getattr(an, 'ttl', 0)
                            
                            # Format response data based on type
                            if hasattr(an, 'rdata'):
                                if rrtype in ['A', 'AAAA']:
                                    rdata = str(an.rdata)
                                elif rrtype in ['CNAME', 'NS', 'PTR']:
                                    rdata = str(an.rdata).rstrip('.')
                                elif rrtype == 'MX':
                                    rdata = f"{an.preference} {an.exchange.decode('utf-8', errors='ignore').rstrip('.')}"
                                elif rrtype == 'TXT':
                                    rdata = str(an.rdata)
                                else:
                                    rdata = str(an.rdata)
                            else:
                                rdata = ""
                            
                            record = DNSRecordObject(
                                timestamp=timestamp,
                                query_name=rrname,
                                record_type=rrtype,
                                response_data=rdata,
                                ttl=ttl,
                                rcode=rcode,
                                is_response=True,
                                packet_id=dns.id
                            )
                            
                            self._dns_store.append(record)
                            self._dns_records.append(record)
                            
                    except Exception as e:
                        # Create a basic response record if parsing fails
                        record = DNSRecordObject(
                            timestamp=timestamp,
                            query_name=qname,
                            record_type=qtype,
                            response_data="",
                            ttl=0,
                            rcode=rcode,
                            is_response=True,
                            packet_id=dns.id
                        )
                        
                        self._dns_store.append(record)
                        self._dns_records.append(record)
                else:
                    # No answer records - create empty response
                    record = DNSRecordObject(
                        timestamp=timestamp,
                        query_name=qname,
                        record_type=qtype,
                        response_data="",
                        ttl=0,
                        rcode=rcode,
                        is_response=True,
                        packet_id=dns.id
                    )
                    
                    self._dns_store.append(record)
                    self._dns_records.append(record)

        # Update statistics
        self._update_statistics(total_queries, total_responses, error_count, 
                              type_counts, top_domains)
        
        # Update status
        total_records = len(self._dns_records)
        self._status_label.set_text(
            _("{records} DNS records analyzed").format(records=total_records)
        )

    def _update_statistics(self, queries, responses, errors, type_counts, top_domains):
        """Update the statistics display."""
        # Clear existing stats
        while self._stats_box.get_first_child():
            self._stats_box.remove(self._stats_box.get_first_child())

        # Basic stats
        basic_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        basic_box.append(Gtk.Label(label=_("Basic Statistics"), css_classes=["heading"]))
        basic_box.append(Gtk.Label(label=f"{_('Queries')}: {queries}", halign=Gtk.Align.START))
        basic_box.append(Gtk.Label(label=f"{_('Responses')}: {responses}", halign=Gtk.Align.START))
        basic_box.append(Gtk.Label(label=f"{_('Errors')}: {errors}", halign=Gtk.Align.START))
        self._stats_box.append(basic_box)

        # Top record types
        if type_counts:
            types_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            types_box.append(Gtk.Label(label=_("Top Record Types"), css_classes=["heading"]))
            
            for qtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                types_box.append(Gtk.Label(label=f"{qtype}: {count}", halign=Gtk.Align.START))
            
            self._stats_box.append(types_box)

        # Top queried domains
        if top_domains:
            domains_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            domains_box.append(Gtk.Label(label=_("Top Domains"), css_classes=["heading"]))
            
            for domain, count in sorted(top_domains.items(), key=lambda x: x[1], reverse=True)[:5]:
                domain_text = domain if len(domain) <= 30 else domain[:27] + "..."
                domains_box.append(Gtk.Label(label=f"{domain_text}: {count}", halign=Gtk.Align.START))
            
            self._stats_box.append(domains_box)

    def update_packets(self, pcap_file):
        """Update with new packets."""
        self._pcap_file = pcap_file
        self._analyze_btn.set_sensitive(pcap_file.packets is not None)
        if not pcap_file.packets:
            self._dns_store.remove_all()
            self._dns_records.clear()
            self._status_label.set_text(_("No DNS analysis performed yet"))
            # Clear statistics
            while self._stats_box.get_first_child():
                self._stats_box.remove(self._stats_box.get_first_child())