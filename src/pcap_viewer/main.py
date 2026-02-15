"""PCAP Viewer - GTK4/Adwaita application for analyzing network captures."""

import sys
import os
import gettext
import threading

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GObject, GLib, Gdk, Pango

from . import __version__
from .pcap_parser import PcapFile, get_layers, format_hex
from .hex_view import HexView
from .stats import compute_stats

# i18n
LOCALE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "po")
if not os.path.isdir(LOCALE_DIR):
    LOCALE_DIR = "/usr/share/locale"
gettext.bindtextdomain("pcap-viewer", LOCALE_DIR)
gettext.textdomain("pcap-viewer")
_ = gettext.gettext

APP_ID = "se.danielnylander.pcap-viewer"


class PacketObject(GObject.Object):
    """GObject wrapper for packet data to use with Gio.ListStore."""

    __gtype_name__ = "PacketObject"

    def __init__(self, nr=0, time=0.0, src="", dst="", protocol="", length=0, info="", index=0):
        super().__init__()
        self._nr = nr
        self._time = time
        self._src = src
        self._dst = dst
        self._protocol = protocol
        self._length = length
        self._info = info
        self._index = index  # index into pcap_file packets

    @GObject.Property(type=int)
    def nr(self):
        return self._nr

    @GObject.Property(type=float)
    def time(self):
        return self._time

    @GObject.Property(type=str)
    def src(self):
        return self._src

    @GObject.Property(type=str)
    def dst(self):
        return self._dst

    @GObject.Property(type=str)
    def protocol(self):
        return self._protocol

    @GObject.Property(type=int)
    def length(self):
        return self._length

    @GObject.Property(type=str)
    def info(self):
        return self._info

    @GObject.Property(type=int)
    def index(self):
        return self._index


class LayerObject(GObject.Object):
    """GObject wrapper for layer tree items."""

    __gtype_name__ = "LayerObject"

    def __init__(self, label="", children=None):
        super().__init__()
        self._label = label
        self._children = children or []

    @GObject.Property(type=str)
    def label(self):
        return self._label

    @property
    def children(self):
        return self._children


class PcapViewerWindow(Adw.ApplicationWindow):
    """Main application window."""

    def __init__(self, app):
        super().__init__(application=app)
        self.set_title(_("PCAP Viewer"))
        self.set_default_size(1200, 800)
        self.set_size_request(800, 500)

        self.pcap_file = PcapFile()
        self._current_page = 0

        self._build_ui()
        self._setup_drag_drop()
        self._setup_actions()

    def _build_ui(self):
        # Main layout
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # HeaderBar
        header = Adw.HeaderBar()
        self._filter_entry = Gtk.SearchEntry()
        self._filter_entry.set_placeholder_text(_("Filter (protocol, IP, keyword)…"))
        self._filter_entry.set_hexpand(True)
        self._filter_entry.connect("activate", self._on_filter_activate)

        open_btn = Gtk.Button(icon_name="document-open-symbolic")
        open_btn.set_tooltip_text(_("Open PCAP file"))
        open_btn.connect("clicked", self._on_open_clicked)

        # Hamburger menu
        menu = Gio.Menu()
        menu.append(_("Statistics"), "win.show-stats")
        menu.append(_("About"), "win.about")
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu)

        header.pack_start(open_btn)
        header.set_title_widget(self._filter_entry)
        header.pack_end(menu_btn)
        main_box.append(header)

        # Content with overlay for toast
        self._toast_overlay = Adw.ToastOverlay()

        # Stack for empty state vs content
        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)

        # Empty state
        empty = Adw.StatusPage()
        empty.set_icon_name("network-wired-symbolic")
        empty.set_title(_("No Capture Loaded"))
        empty.set_description(_("Open a .pcap or .pcapng file to begin analysis.\nYou can also drag and drop files here."))
        self._stack.add_named(empty, "empty")

        # Content panes
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Packet count bar
        self._status_label = Gtk.Label(label="")
        self._status_label.set_halign(Gtk.Align.START)
        self._status_label.add_css_class("dim-label")
        self._status_label.set_margin_start(8)
        self._status_label.set_margin_top(4)
        self._status_label.set_margin_bottom(4)
        content_box.append(self._status_label)

        paned_v1 = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)
        paned_v1.set_vexpand(True)

        # Top: Packet list (ColumnView)
        self._packet_store = Gio.ListStore(item_type=PacketObject)
        selection = Gtk.SingleSelection(model=self._packet_store)
        selection.connect("notify::selected", self._on_packet_selected)
        self._selection = selection

        self._column_view = Gtk.ColumnView(model=selection)
        self._column_view.add_css_class("data-table")

        columns = [
            ("Nr", "nr", 60),
            ("Time", "time", 100),
            ("Source", "src", 160),
            ("Destination", "dst", 160),
            ("Protocol", "protocol", 80),
            ("Length", "length", 70),
            ("Info", "info", 300),
        ]
        for title, prop, width in columns:
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self._on_col_setup)
            factory.connect("bind", self._on_col_bind, prop)
            col = Gtk.ColumnViewColumn(title=_(title), factory=factory)
            col.set_fixed_width(width)
            col.set_resizable(True)
            self._column_view.append_column(col)

        scroll_top = Gtk.ScrolledWindow()
        scroll_top.set_min_content_height(200)
        scroll_top.set_vexpand(True)
        scroll_top.set_child(self._column_view)
        paned_v1.set_start_child(scroll_top)

        # Bottom half: detail + hex
        paned_v2 = Gtk.Paned(orientation=Gtk.Orientation.VERTICAL)

        # Middle: Layer detail tree
        self._layer_store = Gio.ListStore(item_type=LayerObject)
        tree_model = Gtk.TreeListModel.new(self._layer_store, False, True, self._create_child_model)
        tree_selection = Gtk.SingleSelection(model=tree_model)
        self._layer_list = Gtk.ListView(model=tree_selection)
        layer_factory = Gtk.SignalListItemFactory()
        layer_factory.connect("setup", self._on_layer_setup)
        layer_factory.connect("bind", self._on_layer_bind)
        self._layer_list.set_factory(layer_factory)

        scroll_mid = Gtk.ScrolledWindow()
        scroll_mid.set_min_content_height(150)
        scroll_mid.set_vexpand(True)
        scroll_mid.set_child(self._layer_list)
        paned_v2.set_start_child(scroll_mid)

        # Bottom: Hex view
        self._hex_view = HexView()
        paned_v2.set_end_child(self._hex_view)

        paned_v1.set_end_child(paned_v2)
        paned_v1.set_position(350)
        paned_v2.set_position(200)

        content_box.append(paned_v1)
        self._stack.add_named(content_box, "content")

        self._toast_overlay.set_child(self._stack)
        main_box.append(self._toast_overlay)

        # Stats page
        self._stats_window = None

        self.set_content(main_box)

    def _setup_actions(self):
        about_action = Gio.SimpleAction.new("about", None)
        about_action.connect("activate", self._on_about)
        self.add_action(about_action)

        stats_action = Gio.SimpleAction.new("show-stats", None)
        stats_action.connect("activate", self._on_show_stats)
        self.add_action(stats_action)

    def _setup_drag_drop(self):
        drop = Gtk.DropTarget.new(Gio.File, Gdk.DragAction.COPY)
        drop.connect("drop", self._on_drop)
        self.add_controller(drop)

    def _on_drop(self, target, value, x, y):
        if isinstance(value, Gio.File):
            self._load_file(value.get_path())
            return True
        return False

    def _on_col_setup(self, factory, list_item):
        label = Gtk.Label()
        label.set_halign(Gtk.Align.START)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        list_item.set_child(label)

    def _on_col_bind(self, factory, list_item, prop):
        item = list_item.get_item()
        label = list_item.get_child()
        val = getattr(item, prop)
        if prop == "time":
            label.set_text(f"{val:.6f}")
        else:
            label.set_text(str(val))

    def _create_child_model(self, item):
        obj = item
        if hasattr(item, "get_item"):
            obj = item.get_item()
        if obj.children:
            store = Gio.ListStore(item_type=LayerObject)
            for child in obj.children:
                store.append(child)
            return store
        return None

    def _on_layer_setup(self, factory, list_item):
        expander = Gtk.TreeExpander()
        label = Gtk.Label()
        label.set_halign(Gtk.Align.START)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        expander.set_child(label)
        list_item.set_child(expander)

    def _on_layer_bind(self, factory, list_item):
        expander = list_item.get_child()
        row = list_item.get_item()
        expander.set_list_row(row)
        obj = row.get_item()
        label = expander.get_child()
        label.set_text(obj.label)

    def _on_open_clicked(self, btn):
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Open PCAP File"))
        f = Gtk.FileFilter()
        f.set_name(_("PCAP files"))
        f.add_pattern("*.pcap")
        f.add_pattern("*.pcapng")
        f.add_pattern("*.cap")
        filters = Gio.ListStore(item_type=Gtk.FileFilter)
        filters.append(f)
        all_f = Gtk.FileFilter()
        all_f.set_name(_("All files"))
        all_f.add_pattern("*")
        filters.append(all_f)
        dialog.set_filters(filters)
        dialog.open(self, None, self._on_file_opened)

    def _on_file_opened(self, dialog, result):
        try:
            f = dialog.open_finish(result)
            if f:
                self._load_file(f.get_path())
        except GLib.Error:
            pass

    def _load_file(self, filepath):
        """Load a PCAP file in a background thread."""
        self._toast_overlay.add_toast(Adw.Toast(title=_("Loading…")))

        def do_load():
            try:
                self.pcap_file.load(filepath)
                GLib.idle_add(self._on_file_loaded, filepath)
            except Exception as e:
                GLib.idle_add(self._on_load_error, str(e))

        thread = threading.Thread(target=do_load, daemon=True)
        thread.start()

    def _on_file_loaded(self, filepath):
        self.set_title(f"{os.path.basename(filepath)} — {_('PCAP Viewer')}")
        self._current_page = 0
        self._populate_packets()
        self._stack.set_visible_child_name("content")

    def _on_load_error(self, msg):
        self._toast_overlay.add_toast(Adw.Toast(title=_("Error: ") + msg))

    def _populate_packets(self):
        self._packet_store.remove_all()
        page = self.pcap_file.get_page(self._current_page)
        for p in page:
            obj = PacketObject(
                nr=p["nr"],
                time=p["time"],
                src=p["src"],
                dst=p["dst"],
                protocol=p["protocol"],
                length=p["length"],
                info=p["info"],
                index=p["nr"] - 1,
            )
            self._packet_store.append(obj)
        total = self.pcap_file.total_count
        shown = len(page)
        self._status_label.set_text(
            _("{shown} of {total} packets").format(shown=shown, total=total)
        )

    def _on_filter_activate(self, entry):
        text = entry.get_text()
        self.pcap_file.apply_filter(text)
        self._current_page = 0
        self._populate_packets()

    def _on_packet_selected(self, selection, pspec):
        pos = selection.get_selected()
        item = selection.get_selected_item()
        if item is None:
            return

        idx = item.index
        pkt = self.pcap_file.get_packet(idx)
        if pkt is None:
            return

        # Update hex view
        hex_text = self.pcap_file.get_hex_dump(idx)
        self._hex_view.set_hex_text(hex_text)

        # Update layer detail
        self._layer_store.remove_all()
        layers = get_layers(pkt)
        for layer_name, fields in layers:
            children = [LayerObject(label=f"{fname}: {fval}") for fname, fval in fields]
            self._layer_store.append(LayerObject(label=layer_name, children=children))

    def _on_about(self, action, param):
        about = Adw.AboutWindow(
            application_name=_("PCAP Viewer"),
            application_icon="network-wired-symbolic",
            version=__version__,
            developer_name="Daniel Nylander",
            developers=["Daniel Nylander <daniel@danielnylander.se>"],
            copyright="© 2025 Daniel Nylander",
            license_type=Gtk.License.GPL_3_0,
            website="https://github.com/yeager/pcap-viewer",
            issue_url="https://github.com/yeager/pcap-viewer/issues",
            transient_for=self,
        )
        about.present()

    def _on_show_stats(self, action, param):
        if self.pcap_file.packets is None:
            self._toast_overlay.add_toast(Adw.Toast(title=_("No capture loaded")))
            return

        stats = compute_stats(self.pcap_file.packets)

        win = Adw.Window(transient_for=self)
        win.set_title(_("Statistics"))
        win.set_default_size(600, 500)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        header = Adw.HeaderBar()
        box.append(header)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(16)
        content.set_margin_bottom(16)
        content.set_margin_start(16)
        content.set_margin_end(16)

        # Protocol distribution
        content.append(Gtk.Label(label=_("Protocol Distribution"), css_classes=["title-3"], halign=Gtk.Align.START))
        for proto, count in sorted(stats["protocol_dist"].items(), key=lambda x: x[1], reverse=True):
            content.append(Gtk.Label(label=f"  {proto}: {count}", halign=Gtk.Align.START))

        # Top talkers
        content.append(Gtk.Label(label=_("Top Talkers"), css_classes=["title-3"], halign=Gtk.Align.START))
        for ip, nbytes in stats["top_talkers"][:10]:
            content.append(Gtk.Label(label=f"  {ip}: {nbytes} bytes", halign=Gtk.Align.START))

        # Conversations
        content.append(Gtk.Label(label=_("Conversations"), css_classes=["title-3"], halign=Gtk.Align.START))
        for (src, dst), nbytes, count in stats["conversations"][:10]:
            content.append(Gtk.Label(label=f"  {src} ↔ {dst}: {nbytes} bytes ({count} packets)", halign=Gtk.Align.START))

        # DNS queries
        if stats["dns_queries"]:
            content.append(Gtk.Label(label=_("DNS Queries"), css_classes=["title-3"], halign=Gtk.Align.START))
            for qname, count in stats["dns_queries"][:10]:
                content.append(Gtk.Label(label=f"  {qname}: {count}", halign=Gtk.Align.START))

        scroll.set_child(content)
        box.append(scroll)
        win.set_content(box)
        win.present()


class PcapViewerApp(Adw.Application):
    """Main application class."""

    def __init__(self):
        super().__init__(application_id=APP_ID)
        self._window = None

    def do_activate(self):
        if not self._window:
            self._window = PcapViewerWindow(self)
        self._window.present()

    def do_open(self, files, n_files, hint):
        self.do_activate()
        if n_files > 0:
            self._window._load_file(files[0].get_path())


def main():
    app = PcapViewerApp()
    app.set_flags(Gio.ApplicationFlags.HANDLES_OPEN)
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
