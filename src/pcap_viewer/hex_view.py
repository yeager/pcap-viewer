"""Hex dump widget for displaying packet bytes."""

import gettext

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Pango

_ = gettext.gettext


class HexView(Gtk.ScrolledWindow):
    """Widget displaying hex + ASCII dump of packet data."""

    def __init__(self):
        super().__init__()
        self.set_vexpand(True)
        self.set_hexpand(True)
        self.set_min_content_height(150)

        self._textview = Gtk.TextView()
        self._textview.set_editable(False)
        self._textview.set_cursor_visible(False)
        self._textview.set_monospace(True)
        self._textview.add_css_class("hex-view")

        self.set_child(self._textview)

        buf = self._textview.get_buffer()
        self._highlight_tag = buf.create_tag("highlight", background="yellow", foreground="black")

    def set_hex_text(self, text):
        """Set the hex dump text."""
        buf = self._textview.get_buffer()
        buf.set_text(text if text else "")

    def clear(self):
        """Clear the hex view."""
        buf = self._textview.get_buffer()
        buf.set_text("")

    def highlight_bytes(self, start, length):
        """Highlight a range of bytes in the hex view."""
        buf = self._textview.get_buffer()
        buf.remove_all_tags(buf.get_start_iter(), buf.get_end_iter())

        if length <= 0:
            return

        text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
        lines = text.split("\n")

        for byte_idx in range(start, start + length):
            line_num = byte_idx // 16
            col = byte_idx % 16
            if line_num >= len(lines):
                break
            # Each line: "XXXXXXXX  XX XX XX ... |ASCII|"
            # Hex starts at position 10, each byte is 3 chars
            char_offset = 10 + col * 3
            line_start = sum(len(l) + 1 for l in lines[:line_num])
            s = buf.get_iter_at_offset(line_start + char_offset)
            e = buf.get_iter_at_offset(line_start + char_offset + 2)
            buf.apply_tag(self._highlight_tag, s, e)
