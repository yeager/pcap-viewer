"""File extraction from network captures."""

import gettext
import os
import tempfile
import magic
import base64
import binascii
from collections import defaultdict

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GObject, Pango

from scapy.all import TCP, UDP, Raw, IP

from .pcap_parser import get_protocol_name

_ = gettext.gettext


class FileObject(GObject.Object):
    """GObject wrapper for extracted files."""

    __gtype_name__ = "FileObject"

    def __init__(self, filename="", size=0, protocol="", mime_type="", stream_id="", data=b""):
        super().__init__()
        self._filename = filename
        self._size = size
        self._protocol = protocol
        self._mime_type = mime_type
        self._stream_id = stream_id
        self._data = data

    @GObject.Property(type=str)
    def filename(self):
        return self._filename

    @GObject.Property(type=int)
    def size(self):
        return self._size

    @GObject.Property(type=str)
    def protocol(self):
        return self._protocol

    @GObject.Property(type=str)
    def mime_type(self):
        return self._mime_type

    @GObject.Property(type=str)
    def stream_id(self):
        return self._stream_id

    @property
    def data(self):
        return self._data


class FileExtractorView(Gtk.Box):
    """Widget for extracting files from pcap captures."""

    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_margin_top(12)
        self.set_margin_bottom(12)
        self.set_margin_start(12)
        self.set_margin_end(12)

        self._extracted_files = []
        self._build_ui()

    def _build_ui(self):
        # Header with extract button
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header_box.set_halign(Gtk.Align.START)

        self._extract_btn = Gtk.Button(label=_("Extract Files"))
        self._extract_btn.set_sensitive(False)
        self._extract_btn.connect("clicked", self._on_extract_clicked)
        header_box.append(self._extract_btn)

        self._save_all_btn = Gtk.Button(label=_("Save All"))
        self._save_all_btn.set_sensitive(False)
        self._save_all_btn.connect("clicked", self._on_save_all_clicked)
        header_box.append(self._save_all_btn)

        self._status_label = Gtk.Label(label=_("No files extracted yet"))
        self._status_label.add_css_class("dim-label")
        header_box.append(self._status_label)

        self.append(header_box)

        # File list
        self._file_store = Gio.ListStore(item_type=FileObject)
        selection = Gtk.SingleSelection(model=self._file_store)
        selection.connect("notify::selected", self._on_file_selected)

        self._column_view = Gtk.ColumnView(model=selection)
        self._column_view.add_css_class("data-table")

        columns = [
            (_("Filename"), "filename", 200),
            (_("Size"), "size", 80),
            (_("Protocol"), "protocol", 80),
            (_("MIME Type"), "mime_type", 150),
            (_("Stream"), "stream_id", 100),
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

        # Save button for individual files
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        btn_box.set_halign(Gtk.Align.END)

        self._save_btn = Gtk.Button(label=_("Save Selected"))
        self._save_btn.set_sensitive(False)
        self._save_btn.connect("clicked", self._on_save_selected_clicked)
        btn_box.append(self._save_btn)

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
        if prop == "size":
            label.set_text(self._format_size(val))
        else:
            label.set_text(str(val))

    def _format_size(self, size):
        """Format file size in human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _on_file_selected(self, selection, pspec):
        item = selection.get_selected_item()
        self._save_btn.set_sensitive(item is not None)

    def _on_extract_clicked(self, btn):
        """Extract files from loaded packets."""
        if hasattr(self, '_pcap_file') and self._pcap_file.packets:
            self._extract_files(self._pcap_file.packets)

    def _on_save_all_clicked(self, btn):
        """Save all extracted files to a directory."""
        if not self._extracted_files:
            return

        dialog = Gtk.FileDialog()
        dialog.set_title(_("Select Directory to Save Files"))
        dialog.select_folder(None, None, self._on_save_all_folder_selected)

    def _on_save_selected_clicked(self, btn):
        """Save selected file."""
        selection = self._column_view.get_model()
        item = selection.get_selected_item()
        if not item:
            return

        dialog = Gtk.FileDialog()
        dialog.set_title(_("Save File As"))
        dialog.set_initial_name(item.filename)
        dialog.save(None, None, self._on_save_file_selected, item)

    def _on_save_all_folder_selected(self, dialog, result):
        try:
            folder = dialog.select_folder_finish(result)
            if folder:
                self._save_all_files(folder.get_path())
        except Exception as e:
            print(f"Error selecting folder: {e}")

    def _on_save_file_selected(self, dialog, result, file_obj):
        try:
            file_gio = dialog.save_finish(result)
            if file_gio:
                self._save_file(file_obj, file_gio.get_path())
        except Exception as e:
            print(f"Error saving file: {e}")

    def _save_file(self, file_obj, filepath):
        """Save a single file object to disk."""
        try:
            with open(filepath, 'wb') as f:
                f.write(file_obj.data)
        except Exception as e:
            print(f"Error writing file {filepath}: {e}")

    def _save_all_files(self, directory):
        """Save all extracted files to a directory."""
        for file_obj in self._extracted_files:
            filepath = os.path.join(directory, file_obj.filename)
            self._save_file(file_obj, filepath)

    def _extract_files(self, packets):
        """Extract files from packet capture."""
        self._file_store.remove_all()
        self._extracted_files.clear()

        # Group packets by TCP stream
        streams = defaultdict(list)
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                stream_id = f"{pkt[IP].src}:{tcp.sport}-{pkt[IP].dst}:{tcp.dport}"
                streams[stream_id].append(pkt)

        extracted_count = 0

        # Process each stream
        for stream_id, stream_packets in streams.items():
            # Sort by sequence number
            stream_packets.sort(key=lambda p: p[TCP].seq)
            
            # Reassemble stream data
            stream_data = b""
            for pkt in stream_packets:
                if pkt.haslayer(Raw):
                    stream_data += pkt[Raw].load

            # Extract HTTP objects
            extracted_count += self._extract_http_files(stream_data, stream_id)
            
            # Extract SMTP attachments
            extracted_count += self._extract_smtp_files(stream_data, stream_id)
            
            # Extract FTP transfers
            extracted_count += self._extract_ftp_files(stream_data, stream_id)

        self._status_label.set_text(_("{count} files extracted").format(count=extracted_count))
        self._save_all_btn.set_sensitive(extracted_count > 0)

    def _extract_http_files(self, data, stream_id):
        """Extract HTTP objects from stream data."""
        extracted = 0
        try:
            data_str = data.decode('latin-1', errors='ignore')
            
            # Split by HTTP responses
            responses = data_str.split('HTTP/1.')
            
            for i, response in enumerate(responses[1:], 1):  # Skip first split part
                try:
                    # Find end of headers
                    header_end = response.find('\r\n\r\n')
                    if header_end == -1:
                        continue
                    
                    headers = response[:header_end]
                    body = response[header_end + 4:]
                    
                    # Extract filename from headers
                    filename = f"http_object_{i}"
                    content_type = "application/octet-stream"
                    
                    for line in headers.split('\r\n'):
                        if line.lower().startswith('content-disposition:'):
                            if 'filename=' in line:
                                filename = line.split('filename=')[1].strip('"')
                        elif line.lower().startswith('content-type:'):
                            content_type = line.split(':', 1)[1].strip()
                    
                    if body:
                        body_bytes = body.encode('latin-1')
                        mime_type = self._detect_mime_type(body_bytes)
                        
                        file_obj = FileObject(
                            filename=filename,
                            size=len(body_bytes),
                            protocol="HTTP",
                            mime_type=mime_type or content_type,
                            stream_id=stream_id,
                            data=body_bytes
                        )
                        
                        self._file_store.append(file_obj)
                        self._extracted_files.append(file_obj)
                        extracted += 1
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            pass
            
        return extracted

    def _extract_smtp_files(self, data, stream_id):
        """Extract SMTP attachments from stream data."""
        extracted = 0
        try:
            data_str = data.decode('latin-1', errors='ignore')
            
            # Look for base64 encoded attachments
            if 'Content-Transfer-Encoding: base64' in data_str:
                lines = data_str.split('\r\n')
                in_attachment = False
                attachment_data = ""
                filename = "smtp_attachment"
                
                for line in lines:
                    if line.startswith('Content-Disposition: attachment'):
                        if 'filename=' in line:
                            filename = line.split('filename=')[1].strip('"')
                        in_attachment = True
                        attachment_data = ""
                    elif line.startswith('Content-Transfer-Encoding: base64'):
                        in_attachment = True
                    elif in_attachment and line.strip() and not line.startswith('--'):
                        attachment_data += line.strip()
                    elif in_attachment and (line.startswith('--') or line == ''):
                        if attachment_data:
                            try:
                                decoded_data = base64.b64decode(attachment_data)
                                mime_type = self._detect_mime_type(decoded_data)
                                
                                file_obj = FileObject(
                                    filename=filename,
                                    size=len(decoded_data),
                                    protocol="SMTP",
                                    mime_type=mime_type or "application/octet-stream",
                                    stream_id=stream_id,
                                    data=decoded_data
                                )
                                
                                self._file_store.append(file_obj)
                                self._extracted_files.append(file_obj)
                                extracted += 1
                                
                            except Exception:
                                pass
                        in_attachment = False
                        attachment_data = ""
                        filename = "smtp_attachment"
                        
        except Exception as e:
            pass
            
        return extracted

    def _extract_ftp_files(self, data, stream_id):
        """Extract FTP file transfers from stream data."""
        extracted = 0
        try:
            # FTP data transfers are typically binary data
            if len(data) > 100:  # Minimum size for a file
                mime_type = self._detect_mime_type(data)
                if mime_type and not mime_type.startswith('text/'):
                    filename = f"ftp_transfer_{len(self._extracted_files)}"
                    
                    # Try to infer extension from MIME type
                    if mime_type.startswith('image/jpeg'):
                        filename += '.jpg'
                    elif mime_type.startswith('image/png'):
                        filename += '.png'
                    elif mime_type.startswith('image/gif'):
                        filename += '.gif'
                    elif mime_type.startswith('application/pdf'):
                        filename += '.pdf'
                    elif mime_type.startswith('application/zip'):
                        filename += '.zip'
                    
                    file_obj = FileObject(
                        filename=filename,
                        size=len(data),
                        protocol="FTP",
                        mime_type=mime_type,
                        stream_id=stream_id,
                        data=data
                    )
                    
                    self._file_store.append(file_obj)
                    self._extracted_files.append(file_obj)
                    extracted += 1
                    
        except Exception as e:
            pass
            
        return extracted

    def _detect_mime_type(self, data):
        """Detect MIME type using magic bytes."""
        try:
            mime = magic.Magic(mime=True)
            return mime.from_buffer(data)
        except:
            # Fallback to simple magic byte detection
            if data.startswith(b'\x89PNG'):
                return 'image/png'
            elif data.startswith(b'\xFF\xD8\xFF'):
                return 'image/jpeg'
            elif data.startswith(b'GIF8'):
                return 'image/gif'
            elif data.startswith(b'%PDF'):
                return 'application/pdf'
            elif data.startswith(b'PK\x03\x04'):
                return 'application/zip'
            elif data.startswith(b'<!DOCTYPE html') or data.startswith(b'<html'):
                return 'text/html'
            return None

    def update_packets(self, pcap_file):
        """Update with new packets."""
        self._pcap_file = pcap_file
        self._extract_btn.set_sensitive(pcap_file.packets is not None)
        if not pcap_file.packets:
            self._file_store.remove_all()
            self._extracted_files.clear()
            self._status_label.set_text(_("No files extracted yet"))
            self._save_all_btn.set_sensitive(False)