"""File extraction from network captures."""

import gettext
import os
import tempfile
import magic
import base64
import binascii
from collections import defaultdict
from io import BytesIO

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gtk, Adw, Gio, GObject, Pango, GdkPixbuf, GLib

from scapy.all import TCP, UDP, Raw, IP

from .pcap_parser import get_protocol_name

_ = gettext.gettext

# Image MIME types we can preview
IMAGE_MIME_TYPES = {
    'image/png', 'image/jpeg', 'image/gif', 'image/bmp', 
    'image/svg+xml', 'image/webp', 'image/tiff'
}

# Text MIME types we can preview  
TEXT_MIME_TYPES = {
    'text/plain', 'text/html', 'text/xml', 'text/css', 
    'text/javascript', 'application/json', 'application/xml'
}


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
        self._thumbnail = None
        self._is_previewable = self._check_previewable()

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

    @GObject.Property(type=bool, default=False)
    def is_previewable(self):
        return self._is_previewable

    @property
    def data(self):
        return self._data

    @property
    def thumbnail(self):
        if self._thumbnail is None and self.is_image():
            self._thumbnail = self._create_thumbnail()
        return self._thumbnail

    def is_image(self):
        """Check if file is an image."""
        return self._mime_type in IMAGE_MIME_TYPES

    def is_text(self):
        """Check if file is text."""
        return self._mime_type in TEXT_MIME_TYPES

    def _check_previewable(self):
        """Check if file can be previewed."""
        return self.is_image() or self.is_text()

    def _create_thumbnail(self):
        """Create a thumbnail pixbuf from image data."""
        if not self.is_image() or not self._data:
            return None
            
        try:
            # Create input stream from data
            stream = Gio.MemoryInputStream.new_from_data(self._data)
            
            # Load pixbuf from stream
            pixbuf = GdkPixbuf.Pixbuf.new_from_stream(stream, None)
            if pixbuf:
                # Scale to thumbnail size (48x48 max, preserve aspect ratio)
                width = pixbuf.get_width()
                height = pixbuf.get_height()
                
                if width > height:
                    new_width = min(48, width)
                    new_height = int(height * new_width / width)
                else:
                    new_height = min(48, height)
                    new_width = int(width * new_height / height)
                
                thumbnail = pixbuf.scale_simple(new_width, new_height, GdkPixbuf.InterpType.BILINEAR)
                return thumbnail
        except Exception as e:
            print(f"Error creating thumbnail: {e}")
            
        return None


class FilePreviewDialog(Adw.Window):
    """Dialog for previewing extracted files."""

    def __init__(self, file_obj, parent=None):
        super().__init__(transient_for=parent)
        self._file_obj = file_obj
        self.set_title(f"{_('Preview')} - {file_obj.filename}")
        self.set_default_size(600, 500)
        self.set_modal(True)

        self._build_ui()

    def _build_ui(self):
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Header bar
        header = Adw.HeaderBar()
        
        # Save button
        save_btn = Gtk.Button(label=_("Save"))
        save_btn.add_css_class("suggested-action")
        save_btn.connect("clicked", self._on_save_clicked)
        header.pack_end(save_btn)
        
        main_box.append(header)

        # Content area
        if self._file_obj.is_image():
            content = self._create_image_preview()
        elif self._file_obj.is_text():
            content = self._create_text_preview()
        else:
            content = self._create_generic_preview()

        main_box.append(content)
        self.set_content(main_box)

    def _create_image_preview(self):
        """Create image preview with metadata."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)

        try:
            # Create input stream from data
            stream = Gio.MemoryInputStream.new_from_data(self._file_obj.data)
            
            # Load pixbuf from stream
            pixbuf = GdkPixbuf.Pixbuf.new_from_stream(stream, None)
            
            if pixbuf:
                # Image display
                picture = Gtk.Picture.new_for_pixbuf(pixbuf)
                picture.set_can_shrink(True)
                picture.set_content_fit(Gtk.ContentFit.CONTAIN)
                picture.set_vexpand(True)
                
                scroll = Gtk.ScrolledWindow()
                scroll.set_child(picture)
                scroll.set_vexpand(True)
                box.append(scroll)

                # Metadata
                meta_frame = Gtk.Frame()
                meta_frame.set_label(_("Image Information"))
                
                meta_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
                meta_box.set_margin_top(12)
                meta_box.set_margin_bottom(12)
                meta_box.set_margin_start(12)
                meta_box.set_margin_end(12)
                
                # Image dimensions and info
                width = pixbuf.get_width()
                height = pixbuf.get_height()
                
                info_labels = [
                    f"{_('Filename')}: {self._file_obj.filename}",
                    f"{_('Dimensions')}: {width} × {height} pixels",
                    f"{_('Format')}: {self._file_obj.mime_type}",
                    f"{_('File Size')}: {self._format_size(self._file_obj.size)}",
                    f"{_('Protocol')}: {self._file_obj.protocol}"
                ]
                
                for info in info_labels:
                    label = Gtk.Label(label=info)
                    label.set_halign(Gtk.Align.START)
                    meta_box.append(label)
                
                meta_frame.set_child(meta_box)
                box.append(meta_frame)
            else:
                # Failed to load image
                error_label = Gtk.Label(label=_("Failed to load image"))
                error_label.add_css_class("error")
                box.append(error_label)
                
        except Exception as e:
            error_label = Gtk.Label(label=f"{_('Error loading image')}: {str(e)}")
            error_label.add_css_class("error")
            box.append(error_label)

        return box

    def _create_text_preview(self):
        """Create text preview."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)

        # File info
        info_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        info_labels = [
            f"{_('Filename')}: {self._file_obj.filename}",
            f"{_('Type')}: {self._file_obj.mime_type}",
            f"{_('Size')}: {self._format_size(self._file_obj.size)}"
        ]
        
        for info in info_labels:
            label = Gtk.Label(label=info)
            label.add_css_class("dim-label")
            info_box.append(label)
        
        box.append(info_box)

        # Text content
        text_view = Gtk.TextView()
        text_view.set_editable(False)
        text_view.set_cursor_visible(False)
        text_view.set_monospace(True)
        text_view.add_css_class("text-preview")

        try:
            # Try to decode text
            if isinstance(self._file_obj.data, bytes):
                text_content = self._file_obj.data.decode('utf-8', errors='replace')
            else:
                text_content = str(self._file_obj.data)
            
            # Limit preview size for performance
            if len(text_content) > 10000:
                text_content = text_content[:10000] + f"\n\n[... {_('truncated')} ...]"
            
            buf = text_view.get_buffer()
            buf.set_text(text_content)
            
        except Exception as e:
            buf = text_view.get_buffer()
            buf.set_text(f"{_('Error decoding text')}: {str(e)}")

        scroll = Gtk.ScrolledWindow()
        scroll.set_child(text_view)
        scroll.set_vexpand(True)
        scroll.set_min_content_height(300)
        box.append(scroll)

        return box

    def _create_generic_preview(self):
        """Create preview for non-previewable files."""
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)

        # File icon (generic)
        icon = Gtk.Image.new_from_icon_name("text-x-generic-symbolic")
        icon.set_pixel_size(64)
        box.append(icon)

        # File info
        info_labels = [
            f"{_('Filename')}: {self._file_obj.filename}",
            f"{_('Type')}: {self._file_obj.mime_type}",
            f"{_('Size')}: {self._format_size(self._file_obj.size)}",
            f"{_('Protocol')}: {self._file_obj.protocol}"
        ]
        
        for info in info_labels:
            label = Gtk.Label(label=info)
            label.set_halign(Gtk.Align.START)
            box.append(label)

        # Note about preview
        note_label = Gtk.Label(label=_("This file type cannot be previewed"))
        note_label.add_css_class("dim-label")
        box.append(note_label)

        return box

    def _format_size(self, size):
        """Format file size in human-readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _on_save_clicked(self, btn):
        """Handle save button click."""
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Save File As"))
        dialog.set_initial_name(self._file_obj.filename)
        dialog.save(self, None, self._on_save_file_selected)

    def _on_save_file_selected(self, dialog, result):
        try:
            file_gio = dialog.save_finish(result)
            if file_gio:
                with open(file_gio.get_path(), 'wb') as f:
                    f.write(self._file_obj.data)
        except Exception as e:
            print(f"Error saving file: {e}")


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
        self._selection = selection

        self._column_view = Gtk.ColumnView(model=selection)
        self._column_view.add_css_class("data-table")

        # Add thumbnail column
        thumb_factory = Gtk.SignalListItemFactory()
        thumb_factory.connect("setup", self._on_thumbnail_setup)
        thumb_factory.connect("bind", self._on_thumbnail_bind)
        thumb_col = Gtk.ColumnViewColumn(title="", factory=thumb_factory)
        thumb_col.set_fixed_width(60)
        thumb_col.set_resizable(False)
        self._column_view.append_column(thumb_col)

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

        # Add double-click gesture for previewing
        click_gesture = Gtk.GestureClick()
        click_gesture.connect("released", self._on_row_double_clicked)
        self._column_view.add_controller(click_gesture)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_child(self._column_view)
        self.append(scroll)

        # Action buttons for individual files
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        btn_box.set_halign(Gtk.Align.END)

        self._preview_btn = Gtk.Button(label=_("Preview"))
        self._preview_btn.set_sensitive(False)
        self._preview_btn.connect("clicked", self._on_preview_clicked)
        btn_box.append(self._preview_btn)

        self._save_btn = Gtk.Button(label=_("Save Selected"))
        self._save_btn.set_sensitive(False)
        self._save_btn.connect("clicked", self._on_save_selected_clicked)
        btn_box.append(self._save_btn)

        self.append(btn_box)

    def _on_thumbnail_setup(self, factory, list_item):
        """Setup thumbnail column items."""
        image = Gtk.Image()
        image.set_pixel_size(48)
        list_item.set_child(image)

    def _on_thumbnail_bind(self, factory, list_item):
        """Bind thumbnail data to column items."""
        item = list_item.get_item()
        image = list_item.get_child()
        
        if item.is_image() and item.thumbnail:
            image.set_from_pixbuf(item.thumbnail)
            image.set_tooltip_text(_("Image preview available"))
        elif item.is_text():
            image.set_from_icon_name("text-x-generic-symbolic")
            image.set_tooltip_text(_("Text preview available"))
        elif item.is_previewable:
            image.set_from_icon_name("document-properties-symbolic")
            image.set_tooltip_text(_("Preview available"))
        else:
            image.set_from_icon_name("application-x-executable-symbolic")
            image.set_tooltip_text(_("Binary file"))

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
        self._preview_btn.set_sensitive(item is not None and item.is_previewable if item else False)

    def _on_row_double_clicked(self, gesture, n_press, x, y):
        """Handle double-click on file list row."""
        if n_press == 2:  # Double click
            item = self._selection.get_selected_item()
            if item and item.is_previewable:
                self._on_preview_clicked(None)

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

    def _on_preview_clicked(self, btn):
        """Preview selected file."""
        item = self._selection.get_selected_item()
        if item and item.is_previewable:
            # Find the parent window
            parent = self
            while parent and not isinstance(parent, Gtk.Window):
                parent = parent.get_parent()
            
            preview_dialog = FilePreviewDialog(item, parent)
            preview_dialog.present()

    def _on_save_selected_clicked(self, btn):
        """Save selected file."""
        item = self._selection.get_selected_item()
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
            self._preview_btn.set_sensitive(False)
            self._save_btn.set_sensitive(False)