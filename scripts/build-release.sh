#!/bin/bash
set -euo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
output=$(realpath -m -- "${1:-.}")
version=$(sed -n 's/^__version__ = "\([^"]*\)"$/\1/p' "$root/src/pcap_viewer/__init__.py")
test -n "$version"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$output"
package="$work/package"
share="$package/usr/share"
mkdir -p "$package/"{DEBIAN,usr/bin,usr/lib/packetlens/pcap_viewer} \
    "$share/"{applications,icons/hicolor/scalable/apps,man/man1,doc/packetlens}
install -m 644 "$root"/src/pcap_viewer/*.py "$package/usr/lib/packetlens/pcap_viewer/"
python3 "$root/desktop-merge.py" "$root/data/se.danielnylander.packetlens.desktop.in" \
    "$root/po/" "$share/applications/se.danielnylander.packetlens.desktop"
install -m 644 "$root/data/icons/se.danielnylander.packetlens.svg" "$share/icons/hicolor/scalable/apps/"
gzip -n -c "$root/data/man/packetlens.1" > "$share/man/man1/packetlens.1.gz"
install -m 644 "$root/LICENSE" "$share/doc/packetlens/"
install -m 644 "$root/debian/copyright" "$share/doc/packetlens/"
for po in "$root"/po/*.po; do
    locale=$(basename "$po" .po)
    target="$share/locale/$locale/LC_MESSAGES"
    mkdir -p "$target"
    msgfmt -o "$target/packetlens.mo" "$po"
done
cat > "$package/usr/bin/packetlens" <<'PY'
#!/usr/bin/python3
import sys

sys.path.insert(0, "/usr/lib/packetlens")
from pcap_viewer.main import main

raise SystemExit(main())
PY
chmod 755 "$package/usr/bin/packetlens"
ln -s packetlens "$package/usr/bin/pcap-viewer"
cat > "$package/DEBIAN/control" <<CONTROL
Package: packetlens
Version: $version-1
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.10), python3-gi, gir1.2-gtk-4.0 (>= 4.10), gir1.2-adw-1, python3-scapy, python3-magic
Maintainer: Daniel Nylander <daniel@danielnylander.se>
Homepage: https://github.com/yeager/pcap-viewer
Description: GTK4 network packet analyzer and PCAP viewer
 Inspect network captures and analyze DNS, HTTP and TLS traffic.
CONTROL
dpkg-deb --root-owner-group --build "$package" "$output/packetlens_${version}-1_all.deb"

cat > "$work/packetlens.spec" <<SPEC
Name: packetlens
Version: $version
Release: 1
Summary: GTK4 network packet analyzer and PCAP viewer
License: GPL-3.0-or-later
URL: https://github.com/yeager/pcap-viewer
BuildArch: noarch
Requires: python3, python3-gobject, python3-scapy, python3-magic, gtk4 >= 4.10, libadwaita

%description
Inspect network captures and analyze DNS, HTTP and TLS traffic.

%install
mkdir -p "%{buildroot}"
cp -a "$package/usr" "%{buildroot}/"

%files
/usr/bin/packetlens
/usr/bin/pcap-viewer
/usr/lib/packetlens
/usr/share/applications/se.danielnylander.packetlens.desktop
/usr/share/icons/hicolor/scalable/apps/se.danielnylander.packetlens.svg
/usr/share/man/man1/packetlens.1*
%license /usr/share/doc/packetlens/LICENSE
%doc /usr/share/doc/packetlens/copyright
/usr/share/locale/*/LC_MESSAGES/packetlens.mo
SPEC
rpmbuild -bb --nodeps --define "_topdir $work/rpmbuild" --define "_rpmdir $work/rpm" \
    --define '_rpmformat 4' --define '_binary_payload w6.xzdio' "$work/packetlens.spec"
cp "$work/rpm/noarch/packetlens-$version-1.noarch.rpm" "$output/"
