# PacketLens Testing Guide

## Remote Testing on burken (192.168.2.188)

### Prerequisites
- SSH access to burken with user `yeager`
- Ubuntu system with X11/Xvnc running
- Python 3.x with scapy, GTK4, and Adwaita installed

### Step 1: Transfer and Install Package

```bash
# From development machine:
PW=$(security find-generic-password -s ssh-burken -w)
sshpass -p "$PW" scp /tmp/packetlens_0.2.0_all.deb yeager@192.168.2.188:/tmp/

# On burken:
sudo dpkg -i /tmp/packetlens_0.2.0_all.deb
sudo dpkg -r pcap-viewer  # Remove old version if present
```

### Step 2: Run Testing Script

Copy the testing script to burken and execute:
```bash
# Transfer script
scp /tmp/packetlens-test-script.sh yeager@192.168.2.188:/tmp/
ssh yeager@192.168.2.188 'chmod +x /tmp/packetlens-test-script.sh && /tmp/packetlens-test-script.sh'
```

### Step 3: Collect Screenshots

The script automatically generates these screenshots in English (LANG=en_US.UTF-8):

- `packetlens-packets.png` - Main packet list view
- `packetlens-conversations.png` - Conversations tab  
- `packetlens-protocol-stats.png` - Protocol Statistics tab
- `packetlens-dns.png` - DNS Analysis tab
- `packetlens-http.png` - HTTP Analysis tab  
- `packetlens-tls.png` - TLS Analysis tab
- `packetlens-files.png` - File Extraction tab
- `packetlens-timeline.png` - Timeline tab

### Step 4: Copy Screenshots Back

```bash
PW=$(security find-generic-password -s ssh-burken -w)
sshpass -p "$PW" scp yeager@192.168.2.188:/tmp/packetlens-*.png /Users/bosse/.openclaw/workspace/screenshots/
sshpass -p "$PW" scp yeager@192.168.2.188:/tmp/packetlens-*.png /Users/bosse/.openclaw/workspace/pcap-viewer/data/screenshots/
```

### Manual Testing Commands

If the automated script fails, use these manual commands on burken:

```bash
# Set up environment  
export DISPLAY=:1 GDK_BACKEND=x11 GSK_RENDERER=cairo LANG=en_US.UTF-8

# Create test pcap (see script for full version)
python3 -c "from scapy.all import *; wrpcap('/tmp/test.pcap', [IP(dst='8.8.8.8')/UDP(dport=53)/DNS(qd=DNSQR(qname='test.com'))])"

# Launch and screenshot each tab
for tab in packets conversations protocol-stats dns http tls files timeline; do
    echo "Testing tab: $tab"
    dbus-run-session -- bash -c "
        packetlens /tmp/test_traffic.pcap &
        PID=\$!
        sleep 4
        import -window root /tmp/packetlens-$tab.png
        kill \$PID
        wait \$PID 2>/dev/null
    "
done
```

## Expected Test Results

### Installation Verification
- ✅ `packetlens` binary installed in `/usr/bin/`
- ✅ `pcap-viewer` symlink points to `packetlens`  
- ✅ Desktop file installed: `/usr/share/applications/se.danielnylander.packetlens.desktop`
- ✅ Icon installed: `/usr/share/icons/hicolor/scalable/apps/se.danielnylander.packetlens.svg`
- ✅ Swedish translation: `/usr/share/locale/sv/LC_MESSAGES/packetlens.mo`

### Module Import Tests
- ✅ `from pcap_viewer.main import main` - Main application
- ✅ `from pcap_viewer import file_extractor` - File extraction module
- ✅ `from pcap_viewer import conversations` - Conversation analysis
- ✅ `from pcap_viewer import protocol_stats` - Protocol statistics
- ✅ `from pcap_viewer import dns_analyzer` - DNS analysis  
- ✅ `from pcap_viewer import tls_analyzer` - TLS analysis
- ✅ `from pcap_viewer import http_analyzer` - HTTP analysis
- ✅ `from pcap_viewer import timeline` - Timeline view

### GUI Tests
- ✅ Application launches without errors
- ✅ Window title shows "PacketLens"
- ✅ All 8 tabs are accessible
- ✅ Test PCAP loads successfully
- ✅ Packet list populates with data
- ✅ Tab switching works smoothly
- ✅ Screenshots generated for all views

### Package Metadata
- ✅ Package name: `packetlens` (replaces/conflicts with `pcap-viewer`)
- ✅ Version: 0.2.0  
- ✅ Description: "PacketLens — GTK4 network capture analyzer..."
- ✅ Dependencies properly listed
- ✅ Files installed in correct locations

## Troubleshooting

### Common Issues
1. **Missing dependencies**: Install `python3-scapy python3-gi gir1.2-adw-1 gir1.2-gtk-4.0`
2. **Display issues**: Ensure `DISPLAY=:1` and Xvnc is running  
3. **Import errors**: Check Python path and module installation
4. **Screenshot failures**: Try `scrot` instead of `import` command

### SSH Connection Issues
If SSH to burken fails:
1. Verify burken is powered on and network accessible
2. Check if password in keychain is current
3. Try manual SSH with password prompt
4. Verify SSH service is running on burken

## Completion Checklist

- [ ] SSH connection to burken established
- [ ] .deb package successfully installed  
- [ ] All module imports working
- [ ] Test PCAP file generated with diverse traffic
- [ ] Screenshots captured for all 8 tabs in English
- [ ] Screenshots copied to local directories
- [ ] README.md updated with screenshot references
- [ ] All changes committed to git
- [ ] Testing results documented