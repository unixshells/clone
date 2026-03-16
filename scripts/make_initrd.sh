#!/bin/bash
# Build a minimal initrd with busybox for Clone testing.
#
# Usage:
#   ./scripts/make_initrd.sh [output_path]
#
# Default output: /tmp/clone-initrd.img
set -e

OUTPUT="${1:-/tmp/clone-initrd.img}"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

cd "$WORKDIR"

mkdir -p bin dev proc sys etc tmp

# Get static busybox -- try several methods
if [ -f /usr/bin/busybox ]; then
    cp /usr/bin/busybox bin/busybox
elif [ -f /bin/busybox ]; then
    cp /bin/busybox bin/busybox
else
    # Try to install via package manager
    if command -v apt-get &>/dev/null; then
        sudo apt-get install -y busybox-static
        cp /usr/bin/busybox bin/busybox || cp /bin/busybox bin/busybox
    elif command -v yum &>/dev/null; then
        sudo yum install -y busybox
        cp /usr/sbin/busybox bin/busybox || cp /usr/bin/busybox bin/busybox
    elif command -v apk &>/dev/null; then
        sudo apk add busybox-static
        cp /usr/bin/busybox.static bin/busybox || cp /bin/busybox bin/busybox
    else
        echo "ERROR: Cannot find or install busybox. Please install busybox-static."
        exit 1
    fi
fi

chmod +x bin/busybox

# Create symlinks for common commands
for cmd in sh ls cat echo mount mkdir mknod ps kill sleep date hostname \
           grep sed awk vi top free df du uname id whoami pwd \
           ifconfig ip ping wget tar gzip gunzip dmesg; do
    ln -sf busybox "bin/$cmd" 2>/dev/null || true
done

# Create init script
cat > init << 'INITEOF'
#!/bin/busybox sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

# Set hostname
hostname clone

echo "============================================"
echo "  Clone Shell Ready"
echo "  Kernel: $(uname -r)"
echo "  Memory: $(free -m 2>/dev/null | grep Mem | awk '{print $2}')MB"
echo "============================================"

# Start shell
exec /bin/sh
INITEOF
chmod +x init

# Create the initrd (cpio archive, gzipped)
find . | cpio -o -H newc 2>/dev/null | gzip > "$OUTPUT"

echo "Initrd created: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
