#!/bin/bash
# Check prerequisites for running Clone's e2e test suite.
#
# Usage:  ./check_prereqs.sh
#         KERNEL=/path/to/vmlinuz ./check_prereqs.sh
#
# Exit 0 if all required checks pass, 1 if any failed.

set -uo pipefail

KERNEL="${KERNEL:-/boot/vmlinuz-$(uname -r)}"

total_ok=0
total_fail=0
total_warn=0

ok()   { printf '[ OK ] %s\n'         "$1"; total_ok=$((total_ok+1));   }
fail() { printf '[FAIL] %s — %s\n'    "$1" "$2"; total_fail=$((total_fail+1)); }
warn() { printf '[WARN] %s — %s\n'    "$1" "$2"; total_warn=$((total_warn+1)); }

# ── Host kernel and virt ──────────────────────────────────────────────────
check_host_kernel() {
    local v major minor
    v=$(uname -r)
    major=$(echo "$v" | cut -d. -f1)
    minor=$(echo "$v" | cut -d. -f2)
    if [ "$major" -gt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -ge 5 ]; }; then
        ok "host kernel $v (>= 6.5)"
    else
        fail "host kernel $v" "need 6.5+"
    fi
}

check_kvm() {
    if [ ! -c /dev/kvm ]; then
        fail "/dev/kvm" "missing (KVM disabled or virt off in BIOS)"
    elif [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        fail "/dev/kvm" "no rw access (run as root or join kvm group)"
    else
        ok "/dev/kvm rw"
    fi
}

check_root() {
    if [ "$(id -u)" -eq 0 ]; then
        ok "root"
    else
        fail "root" "tests need it for KVM, network, cgroups"
    fi
}

# ── Required commands ─────────────────────────────────────────────────────
check_cmd() {
    local cmd=$1 reason=$2
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd"
    else
        fail "$cmd" "$reason"
    fi
}

# ── busybox is statically linked ──────────────────────────────────────────
check_busybox_static() {
    local bb linkage="unknown"
    bb="${BUSYBOX:-$(command -v busybox 2>/dev/null || true)}"
    if [ -z "$bb" ] || [ ! -x "$bb" ]; then
        return  # already counted by check_cmd busybox
    fi

    if command -v file >/dev/null 2>&1; then
        case "$(file "$bb" 2>/dev/null)" in
            *"statically linked"*)  linkage="static"  ;;
            *"dynamically linked"*) linkage="dynamic" ;;
        esac
    fi
    if [ "$linkage" = "unknown" ] && command -v ldd >/dev/null 2>&1; then
        if ldd "$bb" 2>&1 | grep -q 'not a dynamic executable'; then
            linkage="static"
        else
            linkage="dynamic"
        fi
    fi

    case "$linkage" in
        static)  ok "busybox: static" ;;
        dynamic) fail "busybox: dynamic" "need static build (PID 1 in initrd)" ;;
        *)       warn "busybox linkage" "install file/ldd to verify" ;;
    esac
}

# ── Guest kernel has virtio built in ──────────────────────────────────────
check_guest_kernel_virtio() {
    if [ ! -f "$KERNEL" ]; then
        warn "guest kernel" "$KERNEL not found"
        return
    fi

    local kver config reader=cat
    kver=$(basename "$KERNEL" | sed -n 's/^vmlinuz-//p')
    if [ -z "$kver" ]; then
        warn "guest kernel" "non-standard name, can't find config"
        return
    fi

    config="/boot/config-${kver}"
    if [ ! -f "$config" ]; then
        if [ "$kver" = "$(uname -r)" ] && [ -f /proc/config.gz ]; then
            config=/proc/config.gz
            reader=zcat
        else
            warn "guest kernel virtio" "$config not found"
            return
        fi
    fi

    local mmio blk cmdline ext4 overlay devtmpfs vsock virtio_vsock
    mmio=$($reader         "$config" 2>/dev/null | sed -n 's/^CONFIG_VIRTIO_MMIO=//p'                  | head -1)
    blk=$($reader          "$config" 2>/dev/null | sed -n 's/^CONFIG_VIRTIO_BLK=//p'                   | head -1)
    cmdline=$($reader      "$config" 2>/dev/null | sed -n 's/^CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=//p'  | head -1)
    ext4=$($reader         "$config" 2>/dev/null | sed -n 's/^CONFIG_EXT4_FS=//p'                      | head -1)
    overlay=$($reader      "$config" 2>/dev/null | sed -n 's/^CONFIG_OVERLAY_FS=//p'                   | head -1)
    devtmpfs=$($reader     "$config" 2>/dev/null | sed -n 's/^CONFIG_DEVTMPFS=//p'                     | head -1)
    vsock=$($reader        "$config" 2>/dev/null | sed -n 's/^CONFIG_VSOCKETS=//p'                     | head -1)
    virtio_vsock=$($reader "$config" 2>/dev/null | sed -n 's/^CONFIG_VIRTIO_VSOCKETS=//p'              | head -1)

    local fail_reasons=""
    [ "$mmio"         = "y" ] || fail_reasons="${fail_reasons} VIRTIO_MMIO=${mmio:-unset}"
    [ "$blk"          = "y" ] || fail_reasons="${fail_reasons} VIRTIO_BLK=${blk:-unset}"
    [ "$cmdline"      = "y" ] || fail_reasons="${fail_reasons} VIRTIO_MMIO_CMDLINE_DEVICES=${cmdline:-unset}"
    [ "$ext4"         = "y" ] || fail_reasons="${fail_reasons} EXT4_FS=${ext4:-unset}"
    [ "$devtmpfs"     = "y" ] || fail_reasons="${fail_reasons} DEVTMPFS=${devtmpfs:-unset}"
    [ "$vsock"        = "y" ] || fail_reasons="${fail_reasons} VSOCKETS=${vsock:-unset}"
    [ "$virtio_vsock" = "y" ] || fail_reasons="${fail_reasons} VIRTIO_VSOCKETS=${virtio_vsock:-unset}"

    if [ -z "$fail_reasons" ]; then
        ok "guest kernel built-in (virtio MMIO/BLK/CMDLINE_DEVICES, EXT4, DEVTMPFS, vsock)"
    else
        fail "guest kernel" "needs =y:$fail_reasons"
    fi

    [ "$overlay" = "y" ] || warn "guest kernel OVERLAY_FS" "${overlay:-unset} (--overlay mode tests will skip)"
}

# ── clone-agent built and statically linked ──────────────────────────────
check_clone_agent() {
    # Search common locations; allow override via CLONE_AGENT env.
    local candidates=(
        "${CLONE_AGENT:-}"
        "target/x86_64-unknown-linux-musl/release/clone-agent"
        "target/release/clone-agent"
        "$(pwd)/target/x86_64-unknown-linux-musl/release/clone-agent"
    )
    local agent=""
    for c in "${candidates[@]}"; do
        [ -n "$c" ] && [ -x "$c" ] && { agent="$c"; break; }
    done

    if [ -z "$agent" ]; then
        fail "clone-agent" "not built (cargo build --release --target x86_64-unknown-linux-musl -p clone-agent)"
        return
    fi

    local linkage="unknown"
    if command -v file >/dev/null 2>&1; then
        case "$(file "$agent" 2>/dev/null)" in
            *"statically linked"*|*"static-pie linked"*) linkage="static"  ;;
            *"dynamically linked"*)                       linkage="dynamic" ;;
        esac
    fi
    if [ "$linkage" = "unknown" ] && command -v ldd >/dev/null 2>&1; then
        if ldd "$agent" 2>&1 | grep -q 'not a dynamic executable\|statically linked'; then
            linkage="static"
        else
            linkage="dynamic"
        fi
    fi

    case "$linkage" in
        static)  ok "clone-agent: static ($agent)" ;;
        dynamic) fail "clone-agent: dynamic" "rebuild with --target x86_64-unknown-linux-musl" ;;
        *)       warn "clone-agent linkage" "install file/ldd to verify" ;;
    esac
}

# ── Optional: rootfs creation tools ───────────────────────────────────────
check_rootfs_optional() {
    local cmd=$1 reason=$2
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd"
    else
        warn "$cmd" "$reason"
    fi
}

# ── Run ───────────────────────────────────────────────────────────────────
echo "Clone e2e prerequisites"
echo

echo "Host:"
check_host_kernel
check_kvm
check_root

echo
echo "Required commands:"
check_cmd busybox  "embedded as PID 1 in test initrd"
check_cmd qemu-img "QCOW2 disk image creation (qemu-utils)"
check_cmd jq       "parses control-socket JSON"
check_cmd bc       "arithmetic in test scripts"
check_cmd ps       "process inspection (procps)"
check_cmd socat    "talks to control sockets"

echo
echo "Linkage:"
check_busybox_static
check_clone_agent

echo
echo "Guest kernel ($KERNEL):"
check_guest_kernel_virtio

echo
echo "Rootfs tests (optional):"
check_rootfs_optional debootstrap "needed by test_rootfs_ubuntu"
check_rootfs_optional wget        "needed by test_rootfs_alpine"

echo
printf 'Summary: %d ok, %d failed, %d warnings\n' \
    "$total_ok" "$total_fail" "$total_warn"

[ "$total_fail" -gt 0 ] && exit 1
exit 0

