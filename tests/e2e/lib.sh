#!/bin/bash
# Shared helpers for Clone e2e tests.
set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLONE="${CLONE:-$REPO_ROOT/target/release/clone}"
E2E_DIR="$REPO_ROOT/tests/e2e"
WORK_DIR="${WORK_DIR:-/tmp/clone-e2e-$$}"
KERNEL="${KERNEL:-}"
INITRD="${INITRD:-}"
# Auto-incrementing CID for concurrent VM isolation
NEXT_CID=3

# ── Colours ───────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Counters ──────────────────────────────────────────────────────────────
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# ── Cleanup tracking ─────────────────────────────────────────────────────
declare -a CLEANUP_PIDS=()
declare -a CLEANUP_FILES=()

cleanup() {
    # Kill any VMs we started
    for pid in "${CLEANUP_PIDS[@]:-}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    # Remove temp files
    for f in "${CLEANUP_FILES[@]:-}"; do
        rm -rf "$f" 2>/dev/null || true
    done
    # Remove work dir
    rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# ── Helper: track a PID for cleanup ──────────────────────────────────────
track_pid() { CLEANUP_PIDS+=("$1"); }
track_file() { CLEANUP_FILES+=("$1"); }

# ── Pre-checks ────────────────────────────────────────────────────────────
preflight() {
    echo -e "${CYAN}=== Clone E2E Test Suite ===${NC}"
    echo ""

    # Check we're on Linux
    if [ "$(uname -s)" != "Linux" ]; then
        echo -e "${RED}FATAL: E2E tests require Linux with KVM. Current OS: $(uname -s)${NC}"
        exit 1
    fi

    # Check KVM
    if [ ! -e /dev/kvm ]; then
        echo -e "${RED}FATAL: /dev/kvm not found. Enable KVM in your kernel/BIOS.${NC}"
        exit 1
    fi

    # Check root (needed for KVM, networking, cgroups)
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}FATAL: E2E tests must run as root (sudo).${NC}"
        exit 1
    fi

    # Check clone binary
    if [ ! -x "$CLONE" ]; then
        echo -e "${YELLOW}clone binary not found at $CLONE, building...${NC}"
        (cd "$REPO_ROOT" && cargo build --release)
        if [ ! -x "$CLONE" ]; then
            echo -e "${RED}FATAL: Failed to build clone.${NC}"
            exit 1
        fi
    fi

    # Find or build a kernel
    find_kernel

    # Ensure static (musl) clone-init/clone-agent are available for rootfs tests.
    # The native (glibc) builds in target/release/ won't work inside Alpine guests.
    # Auto-build with musl target if not found.
    local musl_target="x86_64-unknown-linux-musl"
    local musl_init="$REPO_ROOT/target/$musl_target/release/clone-init"
    local musl_agent="$REPO_ROOT/target/$musl_target/release/clone-agent"

    if [ -z "${CLONE_INIT:-}" ]; then
        if [ -x "$musl_init" ]; then
            export CLONE_INIT="$musl_init"
        elif [ -x /usr/local/bin/clone-init ]; then
            export CLONE_INIT="/usr/local/bin/clone-init"
        else
            echo -e "  ${YELLOW}Building clone-init (musl static)...${NC}"
            if (cd "$REPO_ROOT" && rustup target add "$musl_target" >/dev/null 2>&1 && \
                cargo build --release -p clone-init --target "$musl_target" 2>/dev/null); then
                export CLONE_INIT="$musl_init"
                # Also copy to target/release/ so test functions find it
                cp "$musl_init" "$REPO_ROOT/target/release/clone-init"
            fi
        fi
    fi
    if [ -z "${CLONE_AGENT:-}" ]; then
        if [ -x "$musl_agent" ]; then
            export CLONE_AGENT="$musl_agent"
        elif [ -x /usr/local/bin/clone-agent ]; then
            export CLONE_AGENT="/usr/local/bin/clone-agent"
        else
            echo -e "  ${YELLOW}Building clone-agent (musl static)...${NC}"
            if (cd "$REPO_ROOT" && cargo build --release -p clone-agent --target "$musl_target" 2>/dev/null); then
                export CLONE_AGENT="$musl_agent"
                cp "$musl_agent" "$REPO_ROOT/target/release/clone-agent"
            fi
        fi
    fi

    # Build initrd
    build_initrd

    mkdir -p "$WORK_DIR"

    echo -e "  clone:  $CLONE"
    echo -e "  kernel:  $KERNEL"
    echo -e "  initrd:  $INITRD"
    echo -e "  workdir: $WORK_DIR"
    echo ""
}

# ── Find a usable kernel ─────────────────────────────────────────────────
find_kernel() {
    if [ -n "$KERNEL" ] && [ -f "$KERNEL" ]; then
        return 0
    fi

    # Look for common kernel locations
    local candidates=(
        /boot/vmlinuz-$(uname -r)
        /boot/vmlinuz
        "$REPO_ROOT/vmlinux"
        "$REPO_ROOT/bzImage"
        "$REPO_ROOT/tests/e2e/vmlinux"
        /tmp/clone-e2e-kernel
    )
    for k in "${candidates[@]}"; do
        if [ -f "$k" ]; then
            KERNEL="$k"
            return 0
        fi
    done

    # Try to extract from running kernel
    if [ -f "/boot/vmlinuz-$(uname -r)" ]; then
        KERNEL="/boot/vmlinuz-$(uname -r)"
        return 0
    fi

    echo -e "${RED}FATAL: No kernel found. Set KERNEL=/path/to/vmlinuz${NC}"
    echo "  Tried: ${candidates[*]}"
    echo "  Tip: cp /boot/vmlinuz-\$(uname -r) $REPO_ROOT/tests/e2e/vmlinux"
    exit 1
}

# ── Build minimal initrd with busybox ─────────────────────────────────────
build_initrd() {
    if [ -n "$INITRD" ] && [ -f "$INITRD" ]; then
        return 0
    fi

    INITRD="/tmp/clone-e2e-initrd-$$.img"
    track_file "$INITRD"

    local tmpdir
    tmpdir=$(mktemp -d)

    local need_sudo=false
    (
        cd "$tmpdir"
        mkdir -p bin dev proc sys tmp etc

        # Find busybox
        local bb=""
        for p in /usr/bin/busybox /bin/busybox /usr/bin/busybox-static; do
            if [ -x "$p" ]; then bb="$p"; break; fi
        done
        if [ -z "$bb" ]; then
            echo -e "${RED}FATAL: busybox not found. Install busybox-static.${NC}"
            exit 1
        fi
        cp "$bb" bin/busybox
        chmod +x bin/busybox

        # Symlink common commands
        for cmd in sh ls cat echo mount mkdir mknod sleep date hostname \
                   grep dd free ps wc head tail tee printf test expr seq \
                   dmesg uname sync poweroff reboot sed; do
            ln -sf busybox "bin/$cmd" 2>/dev/null || true
        done

        # Create device nodes needed before devtmpfs mount
        mknod dev/console c 5 1 2>/dev/null || need_sudo=true
        mknod dev/null c 1 3 2>/dev/null || true

        # Create init script — the e2e test framework injects commands via kernel cmdline
        cat > init << 'INITEOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

# Print boot marker (tests look for this)
echo "CLONE_BOOT_OK"

# Parse e2e_cmd from /proc/cmdline
E2E_CMD=$(cat /proc/cmdline | tr ' ' '\n' | grep '^e2e_cmd=' | head -1 | cut -d= -f2-)

if [ -n "$E2E_CMD" ]; then
    # URL-decode (replace + with space, %XX with chars) — simplified
    CMD=$(echo "$E2E_CMD" | sed 's/+/ /g')
    echo "E2E_EXEC: $CMD"
    eval "$CMD"
    echo "E2E_EXIT_CODE=$?"
fi

# If no e2e_cmd, check for test script on virtio-block
if [ -b /dev/vda ]; then
    mkdir -p /mnt
    mount /dev/vda /mnt 2>/dev/null && {
        if [ -x /mnt/e2e_test.sh ]; then
            echo "E2E_EXEC_SCRIPT"
            /bin/sh /mnt/e2e_test.sh
            echo "E2E_EXIT_CODE=$?"
            umount /mnt
        fi
    }
fi

echo "CLONE_TEST_DONE"

# Power off cleanly
sync
echo o > /proc/sysrq-trigger 2>/dev/null || poweroff -f
INITEOF
        chmod +x init

        find . | cpio -o -H newc 2>/dev/null | gzip > "$INITRD"
    )
    rm -rf "$tmpdir"
}

# ── Start a VM in the background, capturing serial output ─────────────────
# Usage: start_vm [extra args...]
# Sets: VM_PID, VM_SERIAL_LOG, VM_SOCKET
start_vm() {
    local serial_log="$WORK_DIR/serial-$$.log"
    local extra_args=("$@")

    # Launch clone in background, pipe serial to a file
    # stdin from /dev/null so it doesn't try to read the terminal
    # Extra args can override defaults (e.g., --vcpus 4, --mem-mb 512)
    local has_mem=false has_vcpus=false has_cmdline=false
    for arg in "${extra_args[@]}"; do
        case "$arg" in
            --mem-mb) has_mem=true ;;
            --vcpus) has_vcpus=true ;;
            --cmdline) has_cmdline=true ;;
        esac
    done

    local default_args=()
    default_args+=(--kernel "$KERNEL" --initrd "$INITRD")
    $has_mem || default_args+=(--mem-mb 256)
    $has_vcpus || default_args+=(--vcpus 1)

    # Auto-assign unique CID to avoid vsock port conflicts between tests
    local cid=$NEXT_CID
    NEXT_CID=$((NEXT_CID + 1))
    default_args+=(--cid "$cid")

    $CLONE run \
        "${default_args[@]}" \
        "${extra_args[@]}" \
        < /dev/null > "$serial_log" 2>&1 &

    VM_PID=$!
    VM_SERIAL_LOG="$serial_log"
    VM_SOCKET="/tmp/clone-${VM_PID}.sock"
    track_pid "$VM_PID"
    track_file "$serial_log"
}

# ── Wait for a string in serial output (with timeout) ─────────────────────
# Usage: wait_for_serial "PATTERN" [timeout_seconds]
wait_for_serial() {
    local pattern="$1"
    local timeout="${2:-30}"
    local deadline=$((SECONDS + timeout))

    while [ $SECONDS -lt $deadline ]; do
        if [ -f "$VM_SERIAL_LOG" ] && grep -q "$pattern" "$VM_SERIAL_LOG" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# ── Wait for control socket to appear ─────────────────────────────────────
wait_for_socket() {
    local timeout="${1:-15}"
    local deadline=$((SECONDS + timeout))

    while [ $SECONDS -lt $deadline ]; do
        if [ -S "$VM_SOCKET" ]; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# ── Send a control command and capture response ───────────────────────────
# Usage: control_cmd '{"Pause": null}'
# Sets: CTRL_RESPONSE
control_cmd() {
    local json="$1"
    local socket="${2:-$VM_SOCKET}"

    local timeout="${3:-10}"

    # Send length-prefixed JSON over Unix socket, read length-prefixed response
    CTRL_RESPONSE=$(_JSON="$json" _SOCK="$socket" _TIMEOUT="$timeout" python3 -c '
import socket, struct, sys, os
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(int(os.environ.get("_TIMEOUT", "10")))
s.connect(os.environ["_SOCK"])
payload = os.environ["_JSON"].encode()
frame = struct.pack("<I", len(payload)) + payload
s.sendall(frame)
hdr = b""
while len(hdr) < 4:
    chunk = s.recv(4 - len(hdr))
    if not chunk: break
    hdr += chunk
if len(hdr) == 4:
    resp_len = struct.unpack("<I", hdr)[0]
    resp = b""
    while len(resp) < resp_len:
        chunk = s.recv(resp_len - len(resp))
        if not chunk: break
        resp += chunk
    sys.stdout.write(resp.decode())
s.close()
' 2>/dev/null) || true
}

# ── Start a VM with --rootfs (real distro boot) ──────────────────────────
# Usage: start_vm_rootfs /path/to/rootfs.img [extra args...]
# Sets: VM_PID, VM_SERIAL_LOG, VM_SOCKET
start_vm_rootfs() {
    local rootfs_img="$1"
    shift
    local serial_log="$WORK_DIR/serial-$$.log"
    local extra_args=("$@")

    local has_mem=false
    for arg in "${extra_args[@]:-}"; do
        case "$arg" in
            --mem-mb) has_mem=true ;;
        esac
    done

    local default_args=()
    default_args+=(--kernel "$KERNEL" --rootfs "$rootfs_img")
    $has_mem || default_args+=(--mem-mb 256)

    # Auto-assign unique CID to avoid vsock port conflicts between tests
    local cid=$NEXT_CID
    NEXT_CID=$((NEXT_CID + 1))
    default_args+=(--cid "$cid")

    echo "  [start_vm_rootfs] CMD: $CLONE run ${default_args[*]} ${extra_args[*]:-}" >&2

    $CLONE run \
        "${default_args[@]}" \
        "${extra_args[@]:-}" \
        < /dev/null > "$serial_log" 2>&1 &

    VM_PID=$!
    VM_SERIAL_LOG="$serial_log"
    VM_SOCKET="/tmp/clone-${VM_PID}.sock"
    track_pid "$VM_PID"
    track_file "$serial_log"
}

# ── Stop a VM ─────────────────────────────────────────────────────────────
stop_vm() {
    local pid="${1:-$VM_PID}"
    if kill -0 "$pid" 2>/dev/null; then
        # Try graceful shutdown via control socket
        local sock="/tmp/clone-${pid}.sock"
        if [ -S "$sock" ]; then
            control_cmd '{"cmd":"shutdown"}' "$sock" 2>/dev/null || true
            # Wait up to 5s for graceful exit
            local deadline=$((SECONDS + 5))
            while [ $SECONDS -lt $deadline ] && kill -0 "$pid" 2>/dev/null; do
                sleep 0.2
            done
        fi
        # Force kill if still running
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
}

# ── Create a raw disk image with optional content ─────────────────────────
# Usage: make_raw_disk /path/to/disk.img SIZE_MB [content_script]
make_raw_disk() {
    local path="$1"
    local size_mb="$2"
    local content_script="${3:-}"

    dd if=/dev/zero of="$path" bs=1M count="$size_mb" 2>/dev/null
    if [ -n "$content_script" ]; then
        mkfs.ext4 -q -F "$path"
        local mnt_dir
        mnt_dir=$(mktemp -d)
        mount -o loop "$path" "$mnt_dir"
        # Run content script with $mnt_dir as working dir
        (cd "$mnt_dir" && eval "$content_script")
        umount "$mnt_dir"
        rmdir "$mnt_dir"
    fi
}

# ── Create a QCOW2 disk image ────────────────────────────────────────────
# Usage: make_qcow2_disk /path/to/disk.qcow2 SIZE_MB [backing_file]
make_qcow2_disk() {
    local path="$1"
    local size_mb="$2"
    local backing="${3:-}"

    if [ -n "$backing" ]; then
        qemu-img create -f qcow2 -b "$backing" -F raw "$path" "${size_mb}M"
    else
        qemu-img create -f qcow2 "$path" "${size_mb}M"
    fi
}

# ── Get RSS of a process in KB ────────────────────────────────────────────
get_rss_kb() {
    local pid="$1"
    if [ -f "/proc/$pid/status" ]; then
        grep VmRSS "/proc/$pid/status" | awk '{print $2}'
    else
        echo 0
    fi
}

# ── Get shared memory of a process in KB ──────────────────────────────────
get_shared_kb() {
    local pid="$1"
    if [ -f "/proc/$pid/smaps_rollup" ]; then
        grep Shared "/proc/$pid/smaps_rollup" | awk '{sum += $2} END {print sum}'
    elif [ -f "/proc/$pid/status" ]; then
        grep RssAnon "/proc/$pid/status" | awk '{print $2}'
    else
        echo 0
    fi
}

# ── Test result reporting ─────────────────────────────────────────────────
pass() {
    local name="$1"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "  ${GREEN}PASS${NC}  $name"
}

fail() {
    local name="$1"
    local reason="${2:-}"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "  ${RED}FAIL${NC}  $name"
    if [ -n "$reason" ]; then
        echo -e "        ${RED}→ $reason${NC}"
    fi
}

skip() {
    local name="$1"
    local reason="${2:-}"
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    echo -e "  ${YELLOW}SKIP${NC}  $name"
    if [ -n "$reason" ]; then
        echo -e "        → $reason"
    fi
}

# ── Summary ───────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${CYAN}=== Results ===${NC}"
    echo -e "  Total:   $TESTS_RUN"
    echo -e "  ${GREEN}Passed:  $TESTS_PASSED${NC}"
    if [ "$TESTS_FAILED" -gt 0 ]; then
        echo -e "  ${RED}Failed:  $TESTS_FAILED${NC}"
    fi
    if [ "$TESTS_SKIPPED" -gt 0 ]; then
        echo -e "  ${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
    fi
    echo ""
    if [ "$TESTS_FAILED" -gt 0 ]; then
        echo -e "${RED}SOME TESTS FAILED${NC}"
        return 1
    else
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        return 0
    fi
}
