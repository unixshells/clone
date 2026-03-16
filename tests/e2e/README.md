# Clone End-to-End Tests

28 test functions, 63 assertions. Runs on a Linux host with KVM support.

## Prerequisites

```bash
# Requirements:
# - Linux kernel 6.5+ with KVM enabled
#   (kernel 5.15 has a text corruption bug — do NOT use it)
# - Root access (for KVM, networking, cgroups)
# - busybox-static, qemu-utils, jq, bc, procps
# - For rootfs tests: debootstrap (Ubuntu), wget (Alpine)

sudo apt-get install -y busybox-static qemu-utils jq bc procps debootstrap

# Build Clone + guest components
cargo build --release
cargo build --release -p clone-init --target x86_64-unknown-linux-musl
cargo build --release -p clone-agent --target x86_64-unknown-linux-musl
```

## Running Tests

```bash
# Run all tests (requires root + KVM + kernel 6.5+)
sudo ./tests/e2e/run_all.sh

# Run a specific test
sudo ./tests/e2e/run_all.sh test_boot_serial

# Run multiple specific tests
sudo ./tests/e2e/run_all.sh test_guest_networking test_exec_latency

# Via Makefile (auto-builds first)
make e2e
make e2e-quick
make e2e-snapshot
```

The test suite auto-detects the kernel from `/boot/vmlinuz`. Override with `KERNEL=/path/to/vmlinuz`.

## Test Matrix

### Boot & ACPI (5 tests)

| Test | What it validates |
|------|-------------------|
| `test_boot_serial` | VM boots, kernel prints to serial, init completes |
| `test_boot_speed` | Cold boot under 3,000ms (measured: ~2,218ms) |
| `test_boot_speed_avg` | Average of 5 cold boots under 3,000ms (measured: ~2,225ms) |
| `test_acpi_no_errors` | Zero ACPI errors in kernel boot log |
| `test_multi_vcpu` | 4-vCPU VM boots, guest sees all 4 CPUs |

### Control Plane (2 tests)

| Test | What it validates |
|------|-------------------|
| `test_control_socket` | Unix socket appears, status/pause/resume/shutdown commands work |
| `test_pause_resume` | VM survives 6 rapid pause/resume cycles |

### Storage (3 tests)

| Test | What it validates |
|------|-------------------|
| `test_virtio_block_rw` | VM boots with virtio-block disk attached |
| `test_qcow2_block` | QCOW2 disk image works as virtio-block backend |
| `test_qcow2_backing_file` | QCOW2 overlay + raw backing file, overlay stays small |

### Snapshots & Fork (4 tests)

| Test | What it validates |
|------|-------------------|
| `test_snapshot_fork` | Snapshot created, integrity verified, forked VM runs |
| `test_incremental_snapshot` | Incremental snapshot 668x smaller than full (128MB → 192KB) |
| `test_cow_memory_sharing` | 3 forked VMs total RSS (19MB) < 2x single VM (125MB) |
| `test_template_integrity` | Corrupted template correctly rejected on load |

### Security (1 test)

| Test | What it validates |
|------|-------------------|
| `test_seccomp_filter` | VM boots and runs cleanly under seccomp BPF jail |

### Devices & Sharing (3 tests)

| Test | What it validates |
|------|-------------------|
| `test_virtiofs` | virtio-fs device registers, host dir shared into guest |
| `test_pci_bus` | VM boots with PCI enumeration active (no `pci=off`) |
| `test_vfio_passthrough` | VFIO device visible in guest (skips if no vfio-pci device) |

### Migration (1 test)

| Test | What it validates |
|------|-------------------|
| `test_live_migration` | Pre-copy migration completes, 1ms downtime, receiver running |

### Rootfs Boot (2 tests)

| Test | What it validates |
|------|-------------------|
| `test_rootfs_alpine` | Alpine rootfs created (3.21), boots to OpenRC login prompt |
| `test_rootfs_ubuntu` | Ubuntu rootfs created (noble/24.04), boots, clone-init hands off to real init |

### Guest Agent & Networking (3 tests)

| Test | What it validates |
|------|-------------------|
| `test_unique_cid` | 2 VMs with unique vsock CIDs boot simultaneously |
| `test_guest_networking` | eth0 configured, gateway ICMP, DNS (UDP), TCP connectivity |
| `test_exec_latency` | Exec round-trip < 1,000ms (measured: ~796ms) |

### Multi-VM & Memory (3 tests)

| Test | What it validates |
|------|-------------------|
| `test_concurrent_vms` | 3 VMs boot and run simultaneously |
| `test_memory_accounting` | 512MB VM uses 126MB RSS (overcommit working) |
| `test_balloon` | Guest kernel detects virtio-balloon, RSS < configured memory |

### CoW with Real Distros (1 test)

| Test | What it validates |
|------|-------------------|
| `test_cow_rootfs` | Alpine template snapshot → 3 forks, total RSS < 2x single (CoW works with real distro) |

## Latest Results

Run on bare-metal OVH server, Ubuntu 22.04, kernel 6.5.0-35-generic, 2026-03-17:

```
Total:   63
Passed:  62
Skipped: 1  (test_vfio_passthrough — no spare PCI device on server)
Elapsed: ~315s
```

## Files

| File | Purpose |
|------|---------|
| `run_all.sh` | All 28 test functions + test runner harness |
| `lib.sh` | Shared helpers: VM launch, control socket I/O, cleanup, CID management |
| `debug_incr.py` | Debug tool for incremental snapshot analysis |
