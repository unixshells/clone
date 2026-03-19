# Clone

A lightweight Linux VMM built for multi-tenant shell hosting and high-density VM workloads. 19.3K lines of Rust, single binary, KVM-based.

Clone boots a template VM once, then forks isolated shells in **<20ms** via copy-on-write memory sharing. Idle VMs get reclaimed automatically. A host running 100 shells uses memory like it's running 10.

```
Template VM (Node.js warm, 512MB)
  ├── Fork → User shell 1  ─── <20ms, shares memory pages
  ├── Fork → User shell 2  ─── <20ms, CoW diverges on write
  ├── Fork → User shell 3  ─── <20ms, balloon reclaims when idle
  └── Fork → User shell N  ─── <20ms, KVM hardware isolation
```

---

## Why Clone

**The problem:** Running isolated Linux environments at scale means choosing between containers (fast but weak isolation) or VMs (strong isolation but slow and memory-hungry). Firecracker gets close but has no memory sharing, no filesystem sharing, no live migration, and no GPU passthrough.

**Clone's answer:** CoW fork from warm templates (<20ms), three-layer memory dedup (overcommit + KSM + balloon), virtio-fs for host directory sharing, pre-copy live migration, and VFIO device passthrough — all in a single binary smaller than most config files.

| | Clone (measured) | Firecracker (official) | Cloud Hypervisor (official) | QEMU |
|---|--------|-------------|------------------|------|
| **Code size** | 19.3K Rust | ~50K Rust | ~70K Rust | ~2M+ C |
| **Fork/restore** | **<20ms** (CoW) | ~5-10ms (snapshot) | stop+resume | stop+resume |
| **Cold boot (distro kernel)** | **2,217ms** | ~2-3s | ~2s | 5-20s |
| **Cold boot (minimal kernel)** | — | <=125ms ^1 | <100ms ^1 | 500ms-2s |
| **Live migration downtime** | **1ms** | **none** | yes (unpublished) | 50-300ms |
| **3 forked VMs RSS (busybox)** | **13MB** | N/A | N/A | N/A |
| **3 forked VMs RSS (Alpine)** | **13MB** | N/A | N/A | N/A |
| **10x 512MB idle VMs** | **~200MB** | ~5GB | variable | variable |
| **Incremental snapshot** | **192KB** (682x smaller) | full only | full only | full + incremental |
| **GPU passthrough** | **yes (VFIO)** | **no** | yes | yes |
| **Host dir sharing** | **yes (no daemon)** | **no** | virtiofsd | virtiofsd |

^1 With custom minimal kernels. Distro kernels: all VMMs converge to ~2-3s.

---

## Use Cases

### Unix Shell Hosting (Primary)

The original shared hosting model — many users, each with their own Linux shell — but with VM-level hardware isolation instead of chroot.

```bash
# Boot a template with your base environment
sudo clone run --kernel vmlinuz --rootfs ubuntu.img --mem-mb 512

# Snapshot it once it's warm
clone snapshot --output /templates/shell-base

# Fork shells for users in <20ms each
clone fork --template /templates/shell-base --shared-dir /home/alice:home
clone fork --template /templates/shell-base --shared-dir /home/bob:home
clone fork --template /templates/shell-base --shared-dir /home/charlie:home
# All share the same base memory pages. KVM isolates each user.
```

- **<20ms** to spin up a new user shell (no kernel boot, straight to idle)
- **~4MB additional RAM** per forked shell (measured: 3 Alpine forks = 13MB total vs 127MB template)
- **virtio-fs** mounts user home directories from the host
- **KVM hardware boundary** — not a container, real isolation
- **Balloon reclaim** — idle shells automatically give back memory
- **Live migration** — move a user's shell to another host with ~1ms downtime

### Function-as-a-Service

CoW fork from warm templates with the runtime already loaded. Sub-20ms cold start without custom kernel tuning.

```bash
# Warm template with Python + ML libs loaded
clone fork --template /templates/python-ml
# Execute function, destroy. Runtime was already warm.
```

### AI/ML Inference

Pass a GPU through via VFIO, fork a template with the model weights in memory. Every fork shares the weights (read-only CoW pages).

```bash
sudo clone run --kernel vmlinuz --rootfs ml.img \
  --passthrough 0000:01:00.0 --mem-mb 8192
```

### Dev Environments

Isolated Linux environment in <20ms with your code mounted in.

```bash
clone fork --template /templates/node20-warm \
  --shared-dir ~/projects/myapp:code
# Node.js already warm, your files at /mnt/code inside the VM
```

### CI/CD Runners

Shared base image, per-build writable overlay. Strong isolation, fast teardown.

```bash
sudo clone run --kernel vmlinuz --rootfs ubuntu-ci.img --overlay --net
# Fresh writable layer on shared read-only base. Discard on exit.
```

---

## Quick Start

```bash
# Build
cargo build --release

# Create a rootfs (defaults: ubuntu=noble, debian=bookworm, alpine=3.21)
sudo clone rootfs create --distro ubuntu --size 2G -o ubuntu.img
sudo clone rootfs create --distro ubuntu --release jammy --size 2G -o ubuntu-22.img
sudo clone rootfs create --distro alpine --size 1G -o alpine.img

# Boot a VM
sudo clone run --kernel /boot/vmlinuz-$(uname -r) --rootfs alpine.img

# With networking
sudo clone run --kernel vmlinuz --rootfs alpine.img --net --mem-mb 512

# With host directory sharing
sudo clone run --kernel vmlinuz --rootfs alpine.img \
  --shared-dir /tmp/shared:myfs
# Inside guest: mount -t virtiofs myfs /mnt

# With overlay (shared read-only base, per-VM writable layer)
sudo clone run --kernel vmlinuz --rootfs base.img --overlay

# GPU passthrough
sudo clone run --kernel vmlinuz --rootfs ml.img \
  --passthrough 0000:01:00.0 --mem-mb 8192

# Attach to a running VM's serial console (Ctrl-Q to detach)
clone attach

# Execute a command inside a running VM
clone exec -- ls /

# List all running VMs (no daemon required)
clone list --no-daemon

# Fork with full device support
sudo clone fork --template /tmp/my-template \
  --net --shared-dir /tmp/shared:myfs --block extra-disk.img
```

### Prerequisites

- Linux host with KVM (`/dev/kvm`)
- Kernel 6.5+ recommended
- For networking: `/dev/net/tun`, `/dev/vhost-net`
- For vsock: `/dev/vhost-vsock`
- For GPU passthrough: device bound to `vfio-pci` driver

---

## Features

### VM Lifecycle

| Command | What it does |
|---------|-------------|
| `clone run` | Boot a new VM from kernel + rootfs/initrd |
| `clone fork` | Fork from a template snapshot (<20ms) |
| `clone snapshot` | Snapshot a running VM for later fork |
| `clone attach` | Attach to a running VM's serial console |
| `clone exec` | Execute a command inside a running VM |
| `clone list` | List running VMs (works with or without daemon) |
| `clone migrate --live` | Pre-copy live migration to another host |
| `clone migrate-recv` | Receive a live migration |
| `clone rootfs create` | Create a bootable rootfs (Alpine, Ubuntu, Debian, Docker import) |
| `clone daemon` | Multi-VM orchestration daemon (create, fork, snapshot, destroy) |

### Devices

- **virtio-block** — raw and qcow2 disk images, thin provisioning
- **virtio-net** — TAP + vhost-net kernel data path, auto bridge/NAT setup
- **virtio-balloon** — cooperative memory reclaim with hysteresis policy
- **virtio-vsock** — host-guest communication, vhost-vsock kernel backend
- **virtio-fs** — host directory sharing via inline FUSE (no external daemon)
- **PCI bus** — ECAM config space for VFIO device passthrough
- **Serial console** — 16550A UART, bidirectional terminal I/O

### Memory Management

Three layers stacked to minimize host RAM across VMs:

1. **Overcommit** — `MAP_NORESERVE`, pages allocated on first write only
2. **KSM** — `MADV_MERGEABLE` deduplicates identical pages across all VMs
3. **Balloon** — graduated reclaim with hysteresis (idle 30s → 25%, idle 2min → 50%, idle 5min → floor)

Result: 10 idle 512MB VMs use ~200MB of host RAM, not 5GB.

VMs with >3GB RAM automatically get split memory regions around the x86 PCI MMIO hole (3-4GB). The guest sees all requested memory (e.g., 4GB VM → 3.8Gi usable, 8GB → 7.8Gi). No configuration needed — Clone handles the split transparently.

### CoW Template Fork

```
Boot template → reach idle → snapshot memory + registers
                                    ↓
              New VM = mmap(snapshot, MAP_PRIVATE)  ← <20ms
                                    ↓
              Patch entropy, MAC, clock, CID → enter guest
```

All forks share the same physical pages until they write. No kernel boot on fork. Measured: 3 forked Alpine Linux VMs use **13MB total RSS** vs 127MB for the template — ~4MB per fork of a real running distro.

### Live Migration

Pre-copy over TCP. VM keeps running while memory transfers in the background.

```
Source                              Destination
  │ send full memory (skip zeros) ──→ │
  │ send dirty pages (round 1)   ──→ │
  │ send dirty pages (round 2)   ──→ │
  │ ...converge...                    │
  │ PAUSE → send final dirty + CPU ─→│
  │         ~19ms downtime            │ RESUME
  │ shutdown                          │ running
```

### Security

- **KVM hardware isolation** — each VM is a separate address space
- **Seccomp jailer** — BPF syscall filter on VMM process (`--seccomp`)
- **Measured boot** — SHA-256 kernel hash verification before loading
- **Namespace jail** — optional full jail with chroot + capabilities (`--jail`)

### Rootfs Modes

```bash
# Mode 1: Custom initrd (everything in RAM)
clone run --kernel vmlinuz --initrd my-initrd.img

# Mode 2: Disk rootfs (persistent, read-write)
clone run --kernel vmlinuz --rootfs disk.img

# Mode 3: Shared base + overlay (multi-VM, ephemeral or persistent)
clone run --kernel vmlinuz --rootfs base.img --overlay
clone run --kernel vmlinuz --rootfs base.img --overlay /data/vm1.qcow2
```

---

## Architecture

```
src/
├── main.rs              CLI entry point
├── vmm/                 VM lifecycle, vCPU threads, MMIO bus
├── boot/                Kernel loading (bzImage/ELF), ACPI tables, page tables
├── memory/              Guest memory, overcommit, KSM, page tables, GDT
├── virtio/              Virtio devices (block, net, balloon, vsock, fs)
├── pci/                 PCI bus (ECAM), VFIO passthrough
├── migration/           Pre-copy live migration (sender, receiver, wire protocol)
├── control/             Control plane (per-VM socket + daemon for multi-VM orchestration)
├── net/                 TAP/bridge/NAT auto-setup
├── storage/             Raw + QCOW2 block backends
├── rootfs.rs            Auto-generated initrd for --rootfs mode (embeds kernel modules, agent)
└── rootfs_create.rs     `clone rootfs create` (Alpine, Ubuntu, Debian, Docker)

crates/
├── guest-agent/         In-guest vsock agent (exec, networking, balloon, heartbeat)
└── clone-init/         Minimal init for auto-generated initrd (module loading, rootfs mount, agent launch)
```

**Dependencies:** kvm-ioctls, kvm-bindings, vm-memory, libc, clap, anyhow, tracing, sha2. No libvirt, no QEMU, no forked codebases.

---

## Benchmarks

All numbers measured on bare-metal (OVH dedicated server, Intel Xeon, Ubuntu 22.04, kernel 6.5.0-35-generic).

| Metric | Value |
|--------|-------|
| CoW fork boot | **<20ms** |
| VMM overhead (cold boot) | **8.8ms** (memory 125us, irqchip 288us, devices 310us, kernel load 8.7ms) |
| Cold boot to shell (distro kernel) | **2,217ms** (best), **2,338ms** (avg of 5 runs) |
| Live migration downtime (256MB) | **1ms** |
| Incremental snapshot size | **192KB** for 512MB VM (682x smaller than full) |
| CoW memory sharing (busybox) | **3 forked VMs RSS = 13MB** vs single VM = 125MB |
| CoW memory sharing (Alpine) | **3 forked Alpine VMs RSS = 13MB** vs template = 127MB |
| Memory accounting | **126MB RSS** for 512MB configured VM (overcommit working) |
| Binary size | ~3MB |
| VMM memory overhead | ~5-10MB |

See [docs/SPEC.md](docs/SPEC.md) for detailed comparisons with Firecracker, Cloud Hypervisor, and QEMU.

---

## Test Results

**63 tests, 62 passed, 1 skipped. Full suite in ~315 seconds.**

Run on bare-metal Ubuntu 22.04, kernel 6.5.0-35-generic, 2026-03-17.

### Boot & ACPI
| Test | Result | Details |
|------|--------|---------|
| `test_boot_serial` | PASS | VM booted, printed serial marker, completed init |
| `test_boot_speed` | PASS | Cold boot in **2,218ms** (< 3,000ms target) |
| `test_boot_speed_avg` | PASS | Average **2,225ms** over 5 runs (< 3,000ms target) |
| `test_acpi_no_errors` | PASS | Zero ACPI errors in boot log |
| `test_multi_vcpu` | PASS | 4-vCPU VM booted, guest sees 4 CPUs |

### Control Plane
| Test | Result | Details |
|------|--------|---------|
| `test_control_socket` | PASS | Socket appears, status/pause/resume/shutdown all work |
| `test_pause_resume` | PASS | VM survives 6 pause/resume cycles |

### Storage
| Test | Result | Details |
|------|--------|---------|
| `test_virtio_block_rw` | PASS | VM boots with virtio-block attached |
| `test_qcow2_block` | PASS | QCOW2 disk image as block backend |
| `test_qcow2_backing_file` | PASS | QCOW2 overlay + raw backing (overlay=196KB, base=16MB untouched) |

### Snapshots & Fork
| Test | Result | Details |
|------|--------|---------|
| `test_snapshot_fork` | PASS | Snapshot created, integrity verified, forked VM running |
| `test_incremental_snapshot` | PASS | Incremental snapshot **668x smaller** (full=128MB, dirty=192KB) |
| `test_cow_memory_sharing` | PASS | 3 forked VMs RSS=**19MB** < 2x single VM=125MB |
| `test_template_integrity` | PASS | Corrupted template correctly rejected |

### Security
| Test | Result | Details |
|------|--------|---------|
| `test_seccomp_filter` | PASS | VM boots and runs cleanly under seccomp BPF |

### Devices & Sharing
| Test | Result | Details |
|------|--------|---------|
| `test_virtiofs` | PASS | virtio-fs device registered and active |
| `test_pci_bus` | PASS | VM boots with PCI enumeration active (no `pci=off`) |
| `test_vfio_passthrough` | SKIP | No PCI device bound to vfio-pci on test server |

### Migration
| Test | Result | Details |
|------|--------|---------|
| `test_live_migration` | PASS | Pre-copy migration, **1ms downtime**, source stopped, receiver running |

### Rootfs Boot (Real Distros)
| Test | Result | Details |
|------|--------|---------|
| `test_rootfs_alpine` | PASS | Alpine 3.21 boots to OpenRC login prompt |
| `test_rootfs_ubuntu` | PASS | Ubuntu 24.04 (noble) boots, clone-init hands off to init, control socket active |

### Guest Agent & Networking
| Test | Result | Details |
|------|--------|---------|
| `test_unique_cid` | PASS | 2 VMs with unique CIDs boot simultaneously |
| `test_guest_networking` | PASS | eth0 configured, gateway ICMP, DNS (UDP), TCP all working |
| `test_exec_latency` | PASS | Exec round-trip in **796ms** (< 1,000ms target) |

### Multi-VM & Memory
| Test | Result | Details |
|------|--------|---------|
| `test_concurrent_vms` | PASS | 3 VMs running simultaneously |
| `test_memory_accounting` | PASS | 512MB VM uses **126MB RSS** (overcommit working) |
| `test_balloon` | PASS | Guest kernel detects virtio-balloon, RSS=**126MB** for 512MB VM |

### CoW with Real Distros
| Test | Result | Details |
|------|--------|---------|
| `test_cow_rootfs` | PASS | Alpine template (126MB) → 3 forks total RSS=**18MB** (~6MB/fork) |

```bash
# Run all tests (requires root + KVM + kernel 6.5+)
sudo KERNEL=/path/to/vmlinuz-6.5 ./tests/e2e/run_all.sh

# Run a specific test
sudo KERNEL=/path/to/vmlinuz-6.5 ./tests/e2e/run_all.sh test_live_migration
```

---

## Building on Clone

Clone is the VM engine. Your product is what you build on top.

**What Clone handles (the hard part):**
- VM lifecycle — boot, fork, snapshot, migrate, shutdown
- Memory efficiency — CoW sharing, overcommit, KSM, balloon reclaim
- Device I/O — block, network, filesystem sharing, GPU passthrough
- Isolation — KVM hardware boundary, seccomp, measured boot
- Control plane — per-VM Unix socket API + daemon for multi-VM orchestration
- Guest networking — auto bridge/TAP/NAT/DNS, per-VM IP allocation

**What you build for your use case (the product):**

| Use Case | You Build |
|----------|-----------|
| **Shell hosting** | User auth, SSH key injection, template management, quota/billing, web terminal (websocket → serial bridge) |
| **FaaS platform** | HTTP router → fork → execute → respond → destroy, request queuing, template pool per runtime |
| **CI/CD runners** | Job scheduler, build script injection, artifact extraction, GitHub/GitLab webhook integration |
| **Dev environments** | Workspace config (which template, which dirs to mount), IDE integration, persistent overlay management |
| **ML inference** | Model loading into template, request batching, GPU scheduling across VMs, autoscaling |

The pattern is always the same:

```
1. Create templates for your workload (boot once, snapshot)
2. Fork VMs from templates on demand (<20ms)
3. Inject per-user/per-request state (dirs, env, identity)
4. Run workload
5. Destroy or migrate when done
```

Clone exposes this via CLI (`clone fork`, `clone run`) and Unix socket API. Your orchestration layer calls these and adds the business logic.

---

## Status

**19,371 lines of Rust. 63 e2e tests (62 pass, 1 skip). Single binary.**

Working: full VM boot (up to 64GB RAM), 5 virtio devices, PCI/VFIO passthrough, CoW fork (<20ms), live migration (1ms downtime), snapshots (full + incremental), memory overcommit + KSM + balloon, split memory regions (MMIO hole handling for >3GB VMs), virtio-fs, overlay mode (tmpfs + block), rootfs creation (Alpine, Ubuntu, Debian, Docker import) with `--release` flag, compressed kernel module support (.ko.zst, .ko.xz), seccomp, measured boot, multi-vCPU SMP, guest agent with remote exec, guest networking (auto bridge/TAP/NAT/DNS), per-VM CID allocation, daemon orchestration (create/fork/snapshot/destroy), console attach, daemonless VM listing.

Needs work: MSI-X interrupt routing (stubbed), SR-IOV, vGPU/mdev, confidential VMs (TDX/SEV).

---

## License

Business Source License 1.1 (BSL). Free for personal, non-commercial, educational, and internal use. Commercial use (hosting, reselling, embedding in paid products) requires a paid license from Unix Shells Limited Company. Each version converts to Apache 2.0 four years after release. See [LICENSE](LICENSE) for full terms. Contact licensing@unixshells.com for commercial licensing.
