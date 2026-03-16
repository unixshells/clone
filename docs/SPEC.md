# Clone — Technical Specification
**Lightweight Linux VMM — Fast VMs with Efficient Resource Sharing**

---

## Problem

Running lightweight Linux VMs shouldn't require QEMU's 2M+ lines of code or Firecracker's opinionated serverless assumptions. Whether you're running a persistent dev shell, spinning up dozens of isolated environments, or firing off lambda-style function invocations — you need a VMM that boots fast, shares resources efficiently across VMs, and gets out of the way.

---

## Goals

- **< 20ms VM cold start** via CoW template fork (vs. ~125ms Firecracker, ~2s full kernel boot)
- **~20-40MB effective RAM per idle VM** via overcommit + KSM + balloon reclaim
- **Full Linux compatibility** — Docker-in-VM, debuggers, arbitrary binaries, real root
- **Strong isolation** — KVM hardware boundary, not a container
- **Unified model** for both long-lived dev shells and short-lived lambda-style functions
- **Simple CLI** — `clone run`, `clone fork`, no configuration files required

---

## Architecture

### 1. VMM Core

A minimal VMM written in Rust, using KVM directly. No forked codebases, no framework overhead.

**Components:**
- `kvm-ioctls` / `kvm-bindings` — KVM API surface, vCPU management
- Custom guest memory with overcommit support (`MAP_NORESERVE`)
- Custom virtio queue implementation (virtio spec 2.6-2.7)
- Direct kernel loading (bzImage + ELF) with initrd support
- In-kernel irqchip (LAPIC + IOAPIC) and PIT
- ACPI tables (RSDP, XSDT, MADT, MCFG) for proper hardware discovery
- ACPI PM registers at I/O 0x600 for kernel compatibility
- PCI bus with ECAM config space for device passthrough

**Virtio devices (all MMIO transport, virtio 1.0+):**
- `virtio-balloon` — cooperative memory reclaim via inflate/deflate
- `virtio-block` — disk I/O, raw and qcow2 formats, thin provisioning
- `virtio-net` — networking via TAP device, vhost-net kernel data path
- `virtio-vsock` — host↔guest communication channel, vhost-vsock kernel backend
- `virtio-fs` — host directory sharing via inline FUSE protocol (20 opcodes)

**Also included:**
- 16550A serial console (COM1) — bidirectional terminal I/O with interrupt-driven TX
- Signal handling — clean shutdown on SIGTERM/SIGINT, proper fd cleanup
- Measured boot — SHA-256 kernel hash verification before loading
- Seccomp jailer — BPF syscall filter on VMM process
- Boot timing instrumentation (VMM overhead ~10ms)
- Full-memory page tables (up to 64GB via 2MB pages)

**Also supports:** PCI bus (ECAM), VFIO device passthrough, pre-copy live migration.

### 2. Kernel Loading

- Supports both bzImage and raw ELF kernel formats
- Loads initrd into guest memory with proper boot params
- E820 memory map generated and passed to kernel
- Kernel command line configurable via CLI
- Boot params (zero page) populated per Linux boot protocol
- Optional hash verification (measured boot) before loading

### 3. Rootfs

Three boot modes, from most manual to most automated:

**Mode 1: Custom initrd (`--initrd`)**
- User provides their own initrd image
- Full control — whatever init system, whatever tools
- Everything runs from RAM (tmpfs) unless a block device is also attached
- Good for custom/embedded use cases

**Mode 2: Own rootfs (`--rootfs disk.img`)**
- User provides a disk image (raw or qcow2) containing a full root filesystem
- Clone generates a tiny initrd automatically that mounts the disk and pivot_roots into it
- Disk is attached read-write — user has full ownership, changes persist
- Good for persistent dev shells, long-lived VMs

**Mode 3: Shared base + overlay (`--rootfs base.img --overlay`)**
- Base image is opened **read-only** — safe to share across multiple VMs
- Clone auto-creates a per-VM writable layer (qcow2 overlay or tmpfs)
- Guest sees a normal read-write filesystem, but writes go to the overlay only
- Multiple VMs share the same base image — one copy of the distro in host page cache
- Good for running many similar VMs efficiently

**Overlay strategies:**
- `--overlay tmpfs` (default) — writable layer lives in guest RAM, discarded on shutdown. Ephemeral.
- `--overlay /path/to/overlay.qcow2` — writable layer persists on disk. Can be reused across restarts.
- `--overlay auto` — Clone creates a temp qcow2 in `~/.clone/overlays/`, auto-cleaned on shutdown.

**Built-in initrd:**

For `--rootfs` modes, Clone generates a minimal initrd at boot time (no user action needed). It:
1. Mounts `/proc`, `/sys`, `/dev`
2. Probes for virtio-block devices
3. Mounts the rootfs (read-write or read-only depending on mode)
4. If overlay mode: mounts tmpfs or block overlay, sets up overlayfs (lower=rootfs, upper=overlay)
5. Loads vsock kernel modules if present in rootfs
6. Starts the guest agent if present at `/usr/bin/clone-agent`
7. `pivot_root` and `exec /sbin/init`

**Rootfs creation:**

```bash
# Create a minimal Alpine rootfs image
clone rootfs create --distro alpine --size 1G --output alpine.img

# Create an Ubuntu rootfs image
clone rootfs create --distro ubuntu --size 4G --output ubuntu.img

# Import from an existing directory or Docker export
clone rootfs create --from-dir /path/to/rootfs --size 2G --output custom.img
clone rootfs create --from-docker ubuntu:22.04 --size 4G --output ubuntu.img
```

The `rootfs create` command:
1. Creates a sparse raw disk image (thin-provisioned)
2. Formats it with ext4
3. Bootstraps the distro (Alpine: apk, Ubuntu: debootstrap)
4. Installs the guest agent
5. Configures serial console getty, basic networking
6. Result: a self-contained bootable rootfs image

### 4. Memory Management

The core differentiator. Three layers stacked to minimize physical RAM usage across VMs:

**Layer 1 — Overcommit**
- Guest RAM allocated via `mmap` with `MAP_NORESERVE` — host only commits pages on first write
- Physical pages allocated on demand, no upfront reservation
- A 512MB VM that's only using 80MB costs 80MB of host RAM
- Host OOM killer as backstop — same model as process memory on Linux

**Layer 2 — KSM (Kernel Same-page Merging)**
- `MADV_MERGEABLE` on all guest memory regions
- Host kernel scans across all VM pages, deduplicates identical ones
- 10 VMs running the same kernel + distro = ~1 physical copy of shared pages
- Passive — no guest cooperation needed, works automatically
- Amplified by shared rootfs — VMs booting from the same base image share even more

**Layer 3 — Balloon Reclaim (with Hysteresis)**

Guest agent monitors activity via vsock and reports to VMM. VMM balloon policy responds with asymmetric timing:

- **Deflate (give memory back):** immediate on activity — responsiveness is sacred
- **Inflate (reclaim memory):** graduated, slow
  - Idle 30s → reclaim 25% of reclaimable
  - Idle 2min → reclaim 50%
  - Idle 5min → reclaim to minimum floor (~20-30MB)
- **Cooldown:** after any deflate, suppress inflation for 60s
- **Burstiness tracking:** if 3+ active/idle transitions in 5 minutes, extend cooldown to 3 minutes

This prevents oscillation. Only truly idle VMs get reclaimed.

**Private page tracking:**
- `mincore()` to track resident pages per VM
- Compute effective memory = private (diverged) pages only
- Shared CoW / KSM pages not counted against individual VMs
- Useful for monitoring density and deciding when the host is overloaded

### 5. CoW Template Boot

The primary source of <20ms cold starts.

```
1. Boot a "template" VM (bare shell, Node 20, Python 3.12, etc.)
2. Let it reach idle state — runtime loaded, JIT warmed
3. Snapshot full memory + register state
4. New VM = mmap(template_snapshot, MAP_PRIVATE)
5. Pages are CoW — copied only on write
6. Patch VM-unique state (entropy, network identity, clock, CID)
7. Enter guest mode — no kernel boot, straight to idle
```

- Skips all kernel init on fork — instant resume
- Physical RAM shared across forked VMs (amplified by KSM)
- Template per runtime type, created once and reused

**Per-VM state injection before first vCPU entry:**
- **Entropy** — fresh seed to avoid shared RNG state across forks
- **Network identity** — unique MAC address, IP, vsock CID
- **Clock** — adjust TSC offset and kvmclock to current wall time
- **Identity page** — fixed-layout page in guest memory (VM ID, hostname, CID)

### 6. Networking

- **Per-VM TAP device** — created and configured automatically
- **vhost-net** — kernel handles the data path, VMM only does setup
- **Host bridge** — TAP attached to bridge for connectivity
- **Static IP injection** via guest agent — no DHCP needed
- Works with existing Linux bridge/NAT setup on the host

### 7. Storage

- **virtio-block** with read/write/flush support
- **Raw images** — direct file-backed block device
- **qcow2** — CoW format for cheap clones and thin provisioning
- **Thin provisioning** — sparse files, only written blocks consume disk
- **Multiple block devices** — rootfs + additional data disks

### 8. Host↔Guest Communication (vsock)

- **virtio-vsock** with vhost-vsock kernel backend
- Guest CID configurable (unique per VM)
- Enables host↔guest socket communication without networking
- Used by guest agent for: activity reporting, balloon coordination, identity injection, shutdown commands

### 9. Guest Agent

Small static binary (<1MB, musl-linked) running inside the guest. Communicates with VMM over vsock.

**Reports to VMM:**
- Activity state (active/idle)
- Memory pressure (PSI metrics)
- Process count and load average

**Receives from VMM:**
- Balloon commands (inflate/deflate targets)
- Shutdown/reboot signals
- Identity data on first boot (hostname, IP, CID)
- Exec commands (run arbitrary commands, return stdout/stderr/exit code)

Baked into rootfs images created by `clone rootfs create`. For custom initrd users, the agent binary is optional.

### 10. Console

- **Serial console** over 16550A UART (COM1, IRQ 4)
- Terminal set to raw mode — keystrokes forwarded immediately
- Stdin reader thread raises IRQ on input
- Works as primary console when no SSH/networking configured
- **Console socket** at `/tmp/clone-{pid}.console` — allows `clone attach` from another terminal
- **Remote exec** via `clone exec` — sends commands through control socket → guest agent over vsock

---

## CLI

```bash
# === Boot modes ===

# Initrd-only (custom, everything in RAM)
clone run --kernel vmlinuz --initrd my-initrd.img

# Own rootfs (persistent, read-write)
clone run --kernel vmlinuz --rootfs my-disk.img

# Shared rootfs with ephemeral overlay (multi-VM friendly)
clone run --kernel vmlinuz --rootfs base.img --overlay

# Shared rootfs with persistent overlay
clone run --kernel vmlinuz --rootfs base.img --overlay /data/vm1-overlay.qcow2

# Full options
clone run \
  --kernel vmlinuz \
  --rootfs base.img \
  --overlay \
  --mem-mb 1024 \
  --vcpus 2 \
  --tap tap0 \
  --cmdline "console=ttyS0"

# === Rootfs management ===

# Create a minimal Alpine rootfs
clone rootfs create --distro alpine --size 1G -o alpine.img

# Create an Ubuntu rootfs
clone rootfs create --distro ubuntu --size 4G -o ubuntu.img

# Import from a Docker image
clone rootfs create --from-docker node:20-slim --size 4G -o node20.img

# === Template fork (fast clone) ===

# Snapshot a running VM
clone snapshot --name node20-warm

# Fork from template (<20ms cold start)
clone fork --template node20-warm --cid 4 --tap tap1

# Fork with full device support (networking, shared dirs, block)
clone fork --template node20-warm \
  --net --shared-dir /tmp/shared:myfs --block extra-disk.img

# === VM interaction ===

# Attach to a running VM's serial console (Ctrl-Q to detach)
clone attach                     # auto-detect if only one VM running
clone attach --vm-id 12345       # specify by PID

# Execute a command inside a VM via guest agent
clone exec -- ls /               # auto-detect VM
clone exec --vm-id 12345 -- cat /etc/hostname

# === VM listing ===

# List VMs via daemon
clone list

# List VMs without daemon (scans /tmp/clone-*.sock)
clone list --no-daemon

# === Daemon management ===

# Start the daemon
clone daemon --socket /run/clone/control.sock

# Create a VM via daemon (full options)
clone create --kernel vmlinuz --mem-mb 1024 --vcpus 2 \
  --rootfs alpine.img --overlay --net --seccomp

# Destroy a VM via daemon
clone destroy --vm-id vm-0001

# === Live migration ===

# Migrate a running VM to another host (pre-copy, ~19ms downtime)
clone migrate --live --port 14242 --control /tmp/clone-source.sock 127.0.0.1

# Start a migration receiver
clone migrate-recv --port 14242 --kernel vmlinuz --mem-mb 512

# === PCI device passthrough ===

# Pass a GPU or NIC through to the guest via VFIO
clone run --kernel vmlinuz --rootfs disk.img --passthrough 0000:01:00.0

# === Monitoring ===

# Show running VMs and their memory usage
clone status
clone list --no-daemon    # PID, state, vCPUs, RSS for each VM
```

---

## Prerequisites

- Linux host with KVM enabled (`/dev/kvm` accessible)
- For networking: `/dev/net/tun` access, a pre-configured bridge + TAP device
- For vsock: `/dev/vhost-vsock` accessible
- For vhost-net: `/dev/vhost-net` accessible
- A Linux kernel (bzImage)
- For `rootfs create --distro`: `debootstrap` (Ubuntu) or `apk` (Alpine) on host

---

## Current Status

**~19.3K lines of Rust. 25 e2e tests / 56 assertions (55 pass, 1 skip). Single binary, zero runtime dependencies beyond Linux + KVM.**

### Working
- Full VM boot to interactive shell via serial console
- virtio-balloon (inflate/deflate with MADV_DONTNEED)
- virtio-block (raw + qcow2, thin provisioning)
- virtio-net with vhost-net (kernel data path, sub-ms ping)
- virtio-vsock with vhost-vsock (kernel backend, guest modules load and activate)
- virtio-fs (host directory sharing via inline FUSE protocol, 20 opcodes)
- MMIO transport for all 6 virtio devices
- In-kernel irqchip + PIT
- ACPI tables (RSDP → XSDT → MADT with LAPIC/IOAPIC, optional MCFG for PCI)
- ACPI PM register emulation (ports 0x600-0x607, zero ACPI errors at boot)
- Memory overcommit (MAP_NORESERVE + KSM)
- Private page tracking (mincore)
- Multi-vCPU SMP (threaded AP execution, in-kernel LAPIC SIPI)
- Full-memory page tables (2MB pages, up to 64GB)
- `--rootfs` boot mode (auto-generated initrd, pivot_root into virtio-block disk)
- `clone rootfs create` (Alpine, Ubuntu/Debian, Docker import, directory import)
- Clean shutdown on SIGTERM/SIGINT
- Measured boot (SHA-256 kernel hash verification)
- Seccomp jailer (BPF syscall filter)
- Per-VM identity injection (identity page at guest phys 0x6000)
- CoW template engine (in-memory snapshot/fork, <20ms)
- Incremental snapshots (dirty page tracking, KVM dirty log)
- Guest agent (vsock heartbeat → VMM, shutdown commands, activity reporting)
- Balloon hysteresis policy (graduated reclaim, cooldown, burstiness tracking, agent-driven tick)
- Network auto-setup (`--net` flag: auto-create bridge, TAP, NAT masquerade)
- `clone fork` CLI (load template, CoW mmap, restore vCPU state, inject identity)
- `--overlay` mode (tmpfs ephemeral + persistent block device overlays, auto-format)
- `--shared-dir /host/path:tag` for virtio-fs host directory sharing
- Boot timing instrumentation (VMM overhead ~10ms)
- Kernel cmdline tuning (`tsc=reliable`, `8250.nr_uarts=1`, `random.trust_cpu=on`)
- mmap kernel preload with MADV_SEQUENTIAL + MADV_WILLNEED
- **Pre-copy live migration** over TCP (~19ms downtime on 256MB VM, zero-page optimization, 64-page batching)
- **PCI bus with ECAM** config space (0xB000_0000, 256MB MMIO window for BARs)
- **VFIO device passthrough** (GPU/NIC passthrough, DMA identity mapping, BAR allocation)
- **Console attach** (`clone attach`) — connect to running VM serial via Unix socket, Ctrl-Q to detach
- **Remote exec** (`clone exec`) — execute commands inside VM via guest agent over vsock
- **Daemonless VM listing** (`clone list --no-daemon`) — scan control sockets, show PID/state/vCPUs/RSS
- **Daemon create with full options** — `clone create` passes rootfs/overlay/shared-dir/net/seccomp/jail to spawned VM
- **Fork device support** — `clone fork` supports `--net`, `--shared-dir`, `--block`, `--seccomp`, `--jail`

### Needs Work
- **MSI-X interrupt routing** — stubbed in PCI bus, devices work via legacy INTx. Full MSI-X needed for high-performance passthrough.
- **SR-IOV / vGPU / mdev** — single device passthrough works, but no virtual function or mediated device support.
- **Confidential VMs (TDX/SEV)** — no TEE support yet.

---

## Comparison with Other VMMs

All Clone numbers are measured on real hardware (OVH bare-metal, Intel Xeon, Ubuntu 22.04, kernel 6.5). Other VMM numbers are from official documentation and published benchmarks, cited inline.

### Boot Performance

| Metric | Clone | Firecracker | Cloud Hypervisor | QEMU (microvm) | QEMU (Q35) |
|--------|--------|-------------|------------------|-----------------|-------------|
| **Cold boot (minimal kernel)** | — | **<=125ms** ^1 | **<100ms** ^2 | 500ms-2s | 5-20s |
| **Cold boot (distro kernel)** | **2,217ms** (best), **2,338ms** (avg/5) | ~2-3s ^3 | ~2s | ~2s | 5-20s |
| **CoW fork / snapshot restore** | **<20ms** | ~5-10ms ^4 | stop+resume | stop+resume | stop+resume |
| **VMM boot overhead** | **8.8ms** (mem 125us, irq 288us, dev 310us, kernel 8.7ms) | ~12ms ^1 | not published | not published | not published |

^1 Firecracker SPECIFICATION.md: <=125ms InstanceStart→init, 1 vCPU, 128MB, serial disabled, measured on M5D.metal
^2 cloudhypervisor.org: "Boot to userspace in less than 100ms" with direct kernel boot; CI measures ~92-120ms
^3 jvns.ca: ~2-3s for Ubuntu VM with systemd init
^4 Firecracker uses MAP_PRIVATE mmap of snapshot memory (lazy page fault loading)

**Note:** Firecracker and Cloud Hypervisor achieve sub-200ms cold boot using custom minimal kernels with stripped configs. With standard distro kernels (systemd, full module set), all VMMs converge to ~2-3s — the bottleneck is kernel init, not the VMM. Clone's advantage is **CoW fork** which skips kernel boot entirely.

### Live Migration

| Metric | Clone | Firecracker | Cloud Hypervisor | QEMU |
|--------|--------|-------------|------------------|------|
| **Supported** | yes (pre-copy) | **no** | yes (pre-copy) | yes (pre-copy + post-copy) |
| **Downtime (256MB idle VM)** | **23ms** (measured) | N/A | not published | 50-300ms ^5 |
| **Default downtime target** | converge to <256 dirty pages | N/A | not published | 300ms ^6 |
| **Zero-page optimization** | yes | N/A | not published | yes |
| **Dirty page tracking** | KVM dirty log | N/A | KVM dirty log | KVM dirty log |
| **Post-copy mode** | no | N/A | no | yes |

^5 QEMU pre-copy typically achieves 50-300ms for small idle VMs; heavily memory-writing workloads may not converge
^6 QEMU source: `DEFAULT_MIGRATE_SET_DOWNTIME = 300ms` in migration/options.c

**Note:** Clone's 19ms downtime was measured on a 256MB idle VM over loopback. This is a best-case scenario — downtime increases with dirty page rate and memory size. QEMU achieves similar numbers in similar conditions. The meaningful comparison is: Clone has live migration, Firecracker does not.

### Memory Efficiency

| Metric | Clone | Firecracker | Cloud Hypervisor | QEMU |
|--------|--------|-------------|------------------|------|
| **VMM memory overhead** | ~5-10MB | **<=5MB** ^7 | not published | ~20-40MB |
| **512MB VM actual RSS** | **126MB** (measured) | ~512MB (no overcommit) | variable | variable |
| **3 forked VMs total RSS (busybox)** | **13MB** (CoW sharing) | N/A | N/A | N/A |
| **3 forked VMs total RSS (Alpine)** | **13MB** (CoW sharing, real distro) | N/A | N/A | N/A |
| **Memory overcommit** | yes (MAP_NORESERVE) | **no** ^8 | yes | yes |
| **KSM dedup** | yes (MADV_MERGEABLE) | no | no | yes (manual) |
| **Balloon reclaim** | yes (hysteresis policy) | yes (basic) | yes | yes |
| **Incremental snapshot** | **192KB** for 512MB VM (682x smaller) | full only | full only | full + incremental |
| **10x idle 512MB VMs** | ~200MB host RAM | ~5GB (no overcommit) | ~variable | ~variable |

^7 Firecracker SPECIFICATION.md: <=5MB overhead, CI-enforced, 1 vCPU, 128MB
^8 Firecracker GitHub issue #849: "device pass-through implies pinning physical memory which would remove memory oversubscription capabilities"

### Device & Passthrough Support

| Feature | Clone | Firecracker | Cloud Hypervisor | QEMU |
|---------|--------|-------------|------------------|------|
| **virtio-block** | raw + qcow2 | raw | raw + qcow2 | raw + qcow2 + many |
| **virtio-net** | vhost-net | vhost-net | vhost-net/user | many backends |
| **virtio-balloon** | yes | yes | yes | yes |
| **virtio-vsock** | vhost-vsock | vhost-vsock | vhost-vsock | vhost-vsock |
| **virtio-fs** | yes (inline FUSE) | **no** ^9 | virtiofsd daemon | virtiofsd daemon |
| **Transport** | MMIO + PCI (ECAM) | MMIO only | PCI | PCI / MMIO |
| **PCI bus** | yes (ECAM) | **no** | yes | yes |
| **VFIO passthrough** | yes (full device) | **no** | yes (full device) | yes (full device) |
| **SR-IOV** | no | **no** | yes | yes |
| **vGPU / mdev** | no | **no** | no | yes |
| **MSI-X** | stubbed (INTx) | N/A | yes | yes |
| **GPU direct (P2P DMA)** | no | **no** | yes (NVIDIA clique) | yes |
| **Rate limiting** | no | yes | yes | yes |
| **Confidential VMs** | no | no | yes (TDX/SEV) | yes (TDX/SEV) |

^9 Firecracker design.md confirms: only virtio-net, virtio-block, virtio-vsock, serial, i8042

### Operational Features

| Feature | Clone | Firecracker | Cloud Hypervisor | QEMU |
|---------|--------|-------------|------------------|------|
| **Lines of code** | ~19.3K Rust | ~50K Rust | ~70K Rust | ~2M+ C |
| **Snapshots** | full + incremental | full (mmap CoW) | stop+resume | full + incremental |
| **CoW templates** | **yes (mmap fork)** | no | no | no |
| **Rootfs creation** | **built-in** (Alpine, Ubuntu, Docker) | external | external | external |
| **Guest agent** | built-in (vsock) | no | no | qemu-ga |
| **Overlay mode** | **built-in** (tmpfs + qcow2) | no | no | manual |
| **Host dir sharing** | `--shared-dir` (no daemon) | no | virtiofsd daemon | virtiofsd daemon |
| **Measured boot** | SHA-256 kernel hash | no | no | no |
| **Seccomp** | yes | yes | yes | yes |
| **Multi-vCPU** | yes | yes | yes | yes |
| **Config model** | CLI flags | JSON API | CLI + YAML/API | ~500 flags |
| **Non-Linux guests** | no | no | no | **yes (any arch)** |
| **Production scale** | untested | **AWS Lambda** (millions) | Intel labs | everywhere |

### Where Clone Wins

- **CoW template fork (<20ms)** — no other VMM offers live fork from a running template. Firecracker snapshot restore (~5-10ms) is comparable speed but requires separate snapshot files per VM and doesn't share memory pages across clones. Clone forks share pages via MAP_PRIVATE CoW — measured: 3 forked Alpine Linux VMs total RSS = **13MB** (~4MB/fork) vs 127MB template. Works with real distros, not just minimal kernels.
- **Memory density** — overcommit + KSM + balloon hysteresis stacked together. A 512MB VM uses only **126MB RSS** (measured). 10 idle 512MB VMs use ~200MB host RAM total. Firecracker explicitly doesn't do overcommit (by design — they want predictable allocation). Cloud Hypervisor supports overcommit but not KSM.
- **Simplicity** — 19.3K LOC vs 50K (Firecracker) vs 70K (Cloud Hypervisor) vs 2M+ (QEMU). One Rust file per subsystem. No XML, no libvirt, no configuration files. Full codebase is auditable in a day.
- **Self-contained virtio-fs** — inline FUSE protocol, no external virtiofsd daemon process. `--shared-dir /path:tag` just works. Cloud Hypervisor and QEMU require running a separate virtiofsd process.
- **Built-in rootfs tooling** — `clone rootfs create --distro alpine` creates a bootable image. Others require you to bring your own or use external tools.
- **Overlay mode** — `--rootfs base.img --overlay` gives you a writable VM from a shared read-only base. No manual qcow2 chain setup.
- **Incremental snapshots** — only dirty pages saved. 512MB VM with 192KB dirty → **192KB snapshot** (682x smaller than full). Measured.
- **Feature breadth for the size** — live migration (23ms downtime), VFIO passthrough, virtio-fs, CoW fork, snapshots, balloon, overlays — all in 19.3K LOC. No other VMM packs this feature set at this code size.

### Where Others Win

- **Firecracker** — battle-tested in AWS Lambda at millions of concurrent microVMs. Sub-125ms cold boot with custom kernels (Clone does 2.2s cold boot). <=5MB VMM overhead (CI-enforced). Rate limiting on virtio devices. Minimal attack surface by design (no PCI, no fs sharing, no passthrough). If you need proven production scale, Firecracker is the safe choice.
- **Cloud Hypervisor** — mature VFIO with full MSI-X and SR-IOV support. Intel TDX / AMD SEV for confidential VMs. NVIDIA GPUDirect P2P DMA support. Virtual IOMMU (virtio-iommu) for nested passthrough. Multiple PCI segments for large GPU deployments. If you need advanced GPU infrastructure, Cloud Hypervisor has deeper support.
- **QEMU** — supports everything: every CPU architecture (x86, ARM, RISC-V, MIPS, s390x, ...), every device, every storage format, every network backend, USB, audio, display, TPM, vGPU/mdev. 20+ years of compatibility. If the hardware exists, QEMU emulates it. Also has post-copy live migration for workloads that can't converge with pre-copy.

### When to Use Clone

- **Dev shells** — boot an isolated Linux environment in <20ms via CoW fork, share host dirs via virtio-fs, discard on exit
- **Function-as-a-Service** — CoW fork from warm templates, execute, destroy. Sub-20ms cold start without custom kernel tuning.
- **CI/CD runners** — isolated build environments from shared base images with overlay mode
- **Multi-tenant workloads** — high VM density via memory sharing (overcommit + KSM + balloon), strong KVM isolation
- **GPU passthrough (single device)** — pass a full GPU/NIC into a VM via VFIO for ML training, inference
- **Edge/embedded** — single ~3MB binary, no dependencies, minimal attack surface

### When to Use Something Else

- **Multi-tenant GPU (SR-IOV, vGPU)** — use Cloud Hypervisor or QEMU. Clone supports full device passthrough but not yet SR-IOV or mediated devices for sharing one GPU across VMs.
- **Confidential VMs (TDX/SEV)** — use Cloud Hypervisor or QEMU. Clone has no TEE support.
- **Non-Linux guests** — use QEMU. Clone only supports Linux x86_64 kernels.
- **AWS Lambda scale (millions of VMs)** — use Firecracker. Proven at massive scale with years of production hardening.
- **Exotic hardware** — use QEMU. USB, audio, display, TPM, nested virt, etc.
- **Fastest possible cold boot** — use Firecracker or Cloud Hypervisor with a custom minimal kernel (<125ms). Clone's speed advantage comes from CoW fork, not cold boot.

---

## Build & Run

```bash
# Build
cargo build --release

# Quick start — create a rootfs and boot
clone rootfs create --distro alpine --size 1G -o alpine.img
sudo clone run --kernel /boot/vmlinuz-$(uname -r) --rootfs alpine.img

# With networking
sudo ip link add br0 type bridge
sudo ip addr add 172.20.0.1/24 dev br0
sudo ip link set br0 up
sudo ip tuntap add tap0 mode tap
sudo ip link set tap0 master br0
sudo ip link set tap0 up
sudo iptables -t nat -A POSTROUTING -s 172.20.0.0/24 ! -o br0 -j MASQUERADE
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

sudo clone run \
  --kernel /boot/vmlinuz-$(uname -r) \
  --rootfs alpine.img \
  --mem-mb 512 \
  --tap tap0

# Run 5 VMs from the same base (shared read-only, per-VM overlay)
for i in $(seq 1 5); do
  sudo clone run \
    --kernel /boot/vmlinuz-$(uname -r) \
    --rootfs alpine.img \
    --overlay \
    --mem-mb 256 \
    --tap tap$i &
done
```

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `kvm-ioctls` 0.19 | KVM ioctl wrappers |
| `kvm-bindings` 0.10 | KVM struct definitions |
| `libc` 0.2 | System calls (mmap, ioctl, eventfd) |
| `anyhow` | Error handling |
| `tracing` | Structured logging |
| `clap` | CLI argument parsing |

---

## Language

All Rust. Single binary, no runtime dependencies beyond Linux + KVM.
