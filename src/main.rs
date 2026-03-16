#[cfg(target_os = "linux")]
mod vmm;
#[cfg(target_os = "linux")]
mod memory;
#[cfg(target_os = "linux")]
mod boot;
#[cfg(target_os = "linux")]
mod migration;
#[cfg(target_os = "linux")]
mod pci;

mod virtio;
mod net;
mod storage;
mod control;
mod rootfs;
mod rootfs_create;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "clone", about = "Minimal VMM for dev shells and serverless")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Boot a new VM
    Run {
        /// Path to guest kernel
        #[arg(long)]
        kernel: String,

        /// Path to initrd (optional, mutually exclusive with --rootfs)
        #[arg(long, conflicts_with = "rootfs")]
        initrd: Option<String>,

        /// Path to rootfs disk image. Clone auto-generates an initrd that
        /// mounts this as the root filesystem and boots /sbin/init.
        #[arg(long, conflicts_with = "initrd")]
        rootfs: Option<String>,

        /// Enable overlay mode for rootfs. The base image is mounted read-only
        /// and a writable layer is stacked on top.
        /// Use without a value for tmpfs overlay (ephemeral), or specify a path
        /// for a persistent overlay file.
        #[arg(long, requires = "rootfs", default_missing_value = "tmpfs", num_args = 0..=1)]
        overlay: Option<String>,

        /// Kernel command line
        #[arg(long, default_value = "console=ttyS0 reboot=k panic=1 pci=off nokaslr quiet")]
        cmdline: String,

        /// Show verbose kernel boot messages (adds earlyprintk, removes quiet)
        #[arg(long)]
        verbose_boot: bool,

        /// Memory size in MB
        #[arg(long, default_value_t = 512)]
        mem_mb: u32,

        /// Number of vCPUs
        #[arg(long, default_value_t = 1)]
        vcpus: u32,

        /// Path to block device image (optional, for additional storage)
        #[arg(long)]
        block: Option<String>,

        /// TAP device name for virtio-net (e.g., "tap0"). Omit to disable networking.
        #[arg(long, conflicts_with = "net")]
        tap: Option<String>,

        /// Auto-configure networking (create bridge, TAP, NAT).
        /// Equivalent to --tap with automatic bridge/NAT setup.
        #[arg(long, conflicts_with = "tap")]
        net: bool,

        /// Share a host directory via virtio-fs. Format: /host/path:tag
        /// Guest mounts with: mount -t virtiofs <tag> /mnt
        #[arg(long)]
        shared_dir: Option<String>,

        /// Enable raw terminal mode for serial I/O (default: true)
        #[arg(long, default_value_t = true)]
        raw_terminal: bool,

        /// Pass through a PCI device via VFIO (e.g., "0000:01:00.0").
        /// Device must be bound to vfio-pci driver. Can be repeated.
        #[arg(long)]
        passthrough: Vec<String>,

        /// Enable seccomp BPF filter (restricts VMM syscalls to essential operations)
        #[arg(long)]
        seccomp: bool,

        /// Enable full jail (namespaces + chroot + capabilities + seccomp).
        /// Specify the chroot directory path.
        #[arg(long)]
        jail: Option<String>,

        /// Guest vsock CID (assigned by daemon, default: 3)
        #[arg(long)]
        cid: Option<u64>,

        /// Path to kernel hash manifest (JSON) for measured boot verification.
        /// If provided, the kernel is verified against the manifest before loading.
        #[arg(long)]
        kernel_manifest: Option<String>,
    },
    /// Create a template snapshot from a running VM
    Snapshot {
        /// PID of the VM process (auto-detected if only one VM is running)
        #[arg(long)]
        vm_id: Option<u32>,

        /// Output path for template
        #[arg(long)]
        output: String,
    },
    /// Live migrate a VM to a remote host
    Migrate {
        /// PID of the VM process (auto-detected if only one VM is running)
        #[arg(long)]
        vm_id: Option<u32>,

        /// Remote host in user@host format
        #[arg(long)]
        to: String,

        /// Path on remote host for the template (default: /tmp/clone-migrate-{pid})
        #[arg(long)]
        remote_path: Option<String>,

        /// Shut down local VM after confirmed remote startup
        #[arg(long)]
        shutdown_after: bool,

        /// Dry run: snapshot + transfer but don't fork on remote
        #[arg(long)]
        dry_run: bool,

        /// Use pre-copy live migration over TCP instead of snapshot+rsync
        #[arg(long)]
        live: bool,

        /// TCP port for live migration (used with --live)
        #[arg(long, default_value_t = 14242)]
        port: u16,
    },
    /// Fork a new VM from a template snapshot
    Fork {
        /// Path to template snapshot
        #[arg(long)]
        template: String,

        /// Skip memory hash verification (faster for large templates)
        #[arg(long)]
        skip_verify: bool,

        /// Share a host directory via virtio-fs. Format: /host/path:tag
        #[arg(long)]
        shared_dir: Option<String>,

        /// Auto-configure networking (create bridge, TAP, NAT)
        #[arg(long, conflicts_with = "tap")]
        net: bool,

        /// TAP device name for virtio-net
        #[arg(long, conflicts_with = "net")]
        tap: Option<String>,

        /// Path to block device image
        #[arg(long)]
        block: Option<String>,

        /// Enable seccomp BPF filter
        #[arg(long)]
        seccomp: bool,

        /// Enable full jail (namespaces + chroot + capabilities + seccomp)
        #[arg(long)]
        jail: Option<String>,

        /// Guest vsock CID (auto-assigned by daemon, manual override for standalone)
        #[arg(long)]
        cid: Option<u64>,
    },
    /// Template management
    Template {
        #[command(subcommand)]
        action: TemplateCommands,
    },
    /// Rootfs image management
    Rootfs {
        #[command(subcommand)]
        action: RootfsCommands,
    },
    /// Run the Clone daemon for multi-VM orchestration
    Daemon {
        /// Control socket path
        #[arg(long, default_value = "/run/clone/control.sock")]
        socket: String,
    },
    /// Create a new VM via the daemon
    Create {
        /// Daemon control socket path
        #[arg(long, default_value = "/run/clone/control.sock")]
        socket: String,
        /// Path to guest kernel
        #[arg(long)]
        kernel: String,
        /// Memory size in MB
        #[arg(long, default_value_t = 512)]
        mem_mb: u32,
        /// Number of vCPUs
        #[arg(long, default_value_t = 1)]
        vcpus: u32,
        /// Path to initrd
        #[arg(long, conflicts_with = "rootfs")]
        initrd: Option<String>,
        /// Path to rootfs disk image
        #[arg(long, conflicts_with = "initrd")]
        rootfs: Option<String>,
        /// Enable overlay mode for rootfs (tmpfs or path)
        #[arg(long, requires = "rootfs", default_missing_value = "tmpfs", num_args = 0..=1)]
        overlay: Option<String>,
        /// Share a host directory via virtio-fs. Format: /host/path:tag
        #[arg(long)]
        shared_dir: Option<String>,
        /// Path to block device image
        #[arg(long)]
        block: Option<String>,
        /// Auto-configure networking
        #[arg(long, conflicts_with = "tap")]
        net: bool,
        /// TAP device name for virtio-net
        #[arg(long, conflicts_with = "net")]
        tap: Option<String>,
        /// Enable seccomp BPF filter
        #[arg(long)]
        seccomp: bool,
        /// Enable full jail (namespaces + chroot + capabilities + seccomp)
        #[arg(long)]
        jail: Option<String>,
    },
    /// Destroy a VM via the daemon
    Destroy {
        /// Daemon control socket path
        #[arg(long, default_value = "/run/clone/control.sock")]
        socket: String,
        /// VM ID to destroy
        #[arg(long)]
        vm_id: String,
    },
    /// List all running VMs (scans control sockets, no daemon required)
    List {
        /// Daemon control socket path (use --no-daemon to skip)
        #[arg(long, default_value = "/run/clone/control.sock")]
        socket: String,
        /// List VMs by scanning control sockets (no daemon required)
        #[arg(long)]
        no_daemon: bool,
    },
    /// Attach to a running VM's serial console
    Attach {
        /// VM PID (auto-detected if only one VM running)
        #[arg(long)]
        vm_id: Option<u32>,
    },
    /// Execute a command inside a running VM
    Exec {
        /// VM PID (auto-detected if only one VM running)
        #[arg(long)]
        vm_id: Option<u32>,
        /// Command to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Receive a live migration (destination side)
    MigrateRecv {
        /// TCP port to listen on
        #[arg(long, default_value_t = 14242)]
        port: u16,

        /// Path to guest kernel (needed for receiver VM setup)
        #[arg(long)]
        kernel: String,

        /// Memory size in MB (must match source VM)
        #[arg(long, default_value_t = 256)]
        mem_mb: u32,
    },
    /// Get status of a specific VM
    Status {
        /// Daemon control socket path
        #[arg(long, default_value = "/run/clone/control.sock")]
        socket: String,
        /// VM ID
        #[arg(long)]
        vm_id: String,
    },
}

#[derive(Subcommand)]
enum TemplateCommands {
    /// Verify a template's memory hash
    Verify {
        /// Path to template directory
        #[arg(long)]
        path: String,
    },
}

#[derive(Subcommand)]
enum RootfsCommands {
    /// Create a new rootfs disk image
    Create {
        /// Distro to bootstrap (alpine, ubuntu, debian)
        #[arg(long, conflicts_with_all = ["from_dir", "from_docker"])]
        distro: Option<String>,

        /// Release/version (e.g., noble, jammy, bookworm, 3.21). Defaults: ubuntu=noble, debian=bookworm, alpine=3.21
        #[arg(long, requires = "distro")]
        release: Option<String>,

        /// Import rootfs from a local directory
        #[arg(long, conflicts_with_all = ["distro", "from_docker"])]
        from_dir: Option<String>,

        /// Import rootfs from a Docker image
        #[arg(long, conflicts_with_all = ["distro", "from_dir"])]
        from_docker: Option<String>,

        /// Image size (e.g., "1G", "512M", "4G")
        #[arg(long, default_value = "1G")]
        size: String,

        /// Output file path
        #[arg(short = 'o', long)]
        output: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .json()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            kernel,
            initrd,
            rootfs,
            overlay,
            cmdline,
            verbose_boot,
            mem_mb,
            vcpus,
            block,
            tap,
            net,
            shared_dir,
            raw_terminal: _raw_terminal,
            passthrough,
            seccomp,
            jail,
            cid,
            kernel_manifest,
        } => {
            #[cfg(target_os = "linux")]
            {
                // Verify kernel against manifest if provided
                if let Some(ref manifest_path) = kernel_manifest {
                    let manifest = boot::measured::load_trusted_hashes(manifest_path)
                        .context("Failed to load kernel manifest")?;
                    let kernel_name = std::path::Path::new(&kernel)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| kernel.clone());
                    let verifier = boot::measured::verifier_for_kernel(&manifest, &kernel_name)
                        .context("Kernel not found in manifest")?;
                    verifier.verify_kernel(&kernel)
                        .context("Kernel verification failed")?;
                    eprintln!("Kernel verified: {kernel}");
                }

                let mut cmdline = if verbose_boot {
                    // Replace quiet with verbose options
                    let c = cmdline.replace(" quiet", "");
                    format!("{c} earlyprintk=serial,ttyS0,115200 keep_bootcon")
                } else {
                    cmdline
                };
                let mut effective_initrd = initrd;
                let mut rootfs_block: Option<String> = None;

                // Handle --rootfs mode: generate initrd and set up rootfs block device
                let _initrd_data: Option<Vec<u8>>;
                let mut overlay_device: Option<String> = None;
                if let Some(ref rootfs_image) = rootfs {
                    let raw_overlay = overlay.as_deref().unwrap_or("none");

                    // Determine effective overlay mode for the kernel cmdline.
                    // "tmpfs" → passed as-is (clone-init handles tmpfs overlay)
                    // "none" → no overlay
                    // any path → create/use overlay file, pass "block" to kernel
                    let (overlay_mode, overlay_file) = if raw_overlay == "tmpfs" || raw_overlay == "none" {
                        (raw_overlay.to_string(), None)
                    } else {
                        // Persistent overlay path — create file if needed
                        let path = std::path::Path::new(raw_overlay);
                        if !path.exists() {
                            tracing::info!("Creating overlay file: {raw_overlay}");
                            // Create a 1GB sparse file for overlay storage
                            let f = std::fs::File::create(path)?;
                            f.set_len(1024 * 1024 * 1024)?; // 1GB sparse
                        }
                        ("block".to_string(), Some(raw_overlay.to_string()))
                    };

                    let readonly = overlay_mode != "none";

                    let rootfs_config = rootfs::RootfsConfig {
                        image: rootfs_image.clone(),
                        readonly,
                        overlay: overlay_mode.to_string(),
                        fstype: "auto".to_string(),
                    };

                    overlay_device = overlay_file;

                    // Find clone-init binary and generate initrd
                    let init_binary = rootfs::find_init_binary()?;
                    tracing::info!("Using init binary: {}", init_binary.display());

                    let initrd_bytes = rootfs::generate_initrd(&init_binary)?;

                    // Write generated initrd to a temp file
                    let initrd_path = std::env::temp_dir().join(format!(
                        "clone-initrd-{}.img",
                        std::process::id()
                    ));
                    std::fs::write(&initrd_path, &initrd_bytes)?;
                    effective_initrd = Some(initrd_path.to_string_lossy().to_string());

                    // The rootfs image becomes the primary block device (/dev/vda)
                    rootfs_block = Some(rootfs_image.clone());

                    // Append rootfs params to kernel cmdline
                    for param in rootfs::rootfs_cmdline_params(&rootfs_config) {
                        cmdline.push(' ');
                        cmdline.push_str(&param);
                    }

                    tracing::info!(
                        "Rootfs mode: image={}, overlay={}, readonly={}",
                        rootfs_image,
                        overlay_mode,
                        readonly
                    );

                    _initrd_data = Some(initrd_bytes);
                } else {
                    _initrd_data = None;
                }

                // Rootfs image is the primary block device; --block is additional storage
                let primary_block = rootfs_block.or(block);

                // Handle --net (auto-setup) vs --tap (manual)
                let (effective_tap, pre_opened_tap_fd) = if net {
                    match net::auto_setup_network(std::process::id()) {
                        Ok((tap_name, tap_fd)) => {
                            // Pass both the name (for logging) and the fd
                            // (so boot() doesn't try to recreate the TAP).
                            (Some(tap_name), Some(tap_fd))
                        }
                        Err(e) => {
                            tracing::warn!("Auto network setup failed: {e}");
                            (None, None)
                        }
                    }
                } else {
                    (tap, None)
                };

                tracing::info!("Booting VM: kernel={kernel}, mem={mem_mb}MB, vcpus={vcpus}");
                // If passthrough devices are present, remove pci=off from cmdline
                if !passthrough.is_empty() {
                    cmdline = cmdline.replace(" pci=off", "").replace("pci=off ", "").replace("pci=off", "");
                }

                let config = vmm::VmConfig {
                    kernel_path: kernel,
                    initrd_path: effective_initrd,
                    cmdline,
                    mem_mb,
                    vcpus,
                    block_device: primary_block,
                    overlay_device,
                    tap_device: effective_tap,
                    shared_dir,
                    passthrough_devices: passthrough,
                    seccomp,
                    jail,
                    cid,
                    tap_fd: pre_opened_tap_fd,
                };
                let mut vm = vmm::Vm::new(config)?;
                vm.boot()?;
                vm.run()?;

                // Clean up temp initrd
                if let Some(ref rootfs_image) = rootfs {
                    let _ = rootfs_image; // suppress unused warning
                    let initrd_path = std::env::temp_dir().join(format!(
                        "clone-initrd-{}.img",
                        std::process::id()
                    ));
                    let _ = std::fs::remove_file(initrd_path);
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!(
                    "Clone requires Linux with KVM support. Current OS is not supported.\n\
                     Build and run on a Linux host with: cargo build --release"
                );
            }
        }
        Commands::Snapshot { vm_id, output } => {
            let pid = resolve_vm_pid(vm_id)?;
            let socket_path = format!("/tmp/clone-{pid}.sock");

            eprintln!("Connecting to VM (pid={pid}) at {socket_path}...");

            let request = control::protocol::Request::Snapshot {
                vm_id: pid.to_string(),
                output_path: output.clone(),
            };

            let response = send_control_request(&socket_path, &request)?;
            match response {
                control::protocol::Response::Ok { body } => {
                    eprintln!("Snapshot complete: {output}");
                    if let control::protocol::ResponseBody::SnapshotComplete { path } = body {
                        println!("{path}");
                    }
                }
                control::protocol::Response::Error { message } => {
                    anyhow::bail!("Snapshot failed: {message}");
                }
            }
        }
        Commands::Migrate { vm_id, to, remote_path, shutdown_after, dry_run, live, port } => {
            let pid = resolve_vm_pid(vm_id)?;
            let socket_path = format!("/tmp/clone-{pid}.sock");

            // Live migration path: send LiveMigrate command via control socket
            if live {
                // Extract hostname from user@host format
                let host = if to.contains('@') {
                    to.split('@').last().unwrap_or(&to).to_string()
                } else {
                    to.clone()
                };

                eprintln!("Live migrating VM (pid={pid}) to {host}:{port}...");
                let request = control::protocol::Request::LiveMigrate {
                    dest_host: host,
                    dest_port: port,
                };

                let response = send_control_request(&socket_path, &request)?;
                match response {
                    control::protocol::Response::Ok { body } => {
                        eprintln!("Live migration complete!");
                        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
                    }
                    control::protocol::Response::Error { message } => {
                        anyhow::bail!("Live migration failed: {message}");
                    }
                }
                return Ok(());
            }

            let local_template = format!("/tmp/clone-migrate-{pid}");
            let remote_template = remote_path.unwrap_or_else(|| format!("/tmp/clone-migrate-{pid}"));

            // Pre-flight: verify clone exists on remote
            eprintln!("Pre-flight: checking remote host {to}...");
            let preflight = std::process::Command::new("ssh")
                .args([&to, "clone --version"])
                .output()?;
            if !preflight.status.success() {
                anyhow::bail!(
                    "Pre-flight failed: clone not found on {to}. Install clone on the remote host first."
                );
            }
            let remote_version = String::from_utf8_lossy(&preflight.stdout);
            eprintln!("Remote clone: {}", remote_version.trim());

            // Pre-flight: verify write access on remote
            let write_check = std::process::Command::new("ssh")
                .args([&to, &format!("test -w $(dirname {remote_template})")])
                .status()?;
            if !write_check.success() {
                anyhow::bail!(
                    "Pre-flight failed: no write access to {} on {to}",
                    remote_template
                );
            }
            eprintln!("Pre-flight passed.");

            // Step 1: Snapshot
            eprintln!("Step 1/3: Snapshotting VM (pid={pid})...");
            let request = control::protocol::Request::Snapshot {
                vm_id: pid.to_string(),
                output_path: local_template.clone(),
            };
            let response = send_control_request(&socket_path, &request)?;
            match response {
                control::protocol::Response::Ok { .. } => {
                    eprintln!("Snapshot complete.");
                }
                control::protocol::Response::Error { message } => {
                    anyhow::bail!("Snapshot failed: {message}");
                }
            }

            // Step 2: rsync to remote with progress
            eprintln!("Step 2/3: Transferring to {to}:{remote_template}...");
            let rsync_status = std::process::Command::new("rsync")
                .args([
                    "-a", "--compress", "--progress",
                    &format!("{local_template}/"),
                    &format!("{to}:{remote_template}/"),
                ])
                .status()?;
            if !rsync_status.success() {
                // Cleanup partial transfer on remote
                eprintln!("Transfer failed. Cleaning up remote partial data...");
                let _ = std::process::Command::new("ssh")
                    .args([&to, &format!("rm -rf {remote_template}")])
                    .status();
                anyhow::bail!("rsync failed with exit code: {:?}", rsync_status.code());
            }
            eprintln!("Transfer complete.");

            if dry_run {
                eprintln!("Dry run: skipping remote fork. Template transferred to {to}:{remote_template}");
                return Ok(());
            }

            // Step 3: Fork on remote
            eprintln!("Step 3/3: Starting VM on {to}...");
            let fork_output = std::process::Command::new("ssh")
                .args([&to, &format!("sudo clone fork --template {remote_template}")])
                .output()?;
            if !fork_output.status.success() {
                let stderr = String::from_utf8_lossy(&fork_output.stderr);
                eprintln!(
                    "Remote fork failed. Template is at {to}:{remote_template} for manual recovery.\n\
                     Remote stderr: {stderr}"
                );
                anyhow::bail!("Remote fork failed with exit code: {:?}", fork_output.status.code());
            }

            // Health check: verify remote VM is running
            eprintln!("Verifying remote VM...");
            std::thread::sleep(std::time::Duration::from_secs(2));
            let health = std::process::Command::new("ssh")
                .args([&to, "ls /tmp/clone-*.sock 2>/dev/null | head -1"])
                .output()?;
            if health.status.success() && !health.stdout.is_empty() {
                let remote_sock = String::from_utf8_lossy(&health.stdout);
                eprintln!("Remote VM confirmed: {}", remote_sock.trim());
            } else {
                eprintln!("Warning: could not confirm remote VM is running. Check manually.");
            }

            // Optional: shut down local VM
            if shutdown_after {
                eprintln!("Shutting down local VM (pid={pid})...");
                let shutdown_req = control::protocol::Request::Shutdown;
                match send_control_request(&socket_path, &shutdown_req) {
                    Ok(_) => eprintln!("Local VM shutdown initiated."),
                    Err(e) => eprintln!("Warning: failed to shut down local VM: {e}"),
                }
            }

            eprintln!("Migration complete: VM running on {to}");
        }
        Commands::Fork { template, skip_verify, shared_dir, net, tap, block, seccomp, jail, cid } => {
            #[cfg(target_os = "linux")]
            {
                // Handle --net (auto-setup) vs --tap (manual)
                let (effective_tap, pre_opened_tap_fd) = if net {
                    match net::auto_setup_network(std::process::id()) {
                        Ok((tap_name, tap_fd)) => (Some(tap_name), Some(tap_fd)),
                        Err(e) => {
                            tracing::warn!("Auto network setup failed: {e}");
                            (None, None)
                        }
                    }
                } else {
                    (tap, None)
                };

                tracing::info!("Forking VM from template {template}");
                let config = vmm::VmConfig {
                    kernel_path: String::new(),
                    initrd_path: None,
                    cmdline: String::new(),
                    mem_mb: 0, // will be set from template
                    vcpus: 0,  // will be set from template
                    block_device: block,
                    overlay_device: None,
                    tap_device: effective_tap,
                    shared_dir,
                    passthrough_devices: Vec::new(),
                    seccomp,
                    jail,
                    cid,
                    tap_fd: pre_opened_tap_fd,
                };
                let mut vm = vmm::Vm::new(config)?;
                vm.fork_boot(&template, skip_verify)?;
                vm.run()?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = skip_verify; // suppress unused warning
                let _ = (shared_dir, net, tap, block, seccomp, jail);
                anyhow::bail!("Clone requires Linux with KVM support.");
            }
        }
        Commands::Template { action } => match action {
            TemplateCommands::Verify { path } => {
                #[cfg(target_os = "linux")]
                {
                    match boot::template::TemplateSnapshot::load(&path, true) {
                        Ok(snapshot) => {
                            eprintln!(
                                "Template verification succeeded: runtime={}, memory_size={}MB",
                                snapshot.runtime_type,
                                snapshot.memory_size >> 20,
                            );
                        }
                        Err(e) => {
                            eprintln!("Template verification failed: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = path;
                    anyhow::bail!("Clone requires Linux with KVM support.");
                }
            }
        },
        Commands::Daemon { socket } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(control::daemon::run_daemon(&socket))?;
        }
        Commands::Create { socket, kernel, mem_mb, vcpus, initrd, rootfs, overlay, shared_dir, block, net, tap, seccomp, jail } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let client = control::ControlClient::new(&socket);
                let request = control::protocol::Request::CreateVm {
                    kernel,
                    initrd,
                    cmdline: "console=ttyS0 reboot=k panic=1 pci=off nokaslr quiet".to_string(),
                    mem_mb,
                    vcpus,
                    rootfs,
                    overlay,
                    shared_dir,
                    block,
                    net,
                    tap,
                    seccomp,
                    jail,
                };
                let response = client.send(&request).await?;
                match response {
                    control::protocol::Response::Ok { body } => {
                        if let control::protocol::ResponseBody::VmCreated { vm_id, pid } = body {
                            println!("{vm_id} (pid: {pid})");
                        }
                    }
                    control::protocol::Response::Error { message } => {
                        anyhow::bail!("Create failed: {message}");
                    }
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        Commands::Destroy { socket, vm_id } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let client = control::ControlClient::new(&socket);
                let request = control::protocol::Request::DestroyVm { vm_id: vm_id.clone() };
                let response = client.send(&request).await?;
                match response {
                    control::protocol::Response::Ok { .. } => {
                        eprintln!("VM {vm_id} destroyed");
                    }
                    control::protocol::Response::Error { message } => {
                        anyhow::bail!("Destroy failed: {message}");
                    }
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        Commands::List { socket, no_daemon } => {
            let use_scan = no_daemon || !std::path::Path::new(&socket).exists();
            if use_scan {
                // Scan /tmp/clone-*.sock files directly (no daemon required)
                let mut found = Vec::new();
                if let Ok(entries) = std::fs::read_dir("/tmp") {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name = name.to_string_lossy().to_string();
                        if let Some(rest) = name.strip_prefix("clone-") {
                            if let Some(pid_str) = rest.strip_suffix(".sock") {
                                if let Ok(pid) = pid_str.parse::<u32>() {
                                    let sock_path = format!("/tmp/clone-{pid}.sock");
                                    // Try to query status
                                    let request = control::protocol::Request::VmStatus {
                                        vm_id: pid.to_string(),
                                    };
                                    match send_control_request(&sock_path, &request) {
                                        Ok(control::protocol::Response::Ok { body }) => {
                                            if let control::protocol::ResponseBody::Status { state, pid: vm_pid, vcpus } = body {
                                                // Try to read RSS from /proc/{pid}/status
                                                let rss_mb = read_vm_rss(vm_pid);
                                                found.push((vm_pid, state, vcpus, rss_mb, sock_path));
                                            }
                                        }
                                        _ => {
                                            // Socket exists but not responding, skip
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if found.is_empty() {
                    eprintln!("No VMs running.");
                } else {
                    println!("{:<10} {:<10} {:<8} {:<10} {}", "PID", "STATE", "VCPUS", "RSS_MB", "SOCKET");
                    for (pid, state, vcpus, rss_mb, socket_path) in &found {
                        println!("{:<10} {:<10} {:<8} {:<10} {}", pid, state, vcpus, rss_mb, socket_path);
                    }
                }
            } else {
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(async {
                    let client = control::ControlClient::new(&socket);
                    let request = control::protocol::Request::ListVms;
                    let response = client.send(&request).await?;
                    match response {
                        control::protocol::Response::Ok { body } => {
                            if let control::protocol::ResponseBody::VmList { vms } = body {
                                if vms.is_empty() {
                                    eprintln!("No VMs running.");
                                } else {
                                    println!("{:<12} {:<10} {:<12}", "VM_ID", "STATE", "UPTIME");
                                    for vm in &vms {
                                        println!("{:<12} {:<10} {:<12.1}s", vm.vm_id, vm.state, vm.uptime_secs);
                                    }
                                }
                            }
                        }
                        control::protocol::Response::Error { message } => {
                            anyhow::bail!("List failed: {message}");
                        }
                    }
                    Ok::<(), anyhow::Error>(())
                })?;
            }
        }
        Commands::Attach { vm_id } => {
            let pid = resolve_vm_pid(vm_id)?;
            let console_path = format!("/tmp/clone-{pid}.console");

            eprintln!("Attaching to VM (pid={pid}) console at {console_path}...");
            eprintln!("Press Ctrl-Q to detach.");

            let stream = std::os::unix::net::UnixStream::connect(&console_path)
                .with_context(|| format!("Failed to connect to console socket: {console_path}"))?;

            // Set terminal to raw mode
            let _raw_guard = {
                #[cfg(unix)]
                {
                    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
                    let ret = unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut termios) };
                    if ret == 0 {
                        let original = termios;
                        unsafe {
                            libc::cfmakeraw(&mut termios);
                            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &termios);
                        }
                        Some(original)
                    } else {
                        None
                    }
                }
                #[cfg(not(unix))]
                { None::<()> }
            };

            // Bidirectional bridge: stdin -> socket, socket -> stdout
            let stream_clone = stream.try_clone()?;

            // Thread: socket -> stdout
            let reader_handle = std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut stream = stream_clone;
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            let _ = std::io::stdout().write_all(&buf[..n]);
                            let _ = std::io::stdout().flush();
                        }
                        Err(_) => break,
                    }
                }
            });

            // Main thread: stdin -> socket (watch for Ctrl-Q = 0x11)
            {
                use std::io::Read;
                let mut stream = stream;
                let stdin = std::io::stdin();
                let mut handle = stdin.lock();
                let mut buf = [0u8; 1];
                while handle.read_exact(&mut buf).is_ok() {
                    if buf[0] == 0x11 {
                        // Ctrl-Q: detach
                        break;
                    }
                    let _ = std::io::Write::write_all(&mut stream, &buf);
                }
            }

            // Restore terminal
            #[cfg(unix)]
            if let Some(original) = _raw_guard {
                unsafe {
                    libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &original);
                }
            }

            let _ = reader_handle.join();
            eprintln!("\nDetached from VM (pid={pid}).");
        }
        Commands::Exec { vm_id, command } => {
            let pid = resolve_vm_pid(vm_id)?;
            let socket_path = format!("/tmp/clone-{pid}.sock");

            let (cmd, args) = if command.is_empty() {
                anyhow::bail!("No command specified");
            } else {
                (command[0].clone(), command[1..].to_vec())
            };

            let request = control::protocol::Request::Exec {
                command: cmd,
                args,
            };

            let response = send_control_request(&socket_path, &request)?;
            match response {
                control::protocol::Response::Ok { body } => {
                    if let control::protocol::ResponseBody::ExecResult { exit_code, stdout, stderr } = body {
                        if !stdout.is_empty() {
                            print!("{stdout}");
                        }
                        if !stderr.is_empty() {
                            eprint!("{stderr}");
                        }
                        std::process::exit(exit_code);
                    }
                }
                control::protocol::Response::Error { message } => {
                    anyhow::bail!("Exec failed: {message}");
                }
            }
        }
        Commands::Status { socket, vm_id } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let client = control::ControlClient::new(&socket);
                let request = control::protocol::Request::VmStatus { vm_id };
                let response = client.send(&request).await?;
                match response {
                    control::protocol::Response::Ok { body } => {
                        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
                    }
                    control::protocol::Response::Error { message } => {
                        anyhow::bail!("Status failed: {message}");
                    }
                }
                Ok::<(), anyhow::Error>(())
            })?;
        }
        Commands::MigrateRecv { port, kernel, mem_mb } => {
            #[cfg(target_os = "linux")]
            {
                eprintln!("Starting migration receiver: port={port}, kernel={kernel}, mem={mem_mb}MB");
                migration::run_receiver(port, &kernel, mem_mb)?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (port, kernel, mem_mb);
                anyhow::bail!("Clone requires Linux with KVM support.");
            }
        }
        Commands::Rootfs { action } => match action {
            RootfsCommands::Create {
                distro,
                release,
                from_dir,
                from_docker,
                size,
                output,
            } => {
                let source = if let Some(d) = distro {
                    rootfs_create::RootfsSource::Distro(d, release)
                } else if let Some(dir) = from_dir {
                    rootfs_create::RootfsSource::FromDir(dir)
                } else if let Some(image) = from_docker {
                    rootfs_create::RootfsSource::FromDocker(image)
                } else {
                    anyhow::bail!(
                        "Specify one of: --distro, --from-dir, or --from-docker"
                    );
                };
                rootfs_create::create_rootfs(&source, &size, &output)?;
            }
        },
    }

    Ok(())
}

/// Resolve the VM PID: use the given value, or auto-detect if only one
/// clone control socket exists in /tmp.
fn resolve_vm_pid(vm_id: Option<u32>) -> Result<u32> {
    if let Some(pid) = vm_id {
        return Ok(pid);
    }

    // Auto-detect: find all clone-*.sock files in /tmp
    let mut pids = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(rest) = name.strip_prefix("clone-") {
                if let Some(pid_str) = rest.strip_suffix(".sock") {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        // Verify the socket is connectable
                        if std::os::unix::net::UnixStream::connect(entry.path()).is_ok() {
                            pids.push(pid);
                        }
                    }
                }
            }
        }
    }

    match pids.len() {
        0 => anyhow::bail!("No running Clone instances found. Use --vm-id to specify a PID."),
        1 => Ok(pids[0]),
        n => anyhow::bail!(
            "Found {n} running Clone instances ({pids:?}). Use --vm-id to specify which one."
        ),
    }
}

/// Read VmRSS from /proc/{pid}/status and return it in MB.
fn read_vm_rss(pid: u32) -> u64 {
    let status_path = format!("/proc/{pid}/status");
    if let Ok(contents) = std::fs::read_to_string(&status_path) {
        for line in contents.lines() {
            if let Some(val) = line.strip_prefix("VmRSS:") {
                let val = val.trim();
                // Parse "12345 kB" -> MB
                if let Some(kb_str) = val.strip_suffix("kB").or_else(|| val.strip_suffix("KB")) {
                    if let Ok(kb) = kb_str.trim().parse::<u64>() {
                        return kb / 1024;
                    }
                }
            }
        }
    }
    0
}

/// Send a request to a VM's control socket and return the response.
fn send_control_request(
    socket_path: &str,
    request: &control::protocol::Request,
) -> Result<control::protocol::Response> {
    use std::io::{BufReader, BufWriter};

    let stream = std::os::unix::net::UnixStream::connect(socket_path)
        .with_context(|| format!("Failed to connect to control socket: {socket_path}"))?;

    // Set a generous timeout for snapshot operations
    stream.set_read_timeout(Some(std::time::Duration::from_secs(300)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    let mut writer = BufWriter::new(&stream);
    let mut reader = BufReader::new(&stream);

    control::protocol::write_frame_sync(&mut writer, request)?;
    let response: control::protocol::Response = control::protocol::read_frame_sync(&mut reader)?;

    Ok(response)
}

