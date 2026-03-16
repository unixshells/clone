// Rootfs image creation — bootstraps a bootable disk image from a distro,
// directory, or Docker image.
//
// Requires Linux with root privileges (for loop mounting).
// Tools needed: truncate, mkfs.ext4, mount, umount, losetup
// Distro-specific: debootstrap (Ubuntu), curl+tar (Alpine), docker (Docker import)

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

/// Supported distro targets for rootfs creation.
#[derive(Debug, Clone)]
pub enum RootfsSource {
    /// Bootstrap from a distro name (alpine, ubuntu) with optional release
    Distro(String, Option<String>),
    /// Import from a local directory
    FromDir(String),
    /// Import from a Docker image
    FromDocker(String),
}

/// Create a rootfs disk image.
///
/// Steps:
/// 1. Create sparse raw image of the requested size
/// 2. Format with ext4
/// 3. Mount via loop device
/// 4. Populate the filesystem (distro bootstrap, directory copy, or docker export)
/// 5. Configure serial console and basic networking
/// 6. Unmount and clean up
pub fn create_rootfs(source: &RootfsSource, size: &str, output: &str) -> Result<()> {
    let output_path = Path::new(output);
    if output_path.exists() {
        anyhow::bail!("Output file already exists: {output}. Remove it first or choose a different path.");
    }

    // Parse size string (e.g., "1G", "512M", "4G") to bytes for truncate
    let size_bytes = parse_size(size)?;

    println!("Creating rootfs image: {output} ({size})");

    // 1. Create sparse image
    run_cmd("truncate", &["-s", &size_bytes.to_string(), output])
        .context("Failed to create sparse image")?;

    // 2. Format with ext4
    println!("Formatting with ext4...");
    run_cmd("mkfs.ext4", &["-q", "-F", "-L", "clone-rootfs", output])
        .context("Failed to format image with ext4")?;

    // 3. Mount via loop device
    let mount_dir = format!("/tmp/clone-rootfs-{}", std::process::id());
    std::fs::create_dir_all(&mount_dir)?;

    run_cmd("mount", &["-o", "loop", output, &mount_dir])
        .context("Failed to mount image (are you root?)")?;

    // From here on, ensure we unmount on error
    let result = populate_rootfs(source, &mount_dir);

    // Configure common stuff regardless of source
    if result.is_ok() {
        if let Err(e) = configure_rootfs(&mount_dir) {
            eprintln!("Warning: rootfs configuration partially failed: {e}");
        }
    }

    // 6. Unmount
    println!("Unmounting...");
    let umount_result = run_cmd("umount", &[&mount_dir]);
    let _ = std::fs::remove_dir(&mount_dir);

    // Propagate the populate error if any
    result?;
    umount_result.context("Failed to unmount image")?;

    println!("Rootfs image created: {output}");
    Ok(())
}

fn populate_rootfs(source: &RootfsSource, mount_dir: &str) -> Result<()> {
    match source {
        RootfsSource::Distro(distro, release) => match distro.as_str() {
            "alpine" => bootstrap_alpine(mount_dir, release.as_deref()),
            "ubuntu" => bootstrap_ubuntu(mount_dir, release.as_deref().unwrap_or("noble")),
            "debian" => bootstrap_ubuntu(mount_dir, release.as_deref().unwrap_or("bookworm")),
            other => anyhow::bail!("Unsupported distro: {other}. Supported: alpine, ubuntu, debian"),
        },
        RootfsSource::FromDir(dir) => {
            println!("Copying from directory: {dir}");
            run_cmd("cp", &["-a", &format!("{dir}/."), mount_dir])
                .context("Failed to copy directory contents")?;
            Ok(())
        }
        RootfsSource::FromDocker(image) => import_docker(image, mount_dir),
    }
}

/// Bootstrap an Alpine Linux rootfs using the minirootfs tarball.
fn bootstrap_alpine(mount_dir: &str, release: Option<&str>) -> Result<()> {
    // release format: "3.21" or "3.21.3" — if minor is included, use it; otherwise default
    let (version, minor) = if let Some(r) = release {
        let parts: Vec<&str> = r.splitn(3, '.').collect();
        if parts.len() >= 3 {
            (format!("{}.{}", parts[0], parts[1]), parts[2].to_string())
        } else {
            (r.to_string(), "0".to_string())
        }
    } else {
        ("3.21".to_string(), "3".to_string())
    };

    println!("Bootstrapping Alpine Linux {version}.{minor}...");

    let arch = "x86_64";
    let tarball_url = format!(
        "https://dl-cdn.alpinelinux.org/alpine/v{}/releases/{}/alpine-minirootfs-{}.{}-{}.tar.gz",
        version, arch, version, minor, arch
    );
    let tarball_path = format!("/tmp/alpine-minirootfs-{}.tar.gz", std::process::id());

    println!("Downloading Alpine minirootfs...");
    let dl_result = run_cmd("curl", &["-fsSL", "-o", &tarball_path, &tarball_url]);

    if dl_result.is_err() {
        // Try wget as fallback
        run_cmd("wget", &["-q", "-O", &tarball_path, &tarball_url])
            .context("Failed to download Alpine minirootfs (tried curl and wget)")?;
    }

    // Extract into mount dir
    println!("Extracting...");
    run_cmd("tar", &["xzf", &tarball_path, "-C", mount_dir])
        .context("Failed to extract Alpine minirootfs")?;

    let _ = std::fs::remove_file(&tarball_path);

    // Set up Alpine package repos
    let repos = format!("{mount_dir}/etc/apk/repositories");
    std::fs::write(
        &repos,
        format!(
            "https://dl-cdn.alpinelinux.org/alpine/v{}/main\n\
             https://dl-cdn.alpinelinux.org/alpine/v{}/community\n",
            version, version
        ),
    )?;

    // DNS must be available inside chroot for apk to fetch packages
    std::fs::write(
        format!("{mount_dir}/etc/resolv.conf"),
        "nameserver 8.8.8.8\nnameserver 8.8.4.4\n",
    )?;

    // Install openrc and basic packages via apk in chroot
    println!("Installing base packages...");
    let _ = run_cmd(
        "chroot",
        &[mount_dir, "apk", "add", "--no-cache", "openrc", "agetty", "e2fsprogs"],
    );

    Ok(())
}

/// Bootstrap Ubuntu/Debian using debootstrap.
fn bootstrap_ubuntu(mount_dir: &str, suite: &str) -> Result<()> {
    println!("Bootstrapping {suite} with debootstrap...");

    // Check that debootstrap is available
    if Command::new("which").arg("debootstrap").output()
        .map(|o| !o.status.success()).unwrap_or(true)
    {
        anyhow::bail!(
            "debootstrap is not installed. Install it with:\n  \
             sudo apt install debootstrap"
        );
    }

    // Use DEBOOTSTRAP_MIRROR env var if set, otherwise use a fast US mirror.
    // Operators can set DEBOOTSTRAP_MIRROR for local/regional mirrors.
    let mirror = std::env::var("DEBOOTSTRAP_MIRROR")
        .unwrap_or_else(|_| "http://archive.ubuntu.com/ubuntu".to_string());
    println!("Using mirror: {mirror}");

    run_cmd("debootstrap", &["--variant=minbase", suite, mount_dir, &mirror])
        .context("debootstrap failed")?;

    Ok(())
}

/// Import a Docker image as a rootfs.
fn import_docker(image: &str, mount_dir: &str) -> Result<()> {
    println!("Importing Docker image: {image}");

    // Pull the image
    run_cmd("docker", &["pull", image])
        .context("Failed to pull Docker image")?;

    // Create a container (don't start it)
    let output = Command::new("docker")
        .args(["create", image])
        .output()
        .context("Failed to create Docker container")?;

    if !output.status.success() {
        anyhow::bail!("docker create failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Export the container filesystem
    let tarball = format!("/tmp/clone-docker-{}.tar", std::process::id());
    let export_result = run_cmd_piped("docker", &["export", &container_id], "tar", &["xf", "-", "-C", mount_dir]);

    // Clean up container
    let _ = run_cmd("docker", &["rm", &container_id]);
    let _ = std::fs::remove_file(&tarball);

    export_result.context("Failed to export Docker image")?;

    Ok(())
}

/// Configure a rootfs with serial console and basic networking.
fn configure_rootfs(mount_dir: &str) -> Result<()> {
    // Set hostname
    std::fs::write(format!("{mount_dir}/etc/hostname"), "clone\n")?;

    // Set up /etc/hosts
    let hosts = "127.0.0.1\tlocalhost\n127.0.1.1\tclone\n";
    std::fs::write(format!("{mount_dir}/etc/hosts"), hosts)?;

    // Set up fstab
    let fstab = "/dev/vda\t/\text4\tdefaults,noatime\t0\t1\nproc\t/proc\tproc\tdefaults\t0\t0\nsysfs\t/sys\tsysfs\tdefaults\t0\t0\n";
    std::fs::write(format!("{mount_dir}/etc/fstab"), fstab)?;

    // Configure serial console autologin
    // Check if systemd-based or openrc-based
    let systemd_dir = format!("{mount_dir}/etc/systemd/system");
    let openrc_dir = format!("{mount_dir}/etc/init.d");

    if Path::new(&systemd_dir).exists() {
        configure_systemd_console(mount_dir)?;
    } else if Path::new(&openrc_dir).exists() {
        configure_openrc_console(mount_dir)?;
    } else {
        // Fallback: set up inittab for busybox init (Alpine default)
        let inittab_path = format!("{mount_dir}/etc/inittab");
        if Path::new(&inittab_path).exists() {
            let inittab = std::fs::read_to_string(&inittab_path)?;
            if !inittab.contains("ttyS0") {
                let mut new_inittab = inittab;
                new_inittab.push_str("\n# Clone serial console\nttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100\n");
                std::fs::write(&inittab_path, new_inittab)?;
            }
        }
    }

    // Set root password to empty (passwordless login)
    let shadow_path = format!("{mount_dir}/etc/shadow");
    if Path::new(&shadow_path).exists() {
        let shadow = std::fs::read_to_string(&shadow_path)?;
        let new_shadow: String = shadow
            .lines()
            .map(|line| {
                if line.starts_with("root:") {
                    // Set empty password hash (passwordless)
                    let parts: Vec<&str> = line.splitn(3, ':').collect();
                    if parts.len() >= 3 {
                        format!("root::{}", parts[2])
                    } else {
                        line.to_string()
                    }
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&shadow_path, new_shadow + "\n")?;
    }

    // Configure basic networking (DHCP on eth0 as fallback)
    let interfaces_dir = format!("{mount_dir}/etc/network");
    if Path::new(&interfaces_dir).exists() || {
        let _ = std::fs::create_dir_all(&interfaces_dir);
        true
    } {
        let interfaces = "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp\n";
        std::fs::write(format!("{interfaces_dir}/interfaces"), interfaces)?;
    }

    // DNS
    std::fs::write(
        format!("{mount_dir}/etc/resolv.conf"),
        "nameserver 8.8.8.8\nnameserver 8.8.4.4\n",
    )?;

    println!("Configured: hostname, serial console, networking, root login");
    Ok(())
}

fn configure_systemd_console(mount_dir: &str) -> Result<()> {
    // Mask the default serial-getty (requires udev) and create our own
    let service_dir = format!("{mount_dir}/etc/systemd/system");
    let service_path = format!("{service_dir}/clone-console.service");

    let service = "\
[Unit]
Description=Clone Serial Console
After=systemd-logind.service
ConditionPathExists=/dev/ttyS0

[Service]
ExecStart=/sbin/agetty --autologin root --noclear ttyS0 115200 linux
Type=idle
Restart=always
RestartSec=0
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/ttyS0
TTYReset=yes
TTYVHangup=yes
UtmpIdentifier=ttyS0
KillMode=process

[Install]
WantedBy=multi-user.target
";
    std::fs::write(&service_path, service)?;

    // Enable the service
    let wants_dir = format!("{service_dir}/multi-user.target.wants");
    let _ = std::fs::create_dir_all(&wants_dir);
    let _ = std::os::unix::fs::symlink(
        "/etc/systemd/system/clone-console.service",
        format!("{wants_dir}/clone-console.service"),
    );

    // Mask the default serial-getty to avoid the 90s udev wait
    let _ = std::os::unix::fs::symlink(
        "/dev/null",
        format!("{service_dir}/serial-getty@ttyS0.service"),
    );

    Ok(())
}

fn configure_openrc_console(mount_dir: &str) -> Result<()> {
    // For OpenRC (Alpine with openrc), configure agetty on ttyS0
    let service_path = format!("{mount_dir}/etc/init.d/ttyS0");
    let service = "#!/sbin/openrc-run\n\ncommand=\"/sbin/agetty\"\ncommand_args=\"--autologin root --noclear ttyS0 115200 linux\"\ncommand_background=false\n\ndepend() {\n    after local\n}\n";
    std::fs::write(&service_path, service)?;

    // Make executable
    run_cmd("chmod", &["+x", &service_path])?;

    // Enable it
    let runlevel_dir = format!("{mount_dir}/etc/runlevels/default");
    let _ = std::fs::create_dir_all(&runlevel_dir);
    let _ = std::os::unix::fs::symlink(
        "/etc/init.d/ttyS0",
        format!("{runlevel_dir}/ttyS0"),
    );

    Ok(())
}

/// Parse a human-readable size string (e.g., "1G", "512M") to bytes.
fn parse_size(size: &str) -> Result<u64> {
    let size = size.trim();
    let (num_str, multiplier) = if let Some(n) = size.strip_suffix('G').or(size.strip_suffix('g')) {
        (n, 1024 * 1024 * 1024u64)
    } else if let Some(n) = size.strip_suffix('M').or(size.strip_suffix('m')) {
        (n, 1024 * 1024u64)
    } else if let Some(n) = size.strip_suffix('K').or(size.strip_suffix('k')) {
        (n, 1024u64)
    } else {
        (size, 1u64)
    };

    let num: u64 = num_str
        .parse()
        .with_context(|| format!("Invalid size: {size}"))?;

    Ok(num * multiplier)
}

/// Run a command and return Ok if it succeeds.
fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("Failed to execute: {program}"))?;

    if !status.success() {
        anyhow::bail!("{program} exited with status: {status}");
    }
    Ok(())
}

/// Pipe output of one command into another.
fn run_cmd_piped(prog1: &str, args1: &[&str], prog2: &str, args2: &[&str]) -> Result<()> {
    let child1 = Command::new(prog1)
        .args(args1)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to execute: {prog1}"))?;

    let status = Command::new(prog2)
        .args(args2)
        .stdin(child1.stdout.unwrap())
        .status()
        .with_context(|| format!("Failed to execute: {prog2}"))?;

    if !status.success() {
        anyhow::bail!("{prog2} exited with status: {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("4g").unwrap(), 4 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("100K").unwrap(), 100 * 1024);
        assert_eq!(parse_size("1024").unwrap(), 1024);
    }
}
