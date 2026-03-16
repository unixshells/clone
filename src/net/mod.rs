// Networking subsystem.
//
// Phase 1: basic TAP device + virtio-net
// Phase 3: vhost-net for data path bypass
//
// Architecture:
// - Per-VM TAP device
// - Host bridge for connectivity
// - Static IP injection via guest agent (no DHCP)
// - Port forwarding for dev shell access

use std::os::unix::io::RawFd;

/// Network configuration for a VM.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Name of the host bridge to attach TAP to (e.g., "clone-br0").
    pub bridge_name: String,
    /// Guest IP address (e.g., "10.0.0.2").
    pub guest_ip: String,
    /// Gateway IP address (e.g., "10.0.0.1").
    pub gateway_ip: String,
    /// Subnet mask (e.g., "255.255.255.0").
    pub netmask: String,
    /// MAC address for the guest NIC (6 bytes).
    pub mac_address: [u8; 6],
}

impl NetworkConfig {
    /// Create a new network configuration with the given parameters.
    pub fn new(
        bridge_name: &str,
        guest_ip: &str,
        gateway_ip: &str,
        netmask: &str,
        mac_address: [u8; 6],
    ) -> Self {
        Self {
            bridge_name: bridge_name.to_string(),
            guest_ip: guest_ip.to_string(),
            gateway_ip: gateway_ip.to_string(),
            netmask: netmask.to_string(),
            mac_address,
        }
    }

    /// Generate a MAC address from a VM ID (deterministic).
    /// Uses locally-administered, unicast prefix 02:nano:vm:XX:XX:XX.
    pub fn mac_from_id(vm_id: u32) -> [u8; 6] {
        let bytes = vm_id.to_be_bytes();
        [
            0x02, // locally administered, unicast
            0x4E, // 'N'
            0x56, // 'V'
            bytes[1],
            bytes[2],
            bytes[3],
        ]
    }
}

/// Create a TAP device with the given name.
///
/// On Linux, this opens /dev/net/tun and issues TUNSETIFF ioctl to create
/// a TAP (layer 2) device. The returned fd is used for reading/writing
/// ethernet frames.
///
/// On non-Linux platforms, returns an error (TAP devices are Linux-specific).
#[cfg(target_os = "linux")]
pub fn create_tap(name: &str) -> anyhow::Result<RawFd> {
    use std::ffi::CString;

    // Open /dev/net/tun.
    let tun_path = CString::new("/dev/net/tun").unwrap();
    let fd = unsafe { libc::open(tun_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to open /dev/net/tun: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Prepare ifreq struct for TUNSETIFF.
    // struct ifreq {
    //     char ifr_name[IFNAMSIZ];  // 16 bytes
    //     union { ... };            // we set ifr_flags at offset 16
    // };
    const IFNAMSIZ: usize = 16;
    const IFF_TAP: libc::c_short = 0x0002;
    const IFF_NO_PI: libc::c_short = 0x1000;
    // TUNSETIFF = _IOW('T', 202, int) = 0x400454CA
    const TUNSETIFF: libc::c_ulong = 0x400454CA;

    let mut ifr = [0u8; 40]; // ifreq is typically 40 bytes

    // Copy device name into ifr_name (first 16 bytes), truncating if needed.
    let name_bytes = name.as_bytes();
    let copy_len = std::cmp::min(name_bytes.len(), IFNAMSIZ - 1);
    ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // Set flags at offset 16: IFF_TAP | IFF_NO_PI.
    let flags: libc::c_short = IFF_TAP | IFF_NO_PI;
    ifr[16..18].copy_from_slice(&flags.to_ne_bytes());

    let ret = unsafe { libc::ioctl(fd, TUNSETIFF, ifr.as_ptr()) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd); }
        return Err(anyhow::anyhow!("TUNSETIFF failed for {name}: {err}"));
    }

    // Set the fd to non-blocking mode for async I/O.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd); }
        return Err(anyhow::anyhow!("fcntl F_GETFL failed: {err}"));
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd); }
        return Err(anyhow::anyhow!("fcntl F_SETFL O_NONBLOCK failed: {err}"));
    }

    tracing::info!("TAP device created: {name} (fd={fd})");
    Ok(fd)
}

#[cfg(not(target_os = "linux"))]
pub fn create_tap(name: &str) -> anyhow::Result<RawFd> {
    tracing::warn!("TAP device creation not supported on this platform (stub for '{name}')");
    // Return a dummy fd for compilation. Real TAP requires Linux.
    Ok(-1)
}

/// Configure a TAP device with an IP address and netmask.
///
/// Uses SIOCSIFADDR and SIOCSIFNETMASK ioctls on Linux.
/// On non-Linux platforms, this is a no-op stub.
#[cfg(target_os = "linux")]
pub fn configure_tap(fd: RawFd, ip: &str, netmask: &str) -> anyhow::Result<()> {
    use std::net::Ipv4Addr;

    // We need a socket for the SIOC* ioctls (they operate on the interface
    // name, not the TAP fd directly).
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create ioctl socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Get the interface name from the TAP fd.
    // We could also accept it as a parameter, but getting it from fd is more robust.
    // For now, we'll rely on the caller providing the name via the fd's associated ifreq.
    // Actually, let's just use a utility ioctl to get the ifr_name.

    // TUNGETIFF to retrieve the interface name.
    const TUNGETIFF: libc::c_ulong = 0x800454D2;
    let mut ifr = [0u8; 40];
    let ret = unsafe { libc::ioctl(fd, TUNGETIFF, ifr.as_mut_ptr()) };
    if ret < 0 {
        unsafe { libc::close(sock); }
        return Err(anyhow::anyhow!(
            "TUNGETIFF failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Parse the IP address.
    let ip_addr: Ipv4Addr = ip.parse().map_err(|e| anyhow::anyhow!("Invalid IP: {e}"))?;
    let netmask_addr: Ipv4Addr = netmask
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid netmask: {e}"))?;

    // Helper to build a sockaddr_in and place it in the ifreq union at offset 16.
    fn set_sockaddr_in(ifr: &mut [u8], addr: &Ipv4Addr) {
        // struct sockaddr_in at offset 16 in ifreq:
        // sa_family (2 bytes) + sin_port (2 bytes) + sin_addr (4 bytes)
        let family = (libc::AF_INET as u16).to_ne_bytes();
        ifr[16] = family[0];
        ifr[17] = family[1];
        ifr[18] = 0; // port high
        ifr[19] = 0; // port low
        let octets = addr.octets();
        ifr[20] = octets[0];
        ifr[21] = octets[1];
        ifr[22] = octets[2];
        ifr[23] = octets[3];
    }

    // SIOCSIFADDR = 0x8916
    const SIOCSIFADDR: libc::c_ulong = 0x8916;
    set_sockaddr_in(&mut ifr, &ip_addr);
    let ret = unsafe { libc::ioctl(sock, SIOCSIFADDR, ifr.as_ptr()) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock); }
        return Err(anyhow::anyhow!("SIOCSIFADDR failed: {err}"));
    }

    // SIOCSIFNETMASK = 0x891C
    const SIOCSIFNETMASK: libc::c_ulong = 0x891C;
    set_sockaddr_in(&mut ifr, &netmask_addr);
    let ret = unsafe { libc::ioctl(sock, SIOCSIFNETMASK, ifr.as_ptr()) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock); }
        return Err(anyhow::anyhow!("SIOCSIFNETMASK failed: {err}"));
    }

    // Bring the interface up: SIOCSIFFLAGS with IFF_UP.
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;

    // First get current flags.
    let ret = unsafe { libc::ioctl(sock, SIOCGIFFLAGS, ifr.as_mut_ptr()) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock); }
        return Err(anyhow::anyhow!("SIOCGIFFLAGS failed: {err}"));
    }
    // Set IFF_UP (bit 0) in the flags at offset 16 (as i16).
    let current_flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
    let new_flags = current_flags | (libc::IFF_UP as i16);
    ifr[16..18].copy_from_slice(&new_flags.to_ne_bytes());

    let ret = unsafe { libc::ioctl(sock, SIOCSIFFLAGS, ifr.as_ptr()) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock); }
        return Err(anyhow::anyhow!("SIOCSIFFLAGS (IFF_UP) failed: {err}"));
    }

    unsafe { libc::close(sock); }

    tracing::info!("TAP configured: ip={ip}, netmask={netmask}");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn configure_tap(_fd: RawFd, ip: &str, netmask: &str) -> anyhow::Result<()> {
    tracing::warn!(
        "TAP configuration not supported on this platform (stub: ip={ip}, netmask={netmask})"
    );
    Ok(())
}

/// Add a TAP interface to a Linux bridge.
///
/// Uses SIOCBRADDIF ioctl on Linux. On non-Linux platforms, this is a stub.
#[cfg(target_os = "linux")]
pub fn setup_bridge(bridge_name: &str, tap_name: &str) -> anyhow::Result<()> {
    // Get the interface index of the TAP device.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Get ifindex for the TAP device.
    let mut ifr = [0u8; 40];
    let name_bytes = tap_name.as_bytes();
    let copy_len = std::cmp::min(name_bytes.len(), 15);
    ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // SIOCGIFINDEX = 0x8933
    const SIOCGIFINDEX: libc::c_ulong = 0x8933;
    let ret = unsafe { libc::ioctl(sock, SIOCGIFINDEX, ifr.as_mut_ptr()) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock); }
        return Err(anyhow::anyhow!("SIOCGIFINDEX for {tap_name} failed: {err}"));
    }
    let ifindex = i32::from_ne_bytes([ifr[16], ifr[17], ifr[18], ifr[19]]);

    // Now prepare ifreq for the bridge.
    let mut br_ifr = [0u8; 40];
    let br_bytes = bridge_name.as_bytes();
    let br_copy_len = std::cmp::min(br_bytes.len(), 15);
    br_ifr[..br_copy_len].copy_from_slice(&br_bytes[..br_copy_len]);
    br_ifr[16..20].copy_from_slice(&ifindex.to_ne_bytes());

    // SIOCBRADDIF = 0x89A2
    const SIOCBRADDIF: libc::c_ulong = 0x89A2;
    let ret = unsafe { libc::ioctl(sock, SIOCBRADDIF, br_ifr.as_ptr()) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(sock); }
        return Err(anyhow::anyhow!(
            "SIOCBRADDIF (add {tap_name} to {bridge_name}) failed: {err}"
        ));
    }

    unsafe { libc::close(sock); }
    tracing::info!("Added TAP {tap_name} to bridge {bridge_name}");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn setup_bridge(bridge_name: &str, tap_name: &str) -> anyhow::Result<()> {
    tracing::warn!(
        "Bridge setup not supported on this platform (stub: bridge={bridge_name}, tap={tap_name})"
    );
    Ok(())
}

/// Orchestrate full VM network setup: create TAP, configure IP, add to bridge.
///
/// Returns the TAP file descriptor ready for use by virtio-net.
pub fn setup_vm_network(config: &NetworkConfig) -> anyhow::Result<RawFd> {
    // Generate a TAP device name from the MAC (last 3 bytes as hex).
    let tap_name = format!(
        "nvm-{:02x}{:02x}{:02x}",
        config.mac_address[3], config.mac_address[4], config.mac_address[5]
    );

    tracing::info!(
        "Setting up VM network: tap={tap_name}, ip={}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        config.gateway_ip,
        config.mac_address[0], config.mac_address[1], config.mac_address[2],
        config.mac_address[3], config.mac_address[4], config.mac_address[5]
    );

    // 1. Create the TAP device.
    let tap_fd = create_tap(&tap_name)?;

    // 2. Configure IP on the TAP (this is the host-side gateway address).
    if let Err(e) = configure_tap(tap_fd, &config.gateway_ip, &config.netmask) {
        // Clean up on failure.
        if tap_fd >= 0 {
            unsafe { libc::close(tap_fd); }
        }
        return Err(e);
    }

    // 3. Add TAP to bridge (optional, only if bridge exists).
    if !config.bridge_name.is_empty() {
        if let Err(e) = setup_bridge(&config.bridge_name, &tap_name) {
            tracing::warn!("Failed to add TAP to bridge (non-fatal): {e}");
            // Not fatal — point-to-point networking still works without bridge.
        }
    }

    Ok(tap_fd)
}

/// Default bridge name for Clone networking.
pub const DEFAULT_BRIDGE: &str = "clone-br0";
/// Default bridge subnet.
pub const DEFAULT_BRIDGE_IP: &str = "172.30.0.1";
pub const DEFAULT_BRIDGE_CIDR: &str = "172.30.0.0/24";
pub const DEFAULT_NETMASK: &str = "255.255.255.0";

/// Automatically set up networking: create bridge, TAP, and NAT rules.
///
/// If the clone-br0 bridge doesn't exist, it's created and configured.
/// A new TAP device is created with an auto-generated name and added to the bridge.
/// NAT masquerade is set up for outbound connectivity.
///
/// Returns `(tap_name, tap_fd)`.
#[cfg(target_os = "linux")]
pub fn auto_setup_network(vm_index: u32) -> anyhow::Result<(String, RawFd)> {
    // 1. Ensure the bridge exists
    ensure_bridge()?;

    // 2. Create a TAP device with an auto-generated name
    let tap_name = format!("nvm-{}", vm_index);
    let tap_fd = create_tap(&tap_name)?;

    // 3. Bring TAP up (no IP on the TAP itself — the bridge has the IP)
    bring_interface_up(&tap_name)?;

    // 4. Add TAP to bridge
    if let Err(e) = setup_bridge(DEFAULT_BRIDGE, &tap_name) {
        tracing::warn!("Failed to add TAP to bridge: {e}");
        // Non-fatal — point-to-point still works
    }

    // 5. Ensure NAT masquerade
    ensure_nat()?;

    tracing::info!("Auto network setup complete: tap={tap_name}, bridge={DEFAULT_BRIDGE}");
    Ok((tap_name, tap_fd))
}

#[cfg(not(target_os = "linux"))]
pub fn auto_setup_network(_vm_index: u32) -> anyhow::Result<(String, RawFd)> {
    anyhow::bail!("Auto network setup requires Linux");
}

/// Create the Clone bridge if it doesn't already exist.
#[cfg(target_os = "linux")]
fn ensure_bridge() -> anyhow::Result<()> {
    use std::process::Command;

    // Check if bridge already exists
    if std::path::Path::new(&format!("/sys/class/net/{DEFAULT_BRIDGE}")).exists() {
        tracing::debug!("Bridge {DEFAULT_BRIDGE} already exists");
        return Ok(());
    }

    tracing::info!("Creating bridge {DEFAULT_BRIDGE}");

    let status = Command::new("ip")
        .args(["link", "add", DEFAULT_BRIDGE, "type", "bridge"])
        .status()?;
    if !status.success() {
        anyhow::bail!("Failed to create bridge {DEFAULT_BRIDGE}");
    }

    let status = Command::new("ip")
        .args(["addr", "add", &format!("{DEFAULT_BRIDGE_IP}/24"), "dev", DEFAULT_BRIDGE])
        .status()?;
    if !status.success() {
        anyhow::bail!("Failed to assign IP to bridge {DEFAULT_BRIDGE}");
    }

    let status = Command::new("ip")
        .args(["link", "set", DEFAULT_BRIDGE, "up"])
        .status()?;
    if !status.success() {
        anyhow::bail!("Failed to bring up bridge {DEFAULT_BRIDGE}");
    }

    // Enable IP forwarding
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

    Ok(())
}

/// Set up NAT masquerade for the Clone subnet if not already configured.
#[cfg(target_os = "linux")]
fn ensure_nat() -> anyhow::Result<()> {
    use std::process::Command;

    // Check if the rule already exists
    let output = Command::new("iptables")
        .args(["-t", "nat", "-C", "POSTROUTING", "-s", DEFAULT_BRIDGE_CIDR,
               "!", "-o", DEFAULT_BRIDGE, "-j", "MASQUERADE"])
        .output()?;

    if output.status.success() {
        tracing::debug!("NAT masquerade rule already exists");
        return Ok(());
    }

    // Add the NAT rule
    let status = Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-s", DEFAULT_BRIDGE_CIDR,
               "!", "-o", DEFAULT_BRIDGE, "-j", "MASQUERADE"])
        .status()?;

    if !status.success() {
        tracing::warn!("Failed to add NAT masquerade (non-fatal, may need iptables)");
    } else {
        tracing::info!("NAT masquerade configured for {DEFAULT_BRIDGE_CIDR}");
    }

    // Add FORWARD rules so the kernel allows traffic to/from VMs.
    // Without these, the default FORWARD policy (often DROP) blocks UDP/TCP.
    let _ = Command::new("iptables")
        .args(["-C", "FORWARD", "-s", DEFAULT_BRIDGE_CIDR, "-j", "ACCEPT"])
        .output()
        .and_then(|o| if o.status.success() { Ok(()) } else {
            Command::new("iptables")
                .args(["-A", "FORWARD", "-s", DEFAULT_BRIDGE_CIDR, "-j", "ACCEPT"])
                .status().map(|_| ())
        });
    let _ = Command::new("iptables")
        .args(["-C", "FORWARD", "-d", DEFAULT_BRIDGE_CIDR, "-j", "ACCEPT"])
        .output()
        .and_then(|o| if o.status.success() { Ok(()) } else {
            Command::new("iptables")
                .args(["-A", "FORWARD", "-d", DEFAULT_BRIDGE_CIDR, "-j", "ACCEPT"])
                .status().map(|_| ())
        });

    Ok(())
}

/// Bring a network interface up.
#[cfg(target_os = "linux")]
fn bring_interface_up(name: &str) -> anyhow::Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        anyhow::bail!("Failed to create socket: {}", std::io::Error::last_os_error());
    }

    let mut ifr = [0u8; 40];
    let name_bytes = name.as_bytes();
    let copy_len = std::cmp::min(name_bytes.len(), 15);
    ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // Get current flags
    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

    let ret = unsafe { libc::ioctl(sock, SIOCGIFFLAGS, ifr.as_mut_ptr()) };
    if ret < 0 {
        unsafe { libc::close(sock) };
        anyhow::bail!("SIOCGIFFLAGS for {name} failed: {}", std::io::Error::last_os_error());
    }

    let current_flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
    let new_flags = current_flags | (libc::IFF_UP as i16);
    ifr[16..18].copy_from_slice(&new_flags.to_ne_bytes());

    let ret = unsafe { libc::ioctl(sock, SIOCSIFFLAGS, ifr.as_ptr()) };
    unsafe { libc::close(sock) };

    if ret < 0 {
        anyhow::bail!("Failed to bring up {name}: {}", std::io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_from_id() {
        let mac = NetworkConfig::mac_from_id(1);
        assert_eq!(mac[0], 0x02); // locally administered
        assert_eq!(mac[1], 0x4E); // 'N'
        assert_eq!(mac[2], 0x56); // 'V'
    }

    #[test]
    fn test_mac_from_id_deterministic() {
        let mac1 = NetworkConfig::mac_from_id(42);
        let mac2 = NetworkConfig::mac_from_id(42);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_mac_from_id_unique() {
        let mac1 = NetworkConfig::mac_from_id(1);
        let mac2 = NetworkConfig::mac_from_id(2);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_network_config() {
        let config = NetworkConfig::new(
            "br0",
            "10.0.0.2",
            "10.0.0.1",
            "255.255.255.0",
            [0x02, 0x4E, 0x56, 0x00, 0x00, 0x01],
        );
        assert_eq!(config.bridge_name, "br0");
        assert_eq!(config.guest_ip, "10.0.0.2");
    }
}
