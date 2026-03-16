//! Seccomp jailer: BPF-based syscall filtering, namespace isolation,
//! capability dropping, and resource limits.
//!
//! All Linux-specific code is behind `#[cfg(target_os = "linux")]`.
//! On other platforms the public API compiles but returns errors or no-ops.

use anyhow::Result;

// ---------------------------------------------------------------------------
// Seccomp policy
// ---------------------------------------------------------------------------

/// Defines which syscalls are allowed through the seccomp filter.
#[derive(Debug, Clone)]
pub struct SeccompPolicy {
    /// Allowed syscall numbers (architecture-specific).
    pub allowed: Vec<i32>,
}

impl Default for SeccompPolicy {
    /// Default policy: allowlist of syscalls the VMM needs.
    fn default() -> Self {
        Self {
            allowed: default_allowed_syscalls(),
        }
    }
}

/// Returns the default set of allowed syscall numbers for x86_64 Linux.
/// On non-Linux platforms returns an empty vec (unused).
fn default_allowed_syscalls() -> Vec<i32> {
    #[cfg(target_os = "linux")]
    {
        linux_syscalls::default_allowed()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Linux-specific syscall numbers and BPF
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_syscalls {
    /// x86_64 syscall numbers the VMM needs.
    pub fn default_allowed() -> Vec<i32> {
        vec![
            // KVM ioctls
            libc::SYS_ioctl as i32,
            // Memory management
            libc::SYS_mmap as i32,
            libc::SYS_munmap as i32,
            libc::SYS_madvise as i32,
            libc::SYS_mprotect as i32,
            libc::SYS_brk as i32,
            libc::SYS_mremap as i32,
            // File I/O
            libc::SYS_read as i32,
            libc::SYS_write as i32,
            libc::SYS_openat as i32,
            libc::SYS_close as i32,
            libc::SYS_fstat as i32,
            libc::SYS_newfstatat as i32,
            libc::SYS_lseek as i32,
            libc::SYS_pread64 as i32,
            libc::SYS_pwrite64 as i32,
            libc::SYS_readv as i32,
            libc::SYS_writev as i32,
            libc::SYS_fcntl as i32,
            libc::SYS_statx as i32,
            libc::SYS_getrandom as i32,
            // Socket
            libc::SYS_socket as i32,
            libc::SYS_bind as i32,
            libc::SYS_listen as i32,
            libc::SYS_accept4 as i32,
            libc::SYS_connect as i32,
            libc::SYS_sendto as i32,
            libc::SYS_recvfrom as i32,
            libc::SYS_sendmsg as i32,
            libc::SYS_recvmsg as i32,
            libc::SYS_getsockopt as i32,
            libc::SYS_setsockopt as i32,
            libc::SYS_getsockname as i32,
            libc::SYS_getpeername as i32,
            libc::SYS_shutdown as i32,
            // Process / scheduling
            libc::SYS_exit as i32,
            libc::SYS_exit_group as i32,
            libc::SYS_futex as i32,
            libc::SYS_clock_gettime as i32,
            libc::SYS_clock_getres as i32,
            libc::SYS_nanosleep as i32,
            libc::SYS_sched_yield as i32,
            libc::SYS_getpid as i32,
            libc::SYS_gettid as i32,
            libc::SYS_tgkill as i32,
            libc::SYS_set_robust_list as i32,
            libc::SYS_get_robust_list as i32,
            libc::SYS_prctl as i32,
            libc::SYS_arch_prctl as i32,
            libc::SYS_clone as i32,
            libc::SYS_clone3 as i32,
            libc::SYS_wait4 as i32,
            // Epoll
            libc::SYS_epoll_create1 as i32,
            libc::SYS_epoll_ctl as i32,
            libc::SYS_epoll_wait as i32,
            libc::SYS_epoll_pwait as i32,
            libc::SYS_poll as i32,
            libc::SYS_eventfd2 as i32,
            libc::SYS_timerfd_create as i32,
            libc::SYS_timerfd_settime as i32,
            libc::SYS_timerfd_gettime as i32,
            libc::SYS_pipe2 as i32,
            libc::SYS_dup as i32,
            libc::SYS_dup3 as i32,
            // Signal
            libc::SYS_rt_sigaction as i32,
            libc::SYS_rt_sigprocmask as i32,
            libc::SYS_rt_sigreturn as i32,
            libc::SYS_sigaltstack as i32,
            // Misc needed by tokio / Rust runtime
            libc::SYS_rseq as i32,
            libc::SYS_set_tid_address as i32,
            libc::SYS_getuid as i32,
            libc::SYS_getgid as i32,
            libc::SYS_geteuid as i32,
            libc::SYS_getegid as i32,
            libc::SYS_uname as i32,
            libc::SYS_getcwd as i32,
            libc::SYS_chdir as i32,
        ]
    }
}

// ---------------------------------------------------------------------------
// BPF filter construction (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod bpf {
    //! Build a seccomp-bpf program manually using sock_filter instructions.
    //!
    //! The filter checks the syscall number (seccomp_data.nr, offset 0)
    //! against the allowlist, returning SECCOMP_RET_ALLOW for matches and
    //! SECCOMP_RET_KILL_THREAD for everything else.

    /// BPF instruction — mirrors `struct sock_filter` from <linux/filter.h>.
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct SockFilter {
        pub code: u16,
        pub jt: u8,
        pub jf: u8,
        pub k: u32,
    }

    /// BPF program header — mirrors `struct sock_fprog`.
    #[repr(C)]
    pub struct SockFprog {
        pub len: u16,
        pub filter: *const SockFilter,
    }

    // BPF instruction classes and modes
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_RET: u16 = 0x06;
    const BPF_K: u16 = 0x00;

    // Seccomp return values
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;

    // Offset of `nr` in `struct seccomp_data` (the syscall number).
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;

    fn bpf_stmt(code: u16, k: u32) -> SockFilter {
        SockFilter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    /// Build a BPF filter program for the given allowed syscall numbers.
    ///
    /// Structure:
    ///   LD  seccomp_data.nr
    ///   JEQ allowed[0] -> ALLOW
    ///   JEQ allowed[1] -> ALLOW
    ///   ...
    ///   RET KILL
    ///   RET ALLOW
    pub fn build_filter(allowed: &[i32]) -> Vec<SockFilter> {
        let n = allowed.len();
        // Total instructions: 1 (LD) + n (JEQ) + 1 (RET KILL) + 1 (RET ALLOW)
        let mut prog = Vec::with_capacity(n + 3);

        // Load syscall number
        prog.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

        // For each allowed syscall, jump to ALLOW if match.
        // The ALLOW instruction is at the end: index = 1 + n + 1 = n + 2
        // KILL is at index = 1 + n
        // Current instruction index for allowed[i] is 1 + i
        // jt (match) should jump to ALLOW: distance = (n + 2) - (1 + i) - 1 = n - i
        // jf (no match) should fall through: 0
        for (i, &syscall_nr) in allowed.iter().enumerate() {
            let jt = (n - i) as u8; // jump forward to RET ALLOW
            prog.push(bpf_jump(
                BPF_JMP | BPF_JEQ | BPF_K,
                syscall_nr as u32,
                jt,
                0,
            ));
        }

        // Default: kill
        prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_THREAD));
        // Allow target
        prog.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

        prog
    }

    /// Install the BPF filter via prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER).
    pub fn install_filter(filter: &[SockFilter]) -> std::io::Result<()> {
        let prog = SockFprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };

        // First: allow the process to install seccomp without being root
        // PR_SET_NO_NEW_PRIVS must be set before SECCOMP_MODE_FILTER.
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let ret = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const SockFprog,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Install the seccomp BPF filter for the VMM process.
///
/// On Linux this builds and installs the filter. On other platforms it is a no-op.
pub fn apply_seccomp_filter(policy: &SeccompPolicy) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        tracing::info!(
            allowed_syscalls = policy.allowed.len(),
            "Installing seccomp BPF filter"
        );
        let filter = bpf::build_filter(&policy.allowed);
        bpf::install_filter(&filter)
            .map_err(|e| anyhow::anyhow!("Failed to install seccomp filter: {e}"))?;
        tracing::info!("Seccomp filter installed");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        tracing::warn!("Seccomp not available on this platform — skipping");
    }
    Ok(())
}

/// Full jail setup: namespaces, chroot, capabilities, seccomp, rlimits.
///
/// This should be called early in the VMM process lifetime, before any
/// untrusted guest interaction.
pub fn apply_jail(chroot_dir: &str, policy: &SeccompPolicy) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        apply_jail_linux(chroot_dir, policy)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (chroot_dir, policy);
        tracing::warn!("Jail not available on this platform — skipping");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn apply_jail_linux(chroot_dir: &str, policy: &SeccompPolicy) -> Result<()> {
    use std::ffi::CString;

    tracing::info!(chroot = chroot_dir, "Applying jail");

    // 1. Create new namespaces (mount, pid, net)
    let unshare_flags = libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWNET;
    let ret = unsafe { libc::unshare(unshare_flags) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "unshare failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    tracing::info!("Created new namespaces (mount, pid, net)");

    // 2. Chroot to minimal directory
    let c_dir = CString::new(chroot_dir)
        .map_err(|e| anyhow::anyhow!("Invalid chroot path: {e}"))?;
    let ret = unsafe { libc::chroot(c_dir.as_ptr()) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "chroot failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let ret = unsafe { libc::chdir(b"/\0".as_ptr() as *const libc::c_char) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "chdir failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    tracing::info!("Chrooted to {chroot_dir}");

    // 3. Drop all capabilities
    drop_capabilities()?;

    // 4. Set resource limits
    set_rlimits()?;

    // 5. Apply seccomp filter (must be last — once active, only allowed
    //    syscalls work, so setup must be complete)
    apply_seccomp_filter(policy)?;

    tracing::info!("Jail fully applied");
    Ok(())
}

#[cfg(target_os = "linux")]
fn drop_capabilities() -> Result<()> {
    // Drop all capabilities by setting the bounding set to empty.
    // PR_CAPBSET_DROP = 24, capabilities 0..=40 covers current kernel range.
    for cap in 0..=40i32 {
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        // EINVAL means the capability doesn't exist — that's fine.
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(anyhow::anyhow!("PR_CAPBSET_DROP({cap}) failed: {err}"));
            }
        }
    }
    tracing::info!("Dropped all capabilities");
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_rlimits() -> Result<()> {
    // Limit number of open file descriptors
    let nofile = libc::rlimit {
        rlim_cur: 1024,
        rlim_max: 1024,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &nofile) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "setrlimit(NOFILE) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Limit core dump size to 0
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "setrlimit(CORE) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Limit number of processes (prevent fork bombs from jailed VMM)
    let nproc = libc::rlimit {
        rlim_cur: 64,
        rlim_max: 64,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &nproc) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "setrlimit(NPROC) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    tracing::info!("Resource limits set (nofile=1024, core=0, nproc=64)");
    Ok(())
}
