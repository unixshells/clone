//! Kernel-ABI compatibility shims (`sys`).
//!
//! glibc's `ioctl` request is `c_ulong`; musl's `libc` crate types it
//! `c_int` (fixed 3-arg ABI), and a few wrappers (`renameat2`, `iopl`) are
//! absent from the musl or arm builds of `libc`. Every direct libc call in
//! this crate routes through here so one file owns the ABI knowledge.

use libc::c_int;

/// `ioctl(2)` with the request passed as the raw Linux u64 command value
/// and the argument coerced to its exact vararg slot (register-wide).
#[inline]
pub unsafe fn ioctl(fd: c_int, request: u64, arg: *mut libc::c_void) -> c_int {
    #[cfg(target_env = "musl")]
    let req = request as libc::c_int;
    #[cfg(not(target_env = "musl"))]
    let req = request as libc::c_ulong;
    libc::ioctl(fd, req, arg)
}

/// `renameat2(2)` — glibc wrapper only in `libc`; musl via raw syscall.
#[inline]
pub unsafe fn renameat2(
    olddirfd: c_int,
    oldpath: *const libc::c_char,
    newdirfd: c_int,
    newpath: *const libc::c_char,
    flags: libc::c_uint,
) -> c_int {
    #[cfg(target_env = "musl")]
    {
        libc::syscall(
            libc::SYS_renameat2,
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
        ) as c_int
    }
    #[cfg(not(target_env = "musl"))]
    {
        libc::renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
    }
}

/// `iopl(2)` — x86-only privileged I/O-port level; unavailable (and
/// meaningless) elsewhere.
#[inline]
pub unsafe fn iopl(level: libc::c_int) -> libc::c_int {
    #[cfg(target_arch = "x86_64")]
    {
        libc::syscall(libc::SYS_iopl, level) as libc::c_int
    }
    #[cfg(target_arch = "x86")]
    {
        libc::syscall(172, level) as libc::c_int // SYS_iopl on i386
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = level;
        -libc::ENOSYS
    }
}

/// Value-arg ioctl: integer `arg` passed in the register slot verbatim.
#[inline]
pub unsafe fn ioctl_value(fd: c_int, request: u64, value: u64) -> c_int {
    ioctl(fd, request, value as *mut libc::c_void)
}
