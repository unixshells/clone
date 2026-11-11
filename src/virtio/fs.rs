//! Virtio-fs device (VIRTIO_ID_FS = 26).
//!
//! Implements a virtio-fs device that translates FUSE protocol requests from
//! the guest into host filesystem operations. No external FUSE library —
//! the FUSE binary protocol is implemented directly.
//!
//! The guest mounts with: `mount -t virtiofs <tag> /mnt`
//!
//! Queues:
//!   0 — hiprio (for FORGET requests, processed normally)
//!   1 — request (all other FUSE operations)

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use super::queue::{DescriptorChain, Virtqueue, VRING_DESC_F_WRITE};
use super::{DeviceType, VirtioDevice};

/// Maximum virtqueue size.
const QUEUE_MAX_SIZE: u16 = 256;

/// Root inode number (matches FUSE convention).
const FUSE_ROOT_ID: u64 = 1;

// FUSE opcodes (from linux/fuse.h)
const FUSE_LOOKUP: u32 = 1;
const FUSE_FORGET: u32 = 2;
const FUSE_GETATTR: u32 = 3;
const FUSE_SETATTR: u32 = 4;
const FUSE_READLINK: u32 = 5;
const FUSE_SYMLINK: u32 = 6;
const FUSE_MKNOD: u32 = 8;
const FUSE_MKDIR: u32 = 9;
const FUSE_UNLINK: u32 = 10;
const FUSE_RMDIR: u32 = 11;
const FUSE_RENAME: u32 = 12;
const FUSE_LINK: u32 = 13;
const FUSE_OPEN: u32 = 14;
const FUSE_READ: u32 = 15;
const FUSE_WRITE: u32 = 16;
const FUSE_STATFS: u32 = 17;
const FUSE_RELEASE: u32 = 18;
const FUSE_FSYNC: u32 = 20;
const FUSE_SETXATTR: u32 = 21;
const FUSE_GETXATTR: u32 = 22;
const FUSE_LISTXATTR: u32 = 23;
const FUSE_REMOVEXATTR: u32 = 24;
const FUSE_FLUSH: u32 = 25;
const FUSE_INIT: u32 = 26;
const FUSE_OPENDIR: u32 = 27;
const FUSE_READDIR: u32 = 28;
const FUSE_RELEASEDIR: u32 = 29;
const FUSE_FSYNCDIR: u32 = 30;
const FUSE_ACCESS: u32 = 34;
const FUSE_CREATE: u32 = 35;
const FUSE_BATCH_FORGET: u32 = 42;
const FUSE_FALLOCATE: u32 = 43;
const FUSE_READDIRPLUS: u32 = 44;
const FUSE_RENAME2: u32 = 45;
const FUSE_LSEEK: u32 = 46;
const FUSE_SYNCFS: u32 = 50;

// FUSE INIT flags
const FUSE_DO_READDIRPLUS: u32 = 1 << 13;

// --- FUSE protocol structures (matching Linux kernel layout) ---

/// FUSE request header (40 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseInHeader {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    _padding: u32,
}

/// FUSE response header (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseOutHeader {
    len: u32,
    error: i32,
    unique: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseInitIn {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseInitOut {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    max_background: u16,
    congestion_threshold: u16,
    max_write: u32,
    time_gran: u32,
    max_pages: u16,
    map_alignment: u16,
    flags2: u32,
    _unused: [u32; 7],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseAttr {
    ino: u64,
    size: u64,
    blocks: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseEntryOut {
    nodeid: u64,
    generation: u64,
    entry_valid: u64,
    attr_valid: u64,
    entry_valid_nsec: u32,
    attr_valid_nsec: u32,
    attr: FuseAttr,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseAttrOut {
    attr_valid: u64,
    attr_valid_nsec: u32,
    _dummy: u32,
    attr: FuseAttr,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseOpenOut {
    fh: u64,
    open_flags: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseOpenIn {
    flags: u32,
    open_flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseReadIn {
    fh: u64,
    offset: u64,
    size: u32,
    read_flags: u32,
    lock_owner: u64,
    flags: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseWriteIn {
    fh: u64,
    offset: u64,
    size: u32,
    write_flags: u32,
    lock_owner: u64,
    flags: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseWriteOut {
    size: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseMkdirIn {
    mode: u32,
    umask: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseSetAttrIn {
    valid: u32,
    _padding: u32,
    fh: u64,
    size: u64,
    lock_owner: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    _unused4: u32,
    uid: u32,
    gid: u32,
    _unused5: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseCreateIn {
    flags: u32,
    mode: u32,
    umask: u32,
    open_flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseRenameIn {
    newdir: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseRename2In {
    newdir: u64,
    flags: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseMknodIn {
    mode: u32,
    rdev: u32,
    umask: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseLinkIn {
    oldnodeid: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseGetxattrIn {
    size: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseGetxattrOut {
    size: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseSetxattrIn {
    size: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseAccessIn {
    mask: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseFallocateIn {
    fh: u64,
    offset: u64,
    length: u64,
    mode: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseLseekIn {
    fh: u64,
    offset: u64,
    whence: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseLseekOut {
    offset: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseBatchForgetIn {
    count: u32,
    _dummy: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseForgetOne {
    nodeid: u64,
    nlookup: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseStatfsOut {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
    namelen: u32,
    frsize: u32,
    _padding: u32,
    _spare: [u32; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FuseDirent {
    ino: u64,
    off: u64,
    namelen: u32,
    type_: u32,
    // name follows (padded to 8-byte boundary)
}

// SETATTR valid bits
const FATTR_MODE: u32 = 1 << 0;
const FATTR_UID: u32 = 1 << 1;
const FATTR_GID: u32 = 1 << 2;
const FATTR_SIZE: u32 = 1 << 3;

// Helper to align to 8 bytes (FUSE dirent padding)
fn fuse_dirent_align(x: usize) -> usize {
    (x + 7) & !7
}

// --- Inode map ---

/// File handle state for open files/directories.
enum FuseFileHandle {
    File(std::fs::File),
    Dir(PathBuf),
}

/// Maps inodes to host paths and manages file handles.
struct InodeMap {
    next_inode: u64,
    next_fh: u64,
    inodes: HashMap<u64, PathBuf>,
    handles: HashMap<u64, FuseFileHandle>,
}

impl InodeMap {
    fn new(root_dir: &PathBuf) -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(FUSE_ROOT_ID, root_dir.clone());
        Self {
            next_inode: 2,
            next_fh: 1,
            inodes,
            handles: HashMap::new(),
        }
    }

    fn get_path(&self, inode: u64) -> Option<&PathBuf> {
        self.inodes.get(&inode)
    }

    fn lookup_or_insert(&mut self, path: PathBuf) -> u64 {
        // Check if path already has an inode
        for (&ino, p) in &self.inodes {
            if p == &path {
                return ino;
            }
        }
        let ino = self.next_inode;
        self.next_inode += 1;
        self.inodes.insert(ino, path);
        ino
    }

    fn open_file(&mut self, file: std::fs::File) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, FuseFileHandle::File(file));
        fh
    }

    fn open_dir(&mut self, path: PathBuf) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(fh, FuseFileHandle::Dir(path));
        fh
    }

    fn get_file(&mut self, fh: u64) -> Option<&mut std::fs::File> {
        match self.handles.get_mut(&fh) {
            Some(FuseFileHandle::File(f)) => Some(f),
            _ => None,
        }
    }

    fn get_dir(&self, fh: u64) -> Option<&PathBuf> {
        match self.handles.get(&fh) {
            Some(FuseFileHandle::Dir(p)) => Some(p),
            _ => None,
        }
    }

    fn rename_path(&mut self, old_path: &PathBuf, new_path: &PathBuf) {
        let mut ino_to_update = None;
        for (&ino, path) in &self.inodes {
            if path == old_path {
                ino_to_update = Some(ino);
                break;
            }
        }
        if let Some(ino) = ino_to_update {
            self.inodes.insert(ino, new_path.clone());
        }
    }

    fn release(&mut self, fh: u64) {
        self.handles.remove(&fh);
    }
}

// --- VirtioFs device ---

/// Virtio-fs device that shares a host directory with the guest.
pub struct VirtioFs {
    /// Mount tag visible to the guest (max 36 bytes).
    tag: String,
    /// Host directory to share.
    root_dir: PathBuf,
    /// Inode/file handle mapping.
    inode_map: InodeMap,
    /// Acknowledged feature bits.
    acked_features: [u32; 2],
    /// Whether the device has been activated.
    activated: bool,
}

impl VirtioFs {
    /// Replace the backing directory. Used after fork to swap the template's
    /// dummy directory for the user's actual home directory.
    pub fn set_root_dir(&mut self, root_dir: PathBuf) {
        self.root_dir = root_dir.clone();
        self.inode_map = InodeMap::new(&root_dir);
        tracing::info!(root = %root_dir.display(), "virtio-fs: root directory replaced");
    }

    /// Create a new virtio-fs device sharing `root_dir` with the given mount tag.
    pub fn new(root_dir: PathBuf, tag: String) -> Self {
        let inode_map = InodeMap::new(&root_dir);
        Self {
            tag,
            root_dir,
            inode_map,
            acked_features: [0; 2],
            activated: false,
        }
    }

    /// Process a FUSE request and return the response bytes.
    fn handle_fuse_request(&mut self, request: &[u8]) -> Vec<u8> {
        if request.len() < std::mem::size_of::<FuseInHeader>() {
            return self.make_error_response(0, -libc::EINVAL);
        }

        let header = unsafe { &*(request.as_ptr() as *const FuseInHeader) };
        let body = &request[std::mem::size_of::<FuseInHeader>()..];

        // eprintln!("DBG: FUSE opcode={} unique={} nodeid={} len={}", header.opcode, header.unique, header.nodeid, header.len);

        match header.opcode {
            FUSE_INIT => self.handle_init(header, body),
            FUSE_LOOKUP => self.handle_lookup(header, body),
            FUSE_GETATTR => self.handle_getattr(header),
            FUSE_SETATTR => self.handle_setattr(header, body),
            FUSE_OPEN => self.handle_open(header, body),
            FUSE_READ => self.handle_read(header, body),
            FUSE_WRITE => self.handle_write(header, body),
            FUSE_RELEASE => self.handle_release(header, body),
            FUSE_OPENDIR => self.handle_opendir(header),
            FUSE_READDIR => self.handle_readdir(header, body, false),
            FUSE_READDIRPLUS => self.handle_readdir(header, body, true),
            FUSE_RELEASEDIR => self.handle_release(header, body),
            FUSE_CREATE => self.handle_create(header, body),
            FUSE_MKDIR => self.handle_mkdir(header, body),
            FUSE_UNLINK => self.handle_unlink(header, body),
            FUSE_RMDIR => self.handle_rmdir(header, body),
            FUSE_RENAME => self.handle_rename(header, body),
            FUSE_RENAME2 => self.handle_rename2(header, body),
            FUSE_STATFS => self.handle_statfs(header),
            FUSE_FLUSH | FUSE_FSYNC | FUSE_FSYNCDIR | FUSE_SYNCFS => self.handle_flush(header),
            FUSE_FORGET => {
                Vec::new()
            }
            FUSE_BATCH_FORGET => {
                // No response needed for batch forget
                Vec::new()
            }
            FUSE_READLINK => self.handle_readlink(header),
            FUSE_SYMLINK => self.handle_symlink(header, body),
            FUSE_MKNOD => self.handle_mknod(header, body),
            FUSE_LINK => self.handle_link(header, body),
            FUSE_GETXATTR => self.handle_getxattr(header, body),
            FUSE_SETXATTR => self.handle_setxattr(header, body),
            FUSE_LISTXATTR => self.handle_listxattr(header, body),
            FUSE_REMOVEXATTR => self.handle_removexattr(header, body),
            FUSE_ACCESS => self.handle_access(header, body),
            FUSE_FALLOCATE => self.handle_fallocate(header, body),
            FUSE_LSEEK => self.handle_lseek(header, body),
            _ => {
                tracing::debug!("Unhandled FUSE opcode: {}", header.opcode);
                self.make_error_response(header.unique, -libc::ENOSYS)
            }
        }
    }

    fn make_error_response(&self, unique: u64, error: i32) -> Vec<u8> {
        let header = FuseOutHeader {
            len: std::mem::size_of::<FuseOutHeader>() as u32,
            error,
            unique,
        };
        unsafe { as_bytes(&header).to_vec() }
    }

    fn make_response<T: Sized>(&self, unique: u64, body: &T) -> Vec<u8> {
        let hdr_size = std::mem::size_of::<FuseOutHeader>();
        let body_size = std::mem::size_of::<T>();
        let total = hdr_size + body_size;

        let header = FuseOutHeader {
            len: total as u32,
            error: 0,
            unique,
        };

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(unsafe { as_bytes(&header) });
        out.extend_from_slice(unsafe { as_bytes(body) });
        out
    }

    fn make_response_with_data<T: Sized>(&self, unique: u64, body: &T, data: &[u8]) -> Vec<u8> {
        let hdr_size = std::mem::size_of::<FuseOutHeader>();
        let body_size = std::mem::size_of::<T>();
        let total = hdr_size + body_size + data.len();

        let header = FuseOutHeader {
            len: total as u32,
            error: 0,
            unique,
        };

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(unsafe { as_bytes(&header) });
        out.extend_from_slice(unsafe { as_bytes(body) });
        out.extend_from_slice(data);
        out
    }

    fn handle_init(&self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseInitIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }

        let init_out = FuseInitOut {
            major: 7,
            minor: 31,
            max_readahead: 131072,
            flags: FUSE_DO_READDIRPLUS,
            max_background: 16,
            congestion_threshold: 12,
            max_write: 131072,
            time_gran: 1,
            max_pages: 32,
            map_alignment: 0,
            flags2: 0,
            _unused: [0; 7],
        };

        self.make_response(header.unique, &init_out)
    }

    fn handle_lookup(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        let name = match cstr_from_bytes(body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let parent_path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let child_path = parent_path.join(name);
        let metadata = match std::fs::symlink_metadata(&child_path) {
            Ok(m) => m,
            Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
        };

        let ino = self.inode_map.lookup_or_insert(child_path);
        let attr = metadata_to_fuse_attr(ino, &metadata);

        let entry = FuseEntryOut {
            nodeid: ino,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr,
        };

        self.make_response(header.unique, &entry)
    }

    fn handle_getattr(&self, header: &FuseInHeader) -> Vec<u8> {
        let path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
        };

        let attr = metadata_to_fuse_attr(header.nodeid, &metadata);
        let attr_out = FuseAttrOut {
            attr_valid: 1,
            attr_valid_nsec: 0,
            _dummy: 0,
            attr,
        };

        self.make_response(header.unique, &attr_out)
    }

    fn handle_setattr(&self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseSetAttrIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let setattr = unsafe { &*(body.as_ptr() as *const FuseSetAttrIn) };

        let path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        // Handle truncate
        if setattr.valid & FATTR_SIZE != 0 {
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&path) {
                let _ = f.set_len(setattr.size);
            }
        }

        // Handle chmod
        if setattr.valid & FATTR_MODE != 0 {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(setattr.mode);
            let _ = std::fs::set_permissions(&path, perms);
        }

        // Handle chown (lchown so symlinks aren't followed)
        if setattr.valid & (FATTR_UID | FATTR_GID) != 0 {
            let uid = if setattr.valid & FATTR_UID != 0 { setattr.uid } else { u32::MAX };
            let gid = if setattr.valid & FATTR_GID != 0 { setattr.gid } else { u32::MAX };
            unsafe {
                let c_path = std::ffi::CString::new(path.to_str().unwrap_or("")).unwrap_or_default();
                libc::lchown(c_path.as_ptr(), uid, gid);
            }
        }

        // Return updated attributes
        self.handle_getattr(header)
    }

    fn handle_open(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseOpenIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let open_in = unsafe { &*(body.as_ptr() as *const FuseOpenIn) };

        let path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let flags = open_in.flags as i32;
        let mut opts = std::fs::OpenOptions::new();

        // Map O_RDONLY, O_WRONLY, O_RDWR
        let access = flags & libc::O_ACCMODE;
        if access == libc::O_RDONLY {
            opts.read(true);
        } else if access == libc::O_WRONLY {
            opts.write(true);
        } else {
            opts.read(true).write(true);
        }

        if flags & libc::O_APPEND != 0 {
            opts.append(true);
        }
        if flags & libc::O_TRUNC != 0 {
            opts.truncate(true);
        }

        match opts.open(&path) {
            Ok(file) => {
                let fh = self.inode_map.open_file(file);
                let open_out = FuseOpenOut {
                    fh,
                    open_flags: 0,
                    _padding: 0,
                };
                self.make_response(header.unique, &open_out)
            }
            Err(e) => self.make_error_response(header.unique, -errno_from_io(&e)),
        }
    }

    fn handle_read(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseReadIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let read_in = unsafe { &*(body.as_ptr() as *const FuseReadIn) };

        let file = match self.inode_map.get_file(read_in.fh) {
            Some(f) => f,
            None => return self.make_error_response(header.unique, -libc::EBADF),
        };

        use std::io::{Read, Seek, SeekFrom};
        if let Err(e) = file.seek(SeekFrom::Start(read_in.offset)) {
            return self.make_error_response(header.unique, -errno_from_io(&e));
        }

        let size = read_in.size as usize;
        let mut buf = vec![0u8; size];
        match file.read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                // Response: header + data (no body struct for read)
                let hdr_size = std::mem::size_of::<FuseOutHeader>();
                let total = hdr_size + n;
                let out_header = FuseOutHeader {
                    len: total as u32,
                    error: 0,
                    unique: header.unique,
                };
                let mut out = Vec::with_capacity(total);
                out.extend_from_slice(unsafe { as_bytes(&out_header) });
                out.extend_from_slice(&buf);
                out
            }
            Err(e) => self.make_error_response(header.unique, -errno_from_io(&e)),
        }
    }

    fn handle_write(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseWriteIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let write_in = unsafe { &*(body.as_ptr() as *const FuseWriteIn) };
        let write_data = &body[std::mem::size_of::<FuseWriteIn>()..];

        let file = match self.inode_map.get_file(write_in.fh) {
            Some(f) => f,
            None => return self.make_error_response(header.unique, -libc::EBADF),
        };

        use std::io::{Seek, SeekFrom, Write};
        if let Err(e) = file.seek(SeekFrom::Start(write_in.offset)) {
            return self.make_error_response(header.unique, -errno_from_io(&e));
        }

        let to_write = std::cmp::min(write_data.len(), write_in.size as usize);
        match file.write(&write_data[..to_write]) {
            Ok(n) => {
                let write_out = FuseWriteOut {
                    size: n as u32,
                    _padding: 0,
                };
                self.make_response(header.unique, &write_out)
            }
            Err(e) => self.make_error_response(header.unique, -errno_from_io(&e)),
        }
    }

    fn handle_release(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        // Release request has fh at offset 0
        if body.len() >= 8 {
            let fh = u64::from_le_bytes(body[0..8].try_into().unwrap());
            self.inode_map.release(fh);
        }
        self.make_error_response(header.unique, 0) // success = error 0
    }

    fn handle_opendir(&mut self, header: &FuseInHeader) -> Vec<u8> {
        let path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        // Verify it's a directory
        match std::fs::metadata(&path) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return self.make_error_response(header.unique, -libc::ENOTDIR),
            Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
        }

        let fh = self.inode_map.open_dir(path);
        let open_out = FuseOpenOut {
            fh,
            open_flags: 0,
            _padding: 0,
        };
        self.make_response(header.unique, &open_out)
    }

    fn handle_readdir(&mut self, header: &FuseInHeader, body: &[u8], plus: bool) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseReadIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let read_in = unsafe { &*(body.as_ptr() as *const FuseReadIn) };

        let dir_path = match self.inode_map.get_dir(read_in.fh) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::EBADF),
        };

        let entries = match std::fs::read_dir(&dir_path) {
            Ok(e) => e,
            Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
        };

        let max_size = read_in.size as usize;
        let offset = read_in.offset as usize;
        let mut buf = Vec::with_capacity(max_size);

        // Collect all entries: (name, path_for_stat)
        let mut all: Vec<(String, PathBuf)> = Vec::new();
        all.push((".".to_string(), dir_path.clone()));
        // For "..", use dir parent or dir itself
        let parent = dir_path.parent().unwrap_or(&dir_path).to_path_buf();
        all.push(("..".to_string(), parent));

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let child_path = dir_path.join(&name);
            all.push((name, child_path));
        }

        let dirent_size = std::mem::size_of::<FuseDirent>();
        let entry_out_size = std::mem::size_of::<FuseEntryOut>();

        for (i, (name, path)) in all.iter().enumerate() {
            let entry_idx = i + 1; // 1-based offset
            if entry_idx <= offset {
                continue;
            }

            let name_bytes = name.as_bytes();
            let padded_name_len = fuse_dirent_align(name_bytes.len());
            let record_size = if plus {
                entry_out_size + dirent_size + padded_name_len
            } else {
                dirent_size + padded_name_len
            };

            if buf.len() + record_size > max_size {
                break;
            }

            let metadata = match std::fs::symlink_metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            let ino = self.inode_map.lookup_or_insert(path.clone());
            let ftype = if metadata.is_dir() {
                libc::DT_DIR as u32
            } else if metadata.file_type().is_symlink() {
                libc::DT_LNK as u32
            } else {
                libc::DT_REG as u32
            };

            if plus {
                // READDIRPLUS: FuseEntryOut + FuseDirent + name
                let attr = metadata_to_fuse_attr(ino, &metadata);
                let entry_out = FuseEntryOut {
                    nodeid: ino,
                    generation: 0,
                    entry_valid: 1,
                    attr_valid: 1,
                    entry_valid_nsec: 0,
                    attr_valid_nsec: 0,
                    attr,
                };
                buf.extend_from_slice(unsafe { as_bytes(&entry_out) });
            }

            let dirent = FuseDirent {
                ino,
                off: entry_idx as u64,
                namelen: name_bytes.len() as u32,
                type_: ftype,
            };
            buf.extend_from_slice(unsafe { as_bytes(&dirent) });
            buf.extend_from_slice(name_bytes);
            let padding = padded_name_len - name_bytes.len();
            buf.extend(std::iter::repeat(0u8).take(padding));
        }

        let hdr_size = std::mem::size_of::<FuseOutHeader>();
        let total = hdr_size + buf.len();
        let out_header = FuseOutHeader {
            len: total as u32,
            error: 0,
            unique: header.unique,
        };
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(unsafe { as_bytes(&out_header) });
        out.extend_from_slice(&buf);
        out
    }

    fn handle_create(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseCreateIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let create_in = unsafe { &*(body.as_ptr() as *const FuseCreateIn) };
        let name_body = &body[std::mem::size_of::<FuseCreateIn>()..];

        let name = match cstr_from_bytes(name_body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let parent_path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let child_path = parent_path.join(name);

        use std::os::unix::fs::OpenOptionsExt;
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(create_in.flags & libc::O_TRUNC as u32 != 0)
            .mode(create_in.mode)
            .open(&child_path)
        {
            Ok(f) => f,
            Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
        };

        let metadata = match file.metadata() {
            Ok(m) => m,
            Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
        };

        chown_to_caller(&child_path, header.uid, header.gid);

        let ino = self.inode_map.lookup_or_insert(child_path);
        let attr = metadata_to_fuse_attr(ino, &metadata);
        let fh = self.inode_map.open_file(file);

        // Create response = FuseEntryOut + FuseOpenOut
        let entry = FuseEntryOut {
            nodeid: ino,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr,
        };
        let open_out = FuseOpenOut {
            fh,
            open_flags: 0,
            _padding: 0,
        };

        let hdr_size = std::mem::size_of::<FuseOutHeader>();
        let total = hdr_size + std::mem::size_of::<FuseEntryOut>() + std::mem::size_of::<FuseOpenOut>();
        let out_header = FuseOutHeader {
            len: total as u32,
            error: 0,
            unique: header.unique,
        };
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(unsafe { as_bytes(&out_header) });
        out.extend_from_slice(unsafe { as_bytes(&entry) });
        out.extend_from_slice(unsafe { as_bytes(&open_out) });
        out
    }

    fn handle_mkdir(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseMkdirIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let mkdir_in = unsafe { &*(body.as_ptr() as *const FuseMkdirIn) };
        let name_body = &body[std::mem::size_of::<FuseMkdirIn>()..];

        let name = match cstr_from_bytes(name_body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let parent_path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let child_path = parent_path.join(name);

        // Create directory with mode
        use std::os::unix::fs::DirBuilderExt;
        if let Err(e) = std::fs::DirBuilder::new()
            .mode(mkdir_in.mode)
            .create(&child_path)
        {
            return self.make_error_response(header.unique, -errno_from_io(&e));
        }

        chown_to_caller(&child_path, header.uid, header.gid);

        let metadata = match std::fs::symlink_metadata(&child_path) {
            Ok(m) => m,
            Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
        };

        let ino = self.inode_map.lookup_or_insert(child_path);
        let attr = metadata_to_fuse_attr(ino, &metadata);

        let entry = FuseEntryOut {
            nodeid: ino,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr,
        };

        self.make_response(header.unique, &entry)
    }

    fn handle_unlink(&self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        let name = match cstr_from_bytes(body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let parent_path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let child_path = parent_path.join(name);
        match std::fs::remove_file(&child_path) {
            Ok(()) => self.make_error_response(header.unique, 0),
            Err(e) => self.make_error_response(header.unique, -errno_from_io(&e)),
        }
    }

    fn handle_rmdir(&self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        let name = match cstr_from_bytes(body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let parent_path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let child_path = parent_path.join(name);
        match std::fs::remove_dir(&child_path) {
            Ok(()) => self.make_error_response(header.unique, 0),
            Err(e) => self.make_error_response(header.unique, -errno_from_io(&e)),
        }
    }

    fn handle_rename(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseRenameIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let rename_in = unsafe { &*(body.as_ptr() as *const FuseRenameIn) };
        let names_body = &body[std::mem::size_of::<FuseRenameIn>()..];

        // Old name is first null-terminated string, new name follows
        let old_name = match cstr_from_bytes(names_body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };
        let rest = &names_body[old_name.len() + 1..]; // skip name + null
        let new_name = match cstr_from_bytes(rest) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let old_parent = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };
        let new_parent = match self.inode_map.get_path(rename_in.newdir) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let old_path = old_parent.join(old_name);
        let new_path = new_parent.join(new_name);

        match std::fs::rename(&old_path, &new_path) {
            Ok(()) => {
                // Update inode map: the old path is now at new_path
                self.inode_map.rename_path(&old_path, &new_path);
                self.make_error_response(header.unique, 0)
            }
            Err(e) => self.make_error_response(header.unique, -errno_from_io(&e)),
        }
    }

    fn handle_statfs(&self, header: &FuseInHeader) -> Vec<u8> {
        #[cfg(target_os = "linux")]
        {
            let c_path = match std::ffi::CString::new(self.root_dir.to_str().unwrap_or("/")) {
                Ok(c) => c,
                Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
            };
            let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut buf) };
            if ret < 0 {
                return self.make_error_response(header.unique, -errno());
            }
            let statfs_out = FuseStatfsOut {
                blocks: buf.f_blocks,
                bfree: buf.f_bfree,
                bavail: buf.f_bavail,
                files: buf.f_files,
                ffree: buf.f_ffree,
                bsize: buf.f_bsize as u32,
                namelen: buf.f_namemax as u32,
                frsize: buf.f_frsize as u32,
                _padding: 0,
                _spare: [0; 6],
            };
            return self.make_response(header.unique, &statfs_out);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let statfs_out = FuseStatfsOut {
                blocks: 1024 * 1024, bfree: 512 * 1024, bavail: 512 * 1024,
                files: 1000000, ffree: 999000, bsize: 4096, namelen: 255,
                frsize: 4096, _padding: 0, _spare: [0; 6],
            };
            self.make_response(header.unique, &statfs_out)
        }
    }

    fn handle_flush(&self, header: &FuseInHeader) -> Vec<u8> {
        self.make_error_response(header.unique, 0)
    }

    fn handle_readlink(&self, header: &FuseInHeader) -> Vec<u8> {
        let path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        match std::fs::read_link(&path) {
            Ok(target) => {
                let target_bytes = target.to_string_lossy().into_owned().into_bytes();
                let hdr_size = std::mem::size_of::<FuseOutHeader>();
                let total = hdr_size + target_bytes.len();
                let out_header = FuseOutHeader {
                    len: total as u32,
                    error: 0,
                    unique: header.unique,
                };
                let mut out = Vec::with_capacity(total);
                out.extend_from_slice(unsafe { as_bytes(&out_header) });
                out.extend_from_slice(&target_bytes);
                out
            }
            Err(e) => self.make_error_response(header.unique, -errno_from_io(&e)),
        }
    }

    fn handle_symlink(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        // Body is: name\0target\0
        let name = match cstr_from_bytes(body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };
        let rest = &body[name.len() + 1..];
        let target = match cstr_from_bytes(rest) {
            Some(t) => t,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let parent_path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let link_path = parent_path.join(name);

        if let Err(e) = std::os::unix::fs::symlink(target, &link_path) {
            return self.make_error_response(header.unique, -errno_from_io(&e));
        }

        chown_to_caller(&link_path, header.uid, header.gid);

        let metadata = match std::fs::symlink_metadata(&link_path) {
            Ok(m) => m,
            Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
        };

        let ino = self.inode_map.lookup_or_insert(link_path);
        let attr = metadata_to_fuse_attr(ino, &metadata);

        let entry = FuseEntryOut {
            nodeid: ino,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr,
        };

        self.make_response(header.unique, &entry)
    }

    fn handle_mknod(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseMknodIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let mknod_in = unsafe { &*(body.as_ptr() as *const FuseMknodIn) };
        let name_body = &body[std::mem::size_of::<FuseMknodIn>()..];

        let name = match cstr_from_bytes(name_body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let parent_path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let child_path = parent_path.join(name);
        let mode = mknod_in.mode;

        // For regular files (S_IFREG) or mode 0 (default), create with File::create
        let file_type = mode & libc::S_IFMT as u32;
        if file_type == libc::S_IFREG as u32 || file_type == 0 {
            use std::os::unix::fs::OpenOptionsExt;
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode & 0o7777)
                .open(&child_path)
            {
                Ok(_) => {}
                Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
            }
        } else {
            // For other types (FIFO, socket, etc.), use libc::mknod
            #[cfg(target_os = "linux")]
            {
                let c_path = match std::ffi::CString::new(child_path.to_str().unwrap_or("")) {
                    Ok(c) => c,
                    Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
                };
                let ret = unsafe {
                    libc::mknod(c_path.as_ptr(), mode as libc::mode_t, mknod_in.rdev as libc::dev_t)
                };
                if ret < 0 {
                    return self.make_error_response(header.unique, -errno());
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                return self.make_error_response(header.unique, -libc::ENOSYS);
            }
        }

        chown_to_caller(&child_path, header.uid, header.gid);

        let metadata = match std::fs::symlink_metadata(&child_path) {
            Ok(m) => m,
            Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
        };

        let ino = self.inode_map.lookup_or_insert(child_path);
        let attr = metadata_to_fuse_attr(ino, &metadata);

        let entry = FuseEntryOut {
            nodeid: ino,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr,
        };

        self.make_response(header.unique, &entry)
    }

    fn handle_link(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseLinkIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let link_in = unsafe { &*(body.as_ptr() as *const FuseLinkIn) };
        let name_body = &body[std::mem::size_of::<FuseLinkIn>()..];

        let name = match cstr_from_bytes(name_body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let old_path = match self.inode_map.get_path(link_in.oldnodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let new_parent = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let new_path = new_parent.join(name);

        if let Err(e) = std::fs::hard_link(&old_path, &new_path) {
            return self.make_error_response(header.unique, -errno_from_io(&e));
        }

        let metadata = match std::fs::symlink_metadata(&new_path) {
            Ok(m) => m,
            Err(e) => return self.make_error_response(header.unique, -errno_from_io(&e)),
        };

        let ino = self.inode_map.lookup_or_insert(new_path);
        let attr = metadata_to_fuse_attr(ino, &metadata);

        let entry = FuseEntryOut {
            nodeid: ino,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr,
        };

        self.make_response(header.unique, &entry)
    }

    fn handle_getxattr(&self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseGetxattrIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let getxattr_in = unsafe { &*(body.as_ptr() as *const FuseGetxattrIn) };
        let name_body = &body[std::mem::size_of::<FuseGetxattrIn>()..];

        let name = match cstr_from_bytes(name_body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        #[cfg(target_os = "linux")]
        {
            let c_path = match std::ffi::CString::new(path.to_str().unwrap_or("")) {
                Ok(c) => c,
                Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
            };
            let c_name = match std::ffi::CString::new(name) {
                Ok(c) => c,
                Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
            };

            if getxattr_in.size == 0 {
                // Query the size needed
                let ret = unsafe {
                    libc::lgetxattr(
                        c_path.as_ptr(),
                        c_name.as_ptr(),
                        std::ptr::null_mut(),
                        0,
                    )
                };
                if ret < 0 {
                    return self.make_error_response(header.unique, -errno());
                }
                let out = FuseGetxattrOut {
                    size: ret as u32,
                    _padding: 0,
                };
                return self.make_response(header.unique, &out);
            }

            let mut buf = vec![0u8; getxattr_in.size as usize];
            let ret = unsafe {
                libc::lgetxattr(
                    c_path.as_ptr(),
                    c_name.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if ret < 0 {
                return self.make_error_response(header.unique, -errno());
            }
            buf.truncate(ret as usize);

            // Response: header + data
            let hdr_size = std::mem::size_of::<FuseOutHeader>();
            let total = hdr_size + buf.len();
            let out_header = FuseOutHeader {
                len: total as u32,
                error: 0,
                unique: header.unique,
            };
            let mut out = Vec::with_capacity(total);
            out.extend_from_slice(unsafe { as_bytes(&out_header) });
            out.extend_from_slice(&buf);
            out
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (getxattr_in, name, path);
            self.make_error_response(header.unique, -libc::ENODATA)
        }
    }

    fn handle_setxattr(&self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseSetxattrIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let setxattr_in = unsafe { &*(body.as_ptr() as *const FuseSetxattrIn) };
        let rest = &body[std::mem::size_of::<FuseSetxattrIn>()..];

        // rest is: name\0value (value is setxattr_in.size bytes)
        let name = match cstr_from_bytes(rest) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };
        let value_start = name.len() + 1;
        let value_end = value_start + setxattr_in.size as usize;
        if rest.len() < value_end {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let value = &rest[value_start..value_end];

        let path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        #[cfg(target_os = "linux")]
        {
            let c_path = match std::ffi::CString::new(path.to_str().unwrap_or("")) {
                Ok(c) => c,
                Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
            };
            let c_name = match std::ffi::CString::new(name) {
                Ok(c) => c,
                Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
            };

            let ret = unsafe {
                libc::lsetxattr(
                    c_path.as_ptr(),
                    c_name.as_ptr(),
                    value.as_ptr() as *const libc::c_void,
                    value.len(),
                    setxattr_in.flags as i32,
                )
            };
            if ret < 0 {
                return self.make_error_response(header.unique, -errno());
            }
            self.make_error_response(header.unique, 0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (value, path);
            self.make_error_response(header.unique, -libc::ENOSYS)
        }
    }

    fn handle_listxattr(&self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseGetxattrIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let getxattr_in = unsafe { &*(body.as_ptr() as *const FuseGetxattrIn) };

        let path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        #[cfg(target_os = "linux")]
        {
            let c_path = match std::ffi::CString::new(path.to_str().unwrap_or("")) {
                Ok(c) => c,
                Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
            };

            if getxattr_in.size == 0 {
                // Query the size needed
                let ret = unsafe {
                    libc::llistxattr(c_path.as_ptr(), std::ptr::null_mut(), 0)
                };
                if ret < 0 {
                    return self.make_error_response(header.unique, -errno());
                }
                let out = FuseGetxattrOut {
                    size: ret as u32,
                    _padding: 0,
                };
                return self.make_response(header.unique, &out);
            }

            let mut buf = vec![0u8; getxattr_in.size as usize];
            let ret = unsafe {
                libc::llistxattr(
                    c_path.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            };
            if ret < 0 {
                return self.make_error_response(header.unique, -errno());
            }
            buf.truncate(ret as usize);

            // Response: header + data
            let hdr_size = std::mem::size_of::<FuseOutHeader>();
            let total = hdr_size + buf.len();
            let out_header = FuseOutHeader {
                len: total as u32,
                error: 0,
                unique: header.unique,
            };
            let mut out = Vec::with_capacity(total);
            out.extend_from_slice(unsafe { as_bytes(&out_header) });
            out.extend_from_slice(&buf);
            out
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (getxattr_in, path);
            self.make_error_response(header.unique, -libc::ENODATA)
        }
    }

    fn handle_removexattr(&self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        let name = match cstr_from_bytes(body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        #[cfg(target_os = "linux")]
        {
            let c_path = match std::ffi::CString::new(path.to_str().unwrap_or("")) {
                Ok(c) => c,
                Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
            };
            let c_name = match std::ffi::CString::new(name) {
                Ok(c) => c,
                Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
            };

            let ret = unsafe { libc::lremovexattr(c_path.as_ptr(), c_name.as_ptr()) };
            if ret < 0 {
                return self.make_error_response(header.unique, -errno());
            }
            self.make_error_response(header.unique, 0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, path);
            self.make_error_response(header.unique, -libc::ENOSYS)
        }
    }

    fn handle_access(&self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseAccessIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let access_in = unsafe { &*(body.as_ptr() as *const FuseAccessIn) };

        let path = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let c_path = match std::ffi::CString::new(path.to_str().unwrap_or("")) {
            Ok(c) => c,
            Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let ret = unsafe { libc::access(c_path.as_ptr(), access_in.mask as i32) };
        if ret < 0 {
            return self.make_error_response(header.unique, -errno());
        }
        self.make_error_response(header.unique, 0)
    }

    fn handle_fallocate(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseFallocateIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let falloc_in = unsafe { &*(body.as_ptr() as *const FuseFallocateIn) };

        #[cfg(target_os = "linux")]
        {
            let file = match self.inode_map.get_file(falloc_in.fh) {
                Some(f) => f,
                None => return self.make_error_response(header.unique, -libc::EBADF),
            };

            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();

            let ret = unsafe {
                libc::fallocate(
                    fd,
                    falloc_in.mode as i32,
                    falloc_in.offset as libc::off_t,
                    falloc_in.length as libc::off_t,
                )
            };
            if ret < 0 {
                return self.make_error_response(header.unique, -errno());
            }
            self.make_error_response(header.unique, 0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = falloc_in;
            self.make_error_response(header.unique, -libc::ENOSYS)
        }
    }

    fn handle_lseek(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseLseekIn>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let lseek_in = unsafe { &*(body.as_ptr() as *const FuseLseekIn) };

        let file = match self.inode_map.get_file(lseek_in.fh) {
            Some(f) => f,
            None => return self.make_error_response(header.unique, -libc::EBADF),
        };

        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();

        let ret = unsafe {
            libc::lseek(fd, lseek_in.offset as libc::off_t, lseek_in.whence as i32)
        };
        if ret < 0 {
            return self.make_error_response(header.unique, -errno());
        }

        let out = FuseLseekOut {
            offset: ret as u64,
        };
        self.make_response(header.unique, &out)
    }

    fn handle_rename2(&mut self, header: &FuseInHeader, body: &[u8]) -> Vec<u8> {
        if body.len() < std::mem::size_of::<FuseRename2In>() {
            return self.make_error_response(header.unique, -libc::EINVAL);
        }
        let rename2_in = unsafe { &*(body.as_ptr() as *const FuseRename2In) };
        let names_body = &body[std::mem::size_of::<FuseRename2In>()..];

        let old_name = match cstr_from_bytes(names_body) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };
        let rest = &names_body[old_name.len() + 1..];
        let new_name = match cstr_from_bytes(rest) {
            Some(n) => n,
            None => return self.make_error_response(header.unique, -libc::EINVAL),
        };

        let old_parent = match self.inode_map.get_path(header.nodeid) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };
        let new_parent = match self.inode_map.get_path(rename2_in.newdir) {
            Some(p) => p.clone(),
            None => return self.make_error_response(header.unique, -libc::ENOENT),
        };

        let old_path = old_parent.join(old_name);
        let new_path = new_parent.join(new_name);

        // RENAME_NOREPLACE (1 << 0) — fail if target exists
        #[cfg(target_os = "linux")]
        {
            let flags = rename2_in.flags;
            if flags != 0 {
                // Use renameat2 for flags support
                let c_old = match std::ffi::CString::new(old_path.to_str().unwrap_or("")) {
                    Ok(c) => c,
                    Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
                };
                let c_new = match std::ffi::CString::new(new_path.to_str().unwrap_or("")) {
                    Ok(c) => c,
                    Err(_) => return self.make_error_response(header.unique, -libc::EINVAL),
                };
                let ret = unsafe {
                    crate::sys::renameat2(
                        libc::AT_FDCWD,
                        c_old.as_ptr(),
                        libc::AT_FDCWD,
                        c_new.as_ptr(),
                        flags,
                    )
                };
                if ret < 0 {
                    return self.make_error_response(header.unique, -errno());
                }
                self.inode_map.rename_path(&old_path, &new_path);
                return self.make_error_response(header.unique, 0);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = rename2_in;
        }

        match std::fs::rename(&old_path, &new_path) {
            Ok(()) => {
                self.inode_map.rename_path(&old_path, &new_path);
                self.make_error_response(header.unique, 0)
            }
            Err(e) => self.make_error_response(header.unique, -errno_from_io(&e)),
        }
    }
}

// --- VirtioDevice trait impl ---

impl VirtioDevice for VirtioFs {
    fn device_type(&self) -> DeviceType {
        DeviceType::Fs
    }

    fn queue_max_sizes(&self) -> &[u16] {
        // Queue 0 = hiprio, Queue 1 = request
        &[QUEUE_MAX_SIZE, QUEUE_MAX_SIZE]
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            // No special feature bits needed for basic operation
            1 => 1, // VIRTIO_F_VERSION_1
            _ => 0,
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let idx = (page & 1) as usize;
        self.acked_features[idx] = value;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Config space: tag (36 bytes) + num_request_queues (u32)
        let mut config = [0u8; 40];

        // Write tag (max 36 bytes, null-padded)
        let tag_bytes = self.tag.as_bytes();
        let tag_len = std::cmp::min(tag_bytes.len(), 36);
        config[..tag_len].copy_from_slice(&tag_bytes[..tag_len]);

        // num_request_queues = 1
        config[36..40].copy_from_slice(&1u32.to_le_bytes());

        let start = offset as usize;
        let end = std::cmp::min(start + data.len(), config.len());
        if start < end {
            let len = end - start;
            data[..len].copy_from_slice(&config[start..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Config space is read-only for virtio-fs
    }

    fn activate(&mut self) -> anyhow::Result<()> {
        self.activated = true;
        tracing::info!(tag = %self.tag, root = %self.root_dir.display(), "virtio-fs activated");
        Ok(())
    }

    fn process_queue(&mut self, _queue_index: u16) -> anyhow::Result<()> {
        // Actual processing happens in process_descriptor_chain
        Ok(())
    }

    fn process_descriptor_chain(
        &mut self,
        _queue_index: u16,
        chain: &DescriptorChain,
        vq: &Virtqueue,
    ) -> u32 {
        // Collect all readable data (FUSE request)
        let mut request_data = Vec::new();
        for desc in &chain.descriptors {
            if desc.flags & VRING_DESC_F_WRITE == 0 {
                if let Some(data) = vq.read_descriptor_data(desc) {
                    request_data.extend_from_slice(data);
                }
            }
        }

        if request_data.is_empty() {
            return 0;
        }

        // Process the FUSE request
        let response = self.handle_fuse_request(&request_data);

        if response.is_empty() {
            // FORGET has no response
            return 0;
        }

        // Write response into writable descriptors
        let mut written = 0usize;
        let mut src_offset = 0usize;

        for desc in &chain.descriptors {
            if desc.flags & VRING_DESC_F_WRITE == 0 {
                continue;
            }
            if src_offset >= response.len() {
                break;
            }
            if let Some(buf) = vq.write_descriptor_data(desc) {
                let copy_len = std::cmp::min(buf.len(), response.len() - src_offset);
                buf[..copy_len].copy_from_slice(&response[src_offset..src_offset + copy_len]);
                src_offset += copy_len;
                written += copy_len;
            }
        }

        written as u32
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
    fn reset(&mut self) {
        self.activated = false;
    }

    fn snapshot_state(&self) -> Vec<u8> {
        // Serialize tag and root_dir for snapshot/restore
        let state = serde_json::json!({
            "tag": self.tag,
            "root_dir": self.root_dir.to_str().unwrap_or(""),
        });
        serde_json::to_vec(&state).unwrap_or_default()
    }

    fn restore_state(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let state: serde_json::Value = serde_json::from_slice(data)?;
        if let Some(tag) = state["tag"].as_str() {
            self.tag = tag.to_string();
        }
        // Don't overwrite root_dir from template state. The fork path creates
        // the device with the user's actual home directory. The template's
        // root_dir (/tmp/shell-template-home) is stale.
        Ok(())
    }
}

// --- Helper functions ---

/// Set ownership of a newly created file/dir/symlink to the caller's uid/gid.
/// Uses lchown so symlinks themselves are chowned, not their targets.
fn chown_to_caller(path: &std::path::Path, uid: u32, gid: u32) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(c_path) = std::ffi::CString::new(path.to_str().unwrap_or("")) {
            unsafe { libc::lchown(c_path.as_ptr(), uid, gid); }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, uid, gid);
    }
}

/// Convert a struct to a byte slice (for writing FUSE responses).
///
/// # Safety
/// T must be repr(C) and have no padding requirements that matter.
unsafe fn as_bytes<T: Sized>(val: &T) -> &[u8] {
    std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>())
}

/// Extract a null-terminated C string from a byte slice.
fn cstr_from_bytes(data: &[u8]) -> Option<&str> {
    let nul_pos = data.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&data[..nul_pos]).ok()
}

/// Map std::io::Error to a FUSE errno.
fn errno_from_io(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

/// Get the current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

/// Convert std::fs::Metadata to a FuseAttr.
fn metadata_to_fuse_attr(ino: u64, meta: &std::fs::Metadata) -> FuseAttr {
    FuseAttr {
        ino,
        size: meta.len(),
        blocks: meta.blocks(),
        atime: meta.atime() as u64,
        mtime: meta.mtime() as u64,
        ctime: meta.ctime() as u64,
        atimensec: meta.atime_nsec() as u32,
        mtimensec: meta.mtime_nsec() as u32,
        ctimensec: meta.ctime_nsec() as u32,
        mode: meta.mode(),
        nlink: meta.nlink() as u32,
        uid: meta.uid(),
        gid: meta.gid(),
        rdev: meta.rdev() as u32,
        blksize: meta.blksize() as u32,
        flags: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cstr_from_bytes() {
        assert_eq!(cstr_from_bytes(b"hello\0world"), Some("hello"));
        assert_eq!(cstr_from_bytes(b"\0"), Some(""));
        assert_eq!(cstr_from_bytes(b"noterm"), None);
    }

    #[test]
    fn test_fuse_dirent_align() {
        assert_eq!(fuse_dirent_align(1), 8);
        assert_eq!(fuse_dirent_align(8), 8);
        assert_eq!(fuse_dirent_align(9), 16);
    }

    #[test]
    fn test_config_space_tag() {
        let fs = VirtioFs::new(PathBuf::from("/tmp"), "myfs".to_string());
        let mut buf = [0u8; 40];
        fs.read_config(0, &mut buf);
        assert_eq!(&buf[0..4], b"myfs");
        assert_eq!(buf[4], 0); // null-padded
        // num_request_queues = 1
        let nrq = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
        assert_eq!(nrq, 1);
    }

    #[test]
    fn test_device_type() {
        let fs = VirtioFs::new(PathBuf::from("/tmp"), "test".to_string());
        assert_eq!(fs.device_type(), DeviceType::Fs);
    }

    #[test]
    fn test_queue_sizes() {
        let fs = VirtioFs::new(PathBuf::from("/tmp"), "test".to_string());
        assert_eq!(fs.queue_max_sizes().len(), 2);
        assert_eq!(fs.queue_max_sizes()[0], QUEUE_MAX_SIZE);
    }

    #[test]
    fn test_error_response() {
        let fs = VirtioFs::new(PathBuf::from("/tmp"), "test".to_string());
        let resp = fs.make_error_response(42, -libc::ENOENT);
        assert_eq!(resp.len(), std::mem::size_of::<FuseOutHeader>());
        let hdr = unsafe { &*(resp.as_ptr() as *const FuseOutHeader) };
        assert_eq!(hdr.unique, 42);
        assert_eq!(hdr.error, -libc::ENOENT);
        assert_eq!(hdr.len, std::mem::size_of::<FuseOutHeader>() as u32);
    }

    #[test]
    fn test_metadata_to_fuse_attr() {
        // Create a temp file and verify metadata_to_fuse_attr extracts uid/gid
        let dir = std::env::temp_dir().join("virtio_fs_test_attr");
        let _ = std::fs::create_dir_all(&dir);
        let file_path = dir.join("testfile");
        std::fs::write(&file_path, b"hello").unwrap();

        let meta = std::fs::symlink_metadata(&file_path).unwrap();
        let attr = metadata_to_fuse_attr(99, &meta);

        assert_eq!(attr.ino, 99);
        assert_eq!(attr.size, 5);
        assert_eq!(attr.uid, meta.uid());
        assert_eq!(attr.gid, meta.gid());
        assert_eq!(attr.mode, meta.mode());
        assert_eq!(attr.nlink, meta.nlink() as u32);
        assert_eq!(attr.blocks, meta.blocks());
        assert_eq!(attr.blksize, meta.blksize() as u32);

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_inode_map_basics() {
        let root = PathBuf::from("/tmp/inode_test_root");
        let mut map = InodeMap::new(&root);

        // Root inode is always 1
        assert_eq!(map.get_path(FUSE_ROOT_ID), Some(&root));

        // Unknown inode returns None
        assert_eq!(map.get_path(999), None);

        // lookup_or_insert assigns new inode
        let child = root.join("child");
        let ino = map.lookup_or_insert(child.clone());
        assert!(ino >= 2);
        assert_eq!(map.get_path(ino), Some(&child));

        // Same path returns same inode
        let ino2 = map.lookup_or_insert(child.clone());
        assert_eq!(ino, ino2);

        // Different path gets different inode
        let child2 = root.join("child2");
        let ino3 = map.lookup_or_insert(child2.clone());
        assert_ne!(ino, ino3);
        assert_eq!(map.get_path(ino3), Some(&child2));

        // rename_path updates the mapping
        let child3 = root.join("child_renamed");
        map.rename_path(&child, &child3);
        assert_eq!(map.get_path(ino), Some(&child3));
    }

    #[test]
    fn test_inode_map_handles() {
        let root = PathBuf::from("/tmp/inode_test_handles");
        let _ = std::fs::create_dir_all(&root);
        let mut map = InodeMap::new(&root);

        // Open a real file
        let file_path = root.join("handle_test");
        std::fs::write(&file_path, b"data").unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&file_path)
            .unwrap();
        let fh = map.open_file(file);
        assert!(fh >= 1);

        // get_file returns the file
        assert!(map.get_file(fh).is_some());
        // get_dir on a file handle returns None
        assert!(map.get_dir(fh).is_none());

        // Open a directory handle
        let dir_fh = map.open_dir(root.clone());
        assert_ne!(fh, dir_fh);
        assert!(map.get_dir(dir_fh).is_some());
        // get_file on a dir handle returns None
        assert!(map.get_file(dir_fh).is_none());

        // Release removes the handle
        map.release(fh);
        assert!(map.get_file(fh).is_none());

        // Release dir handle
        map.release(dir_fh);
        assert!(map.get_dir(dir_fh).is_none());

        // Release of unknown handle is a no-op
        map.release(9999);

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn test_snapshot_restore_preserves_tag() {
        let fs1 = VirtioFs::new(PathBuf::from("/tmp/snap1"), "shared_tag".to_string());
        let state = fs1.snapshot_state();
        assert!(!state.is_empty());

        let mut fs2 = VirtioFs::new(PathBuf::from("/tmp/snap2"), "old_tag".to_string());
        fs2.restore_state(&state).unwrap();
        assert_eq!(fs2.tag, "shared_tag");
    }

    #[test]
    fn test_restore_does_not_overwrite_root_dir() {
        // The fork path creates a device with the user's actual home directory.
        // restore_state must NOT overwrite root_dir with the template's stale path.
        let mut fs = VirtioFs::new(PathBuf::from("/home/user"), "tag".to_string());

        // Simulate a template state with a different root_dir
        let template_state = serde_json::json!({
            "tag": "tag",
            "root_dir": "/tmp/shell-template-home",
        });
        let data = serde_json::to_vec(&template_state).unwrap();
        fs.restore_state(&data).unwrap();

        // root_dir must still be the user's path, not the template's
        assert_eq!(fs.root_dir, PathBuf::from("/home/user"));
    }
}
