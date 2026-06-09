//! Filesystem layer: path resolution, open-handle table, metadata mapping.

use std::ffi::CString;
use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::status;

pub const ATTR_READONLY: u32 = 0x01;
pub const ATTR_HIDDEN: u32 = 0x02;
pub const ATTR_DIRECTORY: u32 = 0x10;
pub const ATTR_ARCHIVE: u32 = 0x20;

const EPOCH_DELTA_SECS: i64 = 11_644_473_600;

/// Unix time → Windows FILETIME (100ns ticks since 1601-01-01).
pub fn filetime(secs: i64, nsec: i64) -> u64 {
    if secs < -EPOCH_DELTA_SECS {
        return 0;
    }
    ((secs + EPOCH_DELTA_SECS) as u64) * 10_000_000 + (nsec as u64) / 100
}

pub fn filetime_now() -> u64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    filetime(d.as_secs() as i64, d.subsec_nanos() as i64)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Meta {
    pub size: u64,
    pub alloc: u64,
    pub attrs: u32,
    pub crtime: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub ino: u64,
    pub nlink: u32,
    pub is_dir: bool,
}

fn meta_from_std(m: &std::fs::Metadata) -> Meta {
    let is_dir = m.is_dir();
    let mut attrs = if is_dir { ATTR_DIRECTORY } else { 0 };
    if m.mode() & 0o200 == 0 {
        attrs |= ATTR_READONLY;
    }
    if attrs == 0 {
        attrs = ATTR_ARCHIVE;
    }
    let mtime = filetime(m.mtime(), m.mtime_nsec());
    Meta {
        size: m.size(),
        alloc: m.blocks() * 512,
        attrs,
        // No portable birth time; mtime is a sane stand-in for creation.
        crtime: mtime,
        atime: filetime(m.atime(), m.atime_nsec()),
        mtime,
        ctime: filetime(m.ctime(), m.ctime_nsec()),
        ino: m.ino(),
        nlink: m.nlink() as u32,
        is_dir,
    }
}

/// Dotfiles get the DOS hidden attribute, samba-style.
pub fn finalize_attrs(attrs: u32, leaf: &str) -> u32 {
    if leaf.starts_with('.') && leaf != "." && leaf != ".." {
        attrs | ATTR_HIDDEN
    } else {
        attrs
    }
}

pub fn stat_meta(p: &Path) -> Result<Meta, i32> {
    std::fs::metadata(p)
        .map(|m| meta_from_std(&m))
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

pub fn fstat_meta(fd: RawFd) -> Result<Meta, i32> {
    let f = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
    f.metadata()
        .map(|m| meta_from_std(&m))
        .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

/// Resolve a share-relative SMB name (backslash separators) to a host path.
/// Rejects `..` traversal. Returns the path and the normalized relative name.
pub fn resolve(root: &Path, smb_name: &str) -> Result<(PathBuf, String), u32> {
    let mut p = root.to_path_buf();
    let mut rel = String::new();
    for comp in smb_name.split(['\\', '/']) {
        match comp {
            "" | "." => {}
            ".." => return Err(status::OBJECT_NAME_INVALID),
            c => {
                if c.bytes().any(|b| b == 0) {
                    return Err(status::OBJECT_NAME_INVALID);
                }
                p.push(c);
                if !rel.is_empty() {
                    rel.push('\\');
                }
                rel.push_str(c);
            }
        }
    }
    Ok((p, rel))
}

pub fn cpath(p: &Path) -> Result<CString, i32> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)
}

pub fn open_raw(p: &Path, flags: i32, mode: u32) -> Result<RawFd, i32> {
    let c = cpath(p)?;
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, mode) };
    if fd < 0 {
        Err(errno())
    } else {
        Ok(fd)
    }
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

pub fn pread(fd: RawFd, buf: &mut [u8], off: u64) -> Result<usize, i32> {
    loop {
        let n = unsafe {
            libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), off as libc::off_t)
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = errno();
        if e != libc::EINTR {
            return Err(e);
        }
    }
}

pub fn pwrite_all(fd: RawFd, mut buf: &[u8], mut off: u64) -> Result<(), i32> {
    while !buf.is_empty() {
        let n = unsafe {
            libc::pwrite(fd, buf.as_ptr() as *const libc::c_void, buf.len(), off as libc::off_t)
        };
        if n < 0 {
            let e = errno();
            if e == libc::EINTR {
                continue;
            }
            return Err(e);
        }
        buf = &buf[n as usize..];
        off += n as u64;
    }
    Ok(())
}

pub fn ftruncate(fd: RawFd, len: u64) -> Result<(), i32> {
    if unsafe { libc::ftruncate(fd, len as libc::off_t) } < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

pub fn fsync(fd: RawFd) -> Result<(), i32> {
    if unsafe { libc::fsync(fd) } < 0 {
        Err(errno())
    } else {
        Ok(())
    }
}

/// (total_units, caller_avail_units, actual_avail_units, sectors_per_unit, bytes_per_sector)
pub fn fs_sizes(fd: RawFd) -> Result<(u64, u64, u64, u32, u32), i32> {
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(fd, &mut s) } < 0 {
        return Err(errno());
    }
    let frsize = if s.f_frsize > 0 { s.f_frsize as u64 } else { 512 };
    let spu = (frsize / 512).max(1) as u32;
    Ok((s.f_blocks as u64, s.f_bavail as u64, s.f_bfree as u64, spu, 512))
}

#[derive(Debug, Clone)]
pub struct DirEnt {
    pub name: String,
    pub meta: Meta,
}

#[derive(Debug)]
pub struct DirState {
    pub entries: Vec<DirEnt>,
    pub pos: usize,
    pub pattern: String,
}

#[derive(Debug)]
pub struct OpenFile {
    pub fd: RawFd,
    pub path: PathBuf,
    /// Share-relative name with backslash separators ("" = share root).
    pub rel: String,
    pub leaf: String,
    pub share_idx: u32,
    pub is_dir: bool,
    pub writable: bool,
    pub delete_on_close: bool,
    pub dir: Option<DirState>,
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

/// Read the full directory listing as a snapshot, including `.` and `..`.
pub fn dir_snapshot(of: &OpenFile, pattern: &str) -> Result<Vec<DirEnt>, i32> {
    let self_meta = fstat_meta(of.fd)?;
    let mut out = vec![
        DirEnt { name: ".".into(), meta: self_meta },
        DirEnt { name: "..".into(), meta: self_meta },
    ];
    let rd = std::fs::read_dir(&of.path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
    for ent in rd.flatten() {
        let name = match ent.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue, // skip non-UTF-8 names in v0.1
        };
        let md = match ent.metadata().or_else(|_| std::fs::symlink_metadata(ent.path())) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mut meta = meta_from_std(&md);
        meta.attrs = finalize_attrs(meta.attrs, &name);
        out.push(DirEnt { name, meta });
    }
    if !(pattern.is_empty() || pattern == "*") {
        let pl = pattern.to_lowercase();
        out.retain(|e| e.name.to_lowercase() == pl);
    }
    Ok(out)
}

const HT_IDX_BITS: u32 = 32;

/// Slab of open files. Ids are `(generation << 32) | index`, never reused
/// across a close, so a stale FileId from the client misses cleanly.
#[derive(Default)]
pub struct HandleTable {
    slots: Vec<Option<OpenFile>>,
    gens: Vec<u32>,
    free: Vec<usize>,
}

impl HandleTable {
    pub fn insert(&mut self, of: OpenFile) -> u64 {
        let idx = match self.free.pop() {
            Some(i) => {
                self.slots[i] = Some(of);
                i
            }
            None => {
                self.slots.push(Some(of));
                self.gens.push(1);
                self.slots.len() - 1
            }
        };
        ((self.gens[idx] as u64) << HT_IDX_BITS) | idx as u64
    }

    fn slot(&self, id: u64) -> Option<usize> {
        let idx = (id & 0xFFFF_FFFF) as usize;
        let gen = (id >> HT_IDX_BITS) as u32;
        if idx < self.slots.len() && self.gens[idx] == gen && self.slots[idx].is_some() {
            Some(idx)
        } else {
            None
        }
    }

    pub fn get(&mut self, id: u64) -> Option<&mut OpenFile> {
        let idx = self.slot(id)?;
        self.slots[idx].as_mut()
    }

    pub fn remove(&mut self, id: u64) -> Option<OpenFile> {
        let idx = self.slot(id)?;
        let of = self.slots[idx].take();
        self.gens[idx] = self.gens[idx].wrapping_add(1).max(1);
        self.free.push(idx);
        of
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rejects_traversal() {
        let root = Path::new("/srv/data");
        assert!(resolve(root, "..\\etc\\passwd").is_err());
        assert!(resolve(root, "a\\..\\..\\b").is_err());
        let (p, rel) = resolve(root, "dir\\sub\\f.txt").unwrap();
        assert_eq!(p, Path::new("/srv/data/dir/sub/f.txt"));
        assert_eq!(rel, "dir\\sub\\f.txt");
        let (p, rel) = resolve(root, "").unwrap();
        assert_eq!(p, root);
        assert_eq!(rel, "");
    }

    #[test]
    fn handle_table_gen_safety() {
        let mut t = HandleTable::default();
        let of = OpenFile {
            fd: -1,
            path: "/tmp".into(),
            rel: String::new(),
            leaf: String::new(),
            share_idx: 0,
            is_dir: true,
            writable: false,
            delete_on_close: false,
            dir: None,
        };
        let id = t.insert(of);
        assert!(t.get(id).is_some());
        t.remove(id).unwrap();
        assert!(t.get(id).is_none()); // stale id must miss
    }

    #[test]
    fn filetime_epoch() {
        // 1970-01-01 → 116444736000000000
        assert_eq!(filetime(0, 0), 116_444_736_000_000_000);
    }
}
