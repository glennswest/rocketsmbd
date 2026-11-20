//! IPC$ named pipes forwarded to an RPC backend (#83).
//!
//! A domain join speaks SAMR, LSARPC and NETLOGON as DCE/RPC over SMB named
//! pipes (`ncacn_np`). rocketsmbd does not implement those interfaces: a
//! CREATE of a served pipe on `IPC$` opens a Unix stream socket to the
//! configured backend (`[ipc] backend`, irondirectory's `iron-rpcd`), sends a
//! preamble naming the pipe and the session's authenticated identity and key,
//! and from then on moves bytes both ways unchanged. The preamble format is
//! in docs/IPC-PIPES.md.
//!
//! Named pipes for RPC are message-mode: a READ (or FSCTL_PIPE_TRANSCEIVE)
//! returns one message. The backend's byte stream is cut into messages at
//! DCE/RPC fragment boundaries (`frag_length` in the 16-byte common header);
//! a read buffer shorter than the fragment gets the first part with
//! STATUS_BUFFER_OVERFLOW and the rest on the next read.
//!
//! Every socket here is non-blocking: the reactor thread never waits on the
//! backend. A read with no complete message pends (STATUS_PENDING) and the
//! reactor polls a dup of the socket (`uring.rs`).

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::status;

/// First bytes of the preamble.
pub const PREAMBLE_MAGIC: &[u8; 8] = b"RSMBPIPE";
/// Preamble format version. A change to its layout bumps this.
pub const PREAMBLE_VERSION: u16 = 1;

/// Preamble flags.
pub const FLAG_SIGNED: u16 = 0x0001;
pub const FLAG_ENCRYPTED: u16 = 0x0002;
/// The user was authenticated by Kerberos; `user_sid`/`groups` come from the
/// PAC the KDC signed. Without it (NTLM against rocketsmbd's own user list)
/// there are no SIDs.
pub const FLAG_KERBEROS: u16 = 0x0004;

/// Bytes of backend output buffered per pipe before rocketsmbd stops reading
/// the socket (backpressure). Larger than any DCE/RPC fragment (u16 length).
const RBUF_CAP: usize = 256 * 1024;

/// The authenticated session a pipe is opened for.
pub struct Identity<'a> {
    /// Lowercased pipe name, e.g. `samr`.
    pub pipe: &'a str,
    /// Bit set of `FLAG_*`.
    pub flags: u16,
    /// Negotiated SMB dialect (e.g. 0x0311).
    pub dialect: u16,
    /// The key RPC uses as the "session key" of an `ncacn_np` connection:
    /// Session.ApplicationKey for SMB 3.x, Session.SessionKey for 2.x
    /// (MS-SMB2 3.3.5.5.3), as Samba hands its RPC server. SAMR encrypts
    /// password sets with it.
    pub session_key: &'a [u8; 16],
    /// The authenticated name: a Kerberos principal (`alice@AD.EXAMPLE`) or
    /// an NTLM user.
    pub user: &'a str,
    /// NetBIOS domain from the PAC (empty without one).
    pub domain: &'a str,
    /// User SID from the PAC, `S-1-5-21-…` (empty without one).
    pub user_sid: String,
    /// Group SIDs from the PAC.
    pub groups: Vec<String>,
}

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    let n = s.len().min(u16::MAX as usize);
    out.extend_from_slice(&(n as u16).to_le_bytes());
    out.extend_from_slice(&s[..n]);
}

/// Encode the preamble (docs/IPC-PIPES.md). All integers little-endian;
/// strings are a u16 byte length + UTF-8.
pub fn encode_preamble(id: &Identity) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);
    body.extend_from_slice(&id.flags.to_le_bytes());
    body.extend_from_slice(&id.dialect.to_le_bytes());
    put_str(&mut body, id.pipe.as_bytes());
    put_str(&mut body, id.session_key);
    put_str(&mut body, id.user.as_bytes());
    put_str(&mut body, id.domain.as_bytes());
    put_str(&mut body, id.user_sid.as_bytes());
    let ng = id.groups.len().min(u16::MAX as usize);
    body.extend_from_slice(&(ng as u16).to_le_bytes());
    for g in &id.groups[..ng] {
        put_str(&mut body, g.as_bytes());
    }
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(PREAMBLE_MAGIC);
    out.extend_from_slice(&PREAMBLE_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// One open pipe: the backend stream and what it has sent that the client
/// has not read yet.
pub struct PipeOpen {
    pub tree_id: u32,
    pub name: String,
    sock: UnixStream,
    rbuf: Vec<u8>,
    /// Bytes of the current message (fragment) not yet delivered; 0 = at a
    /// message boundary.
    msg_left: usize,
    eof: bool,
    broken: bool,
}

impl Drop for PipeOpen {
    fn drop(&mut self) {
        // Shut the socket itself down (not only this fd): a reactor poll on a
        // dup of it then completes, and the backend sees the pipe close.
        let _ = self.sock.shutdown(std::net::Shutdown::Both);
    }
}

/// Connect to the backend without blocking: a backend whose listen backlog
/// is full answers EAGAIN instead of stalling the reactor.
fn connect_nb(path: &Path) -> std::io::Result<UnixStream> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: zeroed sockaddr_un is a valid value of the type.
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= sa.sun_path.len() {
        return Err(std::io::Error::new(ErrorKind::InvalidInput, "socket path too long"));
    }
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (d, s) in sa.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    // SAFETY: integer-only syscall; the fd is owned by the UnixStream below.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh socket owned only here.
    let sock = unsafe { UnixStream::from_raw_fd(fd) };
    let len = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    // SAFETY: sa is a live, initialized sockaddr_un and len does not exceed it.
    let rc = unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, len) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(sock)
}

impl PipeOpen {
    /// Connect to `backend` and send the preamble.
    pub fn open(backend: &Path, tree_id: u32, id: &Identity) -> Result<PipeOpen, u32> {
        let mut sock = match connect_nb(backend) {
            Ok(s) => s,
            Err(e) => {
                crate::logw!("ipc: pipe {:?}: backend {:?} unreachable: {e}", id.pipe, backend);
                return Err(status::PIPE_NOT_AVAILABLE);
            }
        };
        let pre = encode_preamble(id);
        match sock.write(&pre) {
            Ok(n) if n == pre.len() => {}
            r => {
                crate::logw!("ipc: pipe {:?}: preamble not accepted by the backend ({r:?})", id.pipe);
                return Err(status::PIPE_NOT_AVAILABLE);
            }
        }
        Ok(PipeOpen {
            tree_id,
            name: id.pipe.to_string(),
            sock,
            rbuf: Vec::new(),
            msg_left: 0,
            eof: false,
            broken: false,
        })
    }

    /// The backend socket, for the reactor to dup and poll.
    pub fn raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    /// Send client bytes to the backend. A write the socket cannot take whole
    /// right now would leave a torn message in the stream, so it breaks the
    /// pipe instead (the socket buffer holds far more than one RPC fragment).
    pub fn write(&mut self, data: &[u8]) -> Result<(), u32> {
        if self.broken || self.eof {
            return Err(status::PIPE_BROKEN);
        }
        let mut off = 0;
        while off < data.len() {
            match self.sock.write(&data[off..]) {
                Ok(0) => break,
                Ok(n) => off += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        if off < data.len() {
            crate::logw!("ipc: pipe {:?}: backend took {off} of {} bytes; breaking the pipe", self.name, data.len());
            self.broken = true;
            let _ = self.sock.shutdown(std::net::Shutdown::Both);
            return Err(status::PIPE_BROKEN);
        }
        Ok(())
    }

    /// Pull whatever the backend has sent, without blocking.
    fn fill(&mut self) {
        let mut buf = [0u8; 16 * 1024];
        while !self.eof && !self.broken && self.rbuf.len() < RBUF_CAP {
            match self.sock.read(&mut buf) {
                Ok(0) => self.eof = true,
                Ok(n) => self.rbuf.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => self.eof = true,
            }
        }
    }

    /// The next message (or its next part) for a read of up to `max` bytes:
    /// `Ok(Some((data, overflow)))` when there is one to hand back,
    /// `Ok(None)` when the client must wait for the backend, `Err(status)`
    /// when the pipe is broken.
    pub fn read(&mut self, max: usize) -> Result<Option<(Vec<u8>, bool)>, u32> {
        self.fill();
        if self.broken {
            return Err(status::PIPE_BROKEN);
        }
        if self.msg_left == 0 {
            if self.rbuf.len() < 16 {
                return if self.eof { Err(status::PIPE_BROKEN) } else { Ok(None) };
            }
            match frag_length(&self.rbuf) {
                Some(n) => self.msg_left = n,
                None => {
                    crate::logw!("ipc: pipe {:?}: backend sent a non-DCE/RPC header; breaking the pipe", self.name);
                    self.broken = true;
                    return Err(status::PIPE_BROKEN);
                }
            }
        }
        let want = self.msg_left.min(max);
        if want == 0 {
            // A zero-length read on a message boundary: nothing to return yet.
            return Ok(Some((Vec::new(), self.msg_left > 0)));
        }
        if self.rbuf.len() < want {
            // Message pipes hand back a whole message (or a buffer's worth).
            return if self.eof { Err(status::PIPE_BROKEN) } else { Ok(None) };
        }
        let data: Vec<u8> = self.rbuf.drain(..want).collect();
        self.msg_left -= want;
        Ok(Some((data, self.msg_left > 0)))
    }
}

/// `frag_length` of the DCE/RPC PDU at the start of `b` (C706 12.6.3: version
/// 5, the data representation's integer byte order in drep[0] bit 4), or
/// `None` if `b` does not start with a connection-oriented PDU header.
pub fn frag_length(b: &[u8]) -> Option<usize> {
    if b.len() < 16 || b[0] != 5 {
        return None;
    }
    let raw = [b[8], b[9]];
    let n = if b[4] & 0x10 != 0 { u16::from_le_bytes(raw) } else { u16::from_be_bytes(raw) } as usize;
    (n >= 16).then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    fn pdu(len: u16, fill: u8) -> Vec<u8> {
        let mut v = vec![5, 0, 2, 3, 0x10, 0, 0, 0];
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&[0; 6]);
        v.resize(len as usize, fill);
        v
    }

    fn ident() -> Identity<'static> {
        static KEY: [u8; 16] = [7; 16];
        Identity {
            pipe: "samr",
            flags: FLAG_SIGNED | FLAG_KERBEROS,
            dialect: 0x0311,
            session_key: &KEY,
            user: "admin@AD.EXAMPLE",
            domain: "AD",
            user_sid: "S-1-5-21-1-2-3-500".into(),
            groups: vec!["S-1-5-21-1-2-3-512".into(), "S-1-5-21-1-2-3-513".into()],
        }
    }

    #[test]
    fn frag_length_both_byte_orders() {
        assert_eq!(frag_length(&pdu(72, 0)), Some(72));
        let mut be = pdu(72, 0);
        be[4] = 0;
        be[8] = 0;
        be[9] = 72;
        assert_eq!(frag_length(&be), Some(72));
        let mut bad = pdu(72, 0);
        bad[0] = 4;
        assert_eq!(frag_length(&bad), None);
        assert_eq!(frag_length(&pdu(72, 0)[..10]), None);
    }

    #[test]
    fn preamble_layout() {
        let p = encode_preamble(&ident());
        assert_eq!(&p[..8], PREAMBLE_MAGIC);
        assert_eq!(u16::from_le_bytes([p[8], p[9]]), PREAMBLE_VERSION);
        let len = u32::from_le_bytes(p[12..16].try_into().unwrap()) as usize;
        assert_eq!(p.len(), 16 + len);
        let b = &p[16..];
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), FLAG_SIGNED | FLAG_KERBEROS);
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), 0x0311);
        assert_eq!(&b[4..6], &4u16.to_le_bytes());
        assert_eq!(&b[6..10], b"samr");
        assert_eq!(&b[10..12], &16u16.to_le_bytes());
        assert_eq!(&b[12..28], &[7u8; 16]);
        // ...user, domain, sid, then 2 groups; the last bytes are the last group.
        assert!(p.ends_with(b"S-1-5-21-1-2-3-513"));
    }

    fn pair() -> (PipeOpen, UnixStream, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("rsmb-pipe-{}-{:x}", std::process::id(), {
            let mut b = [0u8; 8];
            crate::config::urandom(&mut b);
            u64::from_le_bytes(b)
        }));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let l = UnixListener::bind(&path).unwrap();
        let p = PipeOpen::open(&path, 1, &ident()).unwrap();
        let (mut srv, _) = l.accept().unwrap();
        let mut pre = vec![0u8; encode_preamble(&ident()).len()];
        srv.read_exact(&mut pre).unwrap();
        assert_eq!(pre, encode_preamble(&ident()));
        (p, srv, dir)
    }

    fn wait_read(p: &mut PipeOpen, max: usize) -> Result<Option<(Vec<u8>, bool)>, u32> {
        for _ in 0..200 {
            match p.read(max) {
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(5)),
                r => return r,
            }
        }
        Ok(None)
    }

    #[test]
    fn message_mode_reads() {
        let (mut p, mut srv, dir) = pair();
        assert_eq!(p.read(4096), Ok(None), "nothing sent yet");
        p.write(b"request").unwrap();
        let mut got = [0u8; 7];
        srv.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"request");

        // Two fragments in one backend write come back one per read.
        let (a, b) = (pdu(40, 0xAA), pdu(24, 0xBB));
        srv.write_all(&[a.clone(), b.clone()].concat()).unwrap();
        assert_eq!(wait_read(&mut p, 4096), Ok(Some((a.clone(), false))));
        assert_eq!(p.read(4096), Ok(Some((b, false))));

        // A short buffer: first part with overflow, then the rest.
        srv.write_all(&a).unwrap();
        assert_eq!(wait_read(&mut p, 30), Ok(Some((a[..30].to_vec(), true))));
        assert_eq!(p.read(30), Ok(Some((a[30..].to_vec(), false))));

        // A fragment that has only partly arrived waits for the rest.
        srv.write_all(&a[..20]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(p.read(4096), Ok(None));
        srv.write_all(&a[20..]).unwrap();
        assert_eq!(wait_read(&mut p, 4096), Ok(Some((a, false))));

        // Backend gone → broken pipe.
        drop(srv);
        assert_eq!(wait_read(&mut p, 4096), Err(status::PIPE_BROKEN));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn garbage_from_backend_breaks_the_pipe() {
        let (mut p, mut srv, dir) = pair();
        srv.write_all(&[0x47; 32]).unwrap();
        assert_eq!(wait_read(&mut p, 4096), Err(status::PIPE_BROKEN));
        assert_eq!(p.write(b"x"), Err(status::PIPE_BROKEN));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unreachable_backend() {
        let r = PipeOpen::open(Path::new("/nonexistent/rocketsmbd-test.sock"), 1, &ident());
        assert_eq!(r.err(), Some(status::PIPE_NOT_AVAILABLE));
    }
}
