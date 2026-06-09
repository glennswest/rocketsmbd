//! SMB2 command handlers.

use std::path::Path;

use super::*;
use crate::config::{ShareCfg, Srv};
use crate::ntlm;
use crate::status;
use crate::vfs::{self, DirState, OpenFile};
use crate::wire::{from_utf16le, utf16le, Put, Rdr};

// DesiredAccess bits
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const WRITE_BITS: u32 = FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL;

// CreateDisposition
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;

// CreateAction
const CREATE_ACTION_OPENED: u32 = 1;
const CREATE_ACTION_CREATED: u32 = 2;
const CREATE_ACTION_OVERWRITTEN: u32 = 3;

const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;

const SUPPORTED_DIALECTS: [u16; 4] = [0x0302, 0x0300, 0x0210, 0x0202];
const CAP_LARGE_MTU: u32 = 0x4;
const SECURITY_MODE_SIGNING_ENABLED: u16 = 0x1;
const SESSION_FLAG_IS_GUEST: u16 = 0x1;
const MAXIMAL_ACCESS_ALL: u32 = 0x001F_01FF;

pub fn dispatch(
    srv: &Srv,
    pc: &mut ProtoConn,
    h: &ReqHdr,
    msg: &[u8],
    chain: &mut Chain,
    tx: &mut Vec<u8>,
) -> Option<ZcReadPlan> {
    let body = &msg[64..];

    // Resolve effective session/tree for related compound operations.
    if h.flags & FLAG_RELATED != 0 {
        chain.related = true;
        if h.session_id != 0 && h.session_id != u64::MAX {
            chain.session_id = h.session_id;
        }
        if h.tree_id != 0 && h.tree_id != u32::MAX {
            chain.tree_id = h.tree_id;
        }
    } else {
        chain.related = false;
        chain.session_id = h.session_id;
        chain.tree_id = h.tree_id;
    }

    match h.command {
        CMD_NEGOTIATE => negotiate(srv, pc, h, body, chain, tx),
        CMD_ECHO => simple_resp(tx, h, chain),
        CMD_CANCEL => {} // no response
        CMD_SESSION_SETUP => session_setup(srv, pc, h, msg, chain, tx),
        _ => {
            if !pc.sessions.contains_key(&chain.session_id) {
                err_resp(tx, h, status::USER_SESSION_DELETED, chain);
                return None;
            }
            match h.command {
                CMD_LOGOFF => {
                    pc.sessions.remove(&chain.session_id);
                    simple_resp(tx, h, chain);
                }
                CMD_TREE_CONNECT => tree_connect(srv, pc, h, msg, chain, tx),
                _ => {
                    let Some(share_idx) = pc
                        .sessions
                        .get(&chain.session_id)
                        .and_then(|s| s.trees.get(&chain.tree_id))
                        .copied()
                    else {
                        err_resp(tx, h, status::NETWORK_NAME_DELETED, chain);
                        return None;
                    };
                    let share = &srv.cfg.shares[share_idx as usize];
                    match h.command {
                        CMD_TREE_DISCONNECT => {
                            if let Some(s) = pc.sessions.get_mut(&chain.session_id) {
                                s.trees.remove(&chain.tree_id);
                            }
                            simple_resp(tx, h, chain);
                        }
                        CMD_CREATE => create(pc, h, msg, chain, tx, share, share_idx),
                        CMD_CLOSE => close(pc, h, body, chain, tx),
                        CMD_FLUSH => flush(pc, h, body, chain, tx),
                        CMD_READ => return read(pc, h, body, chain, tx),
                        CMD_WRITE => write(pc, h, msg, chain, tx, share),
                        CMD_QUERY_DIRECTORY => query_directory(pc, h, msg, chain, tx),
                        CMD_QUERY_INFO => query_info(srv, pc, h, body, chain, tx),
                        CMD_SET_INFO => set_info(pc, h, msg, chain, tx, share),
                        CMD_IOCTL => ioctl(srv, pc, h, msg, chain, tx),
                        CMD_LOCK | CMD_CHANGE_NOTIFY | CMD_OPLOCK_BREAK => {
                            err_resp(tx, h, status::NOT_SUPPORTED, chain)
                        }
                        _ => err_resp(tx, h, status::NOT_SUPPORTED, chain),
                    }
                }
            }
        }
    }
    None
}

fn simple_resp(tx: &mut Vec<u8>, h: &ReqHdr, chain: &Chain) {
    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(4);
    tx.p16(0);
}

/// Parse a 16-byte FileId; all-ones means "use the previous handle in the
/// compound chain".
fn parse_fid(r: &mut Rdr, chain: &Chain) -> Option<u64> {
    let persistent = r.u64()?;
    let volatile = r.u64()?;
    if persistent == u64::MAX && volatile == u64::MAX {
        chain.last_fid
    } else {
        Some(volatile)
    }
}

fn put_fid(tx: &mut Vec<u8>, fid: u64) {
    tx.p64(fid);
    tx.p64(fid);
}

// ---------------------------------------------------------------- NEGOTIATE

fn negotiate(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, body: &[u8], chain: &Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 36 {
            return None;
        }
        let count = r.u16()? as usize;
        r.skip(2 + 2 + 4 + 16 + 8)?; // secmode, reserved, caps, guid, (ctx/starttime)
        let mut dialects = Vec::with_capacity(count.min(16));
        for _ in 0..count.min(16) {
            dialects.push(r.u16()?);
        }
        Some(dialects)
    })();
    let Some(dialects) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(&chosen) = SUPPORTED_DIALECTS.iter().find(|d| dialects.contains(d)) else {
        err_resp(tx, h, status::NOT_SUPPORTED, chain);
        return;
    };
    pc.dialect = chosen;
    begin_resp(tx, h, status::SUCCESS, false, 0, 0);
    negotiate_body(srv, pc, chosen, tx);
}

pub fn negotiate_resp_smb1_wildcard(srv: &Srv, pc: &mut ProtoConn, tx: &mut Vec<u8>) {
    let h = ReqHdr {
        credit_charge: 0,
        command: CMD_NEGOTIATE,
        credits: 1,
        flags: 0,
        next: 0,
        msg_id: 0,
        tree_id: 0,
        session_id: 0,
    };
    begin_resp(tx, &h, status::SUCCESS, false, 0, 0);
    negotiate_body(srv, pc, 0x02FF, tx);
}

fn negotiate_body(srv: &Srv, pc: &ProtoConn, dialect: u16, tx: &mut Vec<u8>) {
    tx.p16(65);
    tx.p16(SECURITY_MODE_SIGNING_ENABLED);
    tx.p16(dialect);
    tx.p16(0); // NegotiateContextCount / Reserved
    tx.pbytes(&srv.guid);
    tx.p32(CAP_LARGE_MTU);
    tx.p32(MAX_TRANSACT);
    tx.p32(pc.max_read);
    tx.p32(MAX_WRITE);
    tx.p64(vfs::filetime_now());
    tx.p64(srv.start_ft);
    tx.p16(0); // SecurityBufferOffset (no SPNEGO hint; raw NTLMSSP accepted)
    tx.p16(0); // SecurityBufferLength
    tx.p32(0); // NegotiateContextOffset / Reserved2
}

// ------------------------------------------------------------ SESSION_SETUP

fn session_setup(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let blob = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 25 {
            return None;
        }
        r.skip(1 + 1 + 4 + 4)?; // flags, security mode, caps, channel
        let off = r.u16()? as usize;
        let len = r.u16()? as usize;
        let _prev = r.u64()?;
        if len == 0 {
            return Some(&[][..]);
        }
        msg.get(off..off + len)
    })();
    let Some(blob) = blob else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };

    match ntlm::classify(blob) {
        ntlm::Token::Negotiate => {
            // Interim response: assign the session id, send a CHALLENGE.
            let sid = pc.next_session_id;
            pc.next_session_id += 1;
            chain.session_id = sid;
            let mut chal = [0u8; 8];
            crate::config::urandom(&mut chal);
            let token = ntlm::challenge(&srv.cfg.server_name, chal);
            begin_resp(tx, h, status::MORE_PROCESSING_REQUIRED, chain.related, 0, sid);
            tx.p16(9);
            tx.p16(0); // SessionFlags
            tx.p16(72); // SecurityBufferOffset
            tx.p16(token.len() as u16);
            tx.pbytes(&token);
        }
        _ => {
            // AUTHENTICATE (or anonymous/empty): grant a guest session.
            let sid = if h.session_id != 0 {
                h.session_id
            } else {
                let s = pc.next_session_id;
                pc.next_session_id += 1;
                s
            };
            pc.sessions.entry(sid).or_default();
            chain.session_id = sid;
            begin_resp(tx, h, status::SUCCESS, chain.related, 0, sid);
            tx.p16(9);
            tx.p16(SESSION_FLAG_IS_GUEST);
            tx.p16(0);
            tx.p16(0);
        }
    }
}

// ------------------------------------------------------------- TREE_CONNECT

fn tree_connect(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let path = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 9 {
            return None;
        }
        r.skip(2)?;
        let off = r.u16()? as usize;
        let len = r.u16()? as usize;
        msg.get(off..off + len).map(from_utf16le)
    })();
    let Some(path) = path else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    // "\\server\share" → "share"
    let share_name = path.rsplit('\\').next().unwrap_or("");
    let Some(share_idx) = srv
        .cfg
        .shares
        .iter()
        .position(|s| s.name.eq_ignore_ascii_case(share_name))
    else {
        err_resp(tx, h, status::BAD_NETWORK_NAME, chain);
        return;
    };
    let sess = pc.sessions.get_mut(&chain.session_id).expect("session checked");
    sess.next_tree_id += 1;
    let tree_id = sess.next_tree_id;
    sess.trees.insert(tree_id, share_idx as u32);
    chain.tree_id = tree_id;

    begin_resp(tx, h, status::SUCCESS, chain.related, tree_id, chain.session_id);
    tx.p16(16);
    tx.p8(1); // ShareType: disk
    tx.p8(0);
    tx.p32(0); // ShareFlags
    tx.p32(0); // Capabilities
    tx.p32(MAXIMAL_ACCESS_ALL);
}

// ------------------------------------------------------------------- CREATE

struct CreateReq {
    desired: u32,
    disposition: u32,
    options: u32,
    name: String,
}

fn parse_create(msg: &[u8]) -> Option<CreateReq> {
    let body = &msg[64..];
    let mut r = Rdr::new(body);
    if r.u16()? != 57 {
        return None;
    }
    r.skip(1 + 1 + 4 + 8 + 8)?; // secflags, oplock, impersonation, smbflags, reserved
    let desired = r.u32()?;
    let _attrs = r.u32()?;
    let _share_access = r.u32()?;
    let disposition = r.u32()?;
    let options = r.u32()?;
    let name_off = r.u16()? as usize;
    let name_len = r.u16()? as usize;
    let name = if name_len == 0 {
        String::new()
    } else {
        from_utf16le(msg.get(name_off..name_off + name_len)?)
    };
    Some(CreateReq { desired, disposition, options, name })
}

#[allow(clippy::too_many_arguments)]
fn create(
    pc: &mut ProtoConn,
    h: &ReqHdr,
    msg: &[u8],
    chain: &mut Chain,
    tx: &mut Vec<u8>,
    share: &ShareCfg,
    share_idx: u32,
) {
    let Some(req) = parse_create(msg) else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let (path, rel) = match vfs::resolve(&share.path, &req.name) {
        Ok(v) => v,
        Err(st) => {
            err_resp(tx, h, st, chain);
            return;
        }
    };

    let wants_write = req.desired & WRITE_BITS != 0;
    let creates = matches!(
        req.disposition,
        FILE_SUPERSEDE | FILE_CREATE | FILE_OVERWRITE | FILE_OVERWRITE_IF
    );
    let delete_on_close = req.options & FILE_DELETE_ON_CLOSE != 0;
    if share.read_only && (wants_write || creates || delete_on_close) {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }

    let existing = vfs::stat_meta(&path).ok();
    let exists = existing.is_some();
    let existing_dir = existing.map(|m| m.is_dir).unwrap_or(false);

    if exists && req.disposition == FILE_CREATE {
        err_resp(tx, h, status::OBJECT_NAME_COLLISION, chain);
        return;
    }
    if !exists && matches!(req.disposition, FILE_OPEN | FILE_OVERWRITE) {
        err_resp(tx, h, status::OBJECT_NAME_NOT_FOUND, chain);
        return;
    }

    let dir_requested = req.options & FILE_DIRECTORY_FILE != 0;
    let treat_as_dir = existing_dir || (dir_requested && !exists);

    if existing_dir && req.options & FILE_NON_DIRECTORY_FILE != 0 {
        err_resp(tx, h, status::FILE_IS_A_DIRECTORY, chain);
        return;
    }
    if exists && !existing_dir && dir_requested {
        err_resp(tx, h, status::NOT_A_DIRECTORY, chain);
        return;
    }

    let mut action = CREATE_ACTION_OPENED;
    let (fd, is_dir, writable) = if treat_as_dir {
        if !exists {
            let c = match vfs::cpath(&path) {
                Ok(c) => c,
                Err(e) => {
                    err_resp(tx, h, status::from_errno(e), chain);
                    return;
                }
            };
            if unsafe { libc::mkdir(c.as_ptr(), 0o755) } < 0 {
                err_resp(tx, h, status::from_errno(vfs::errno()), chain);
                return;
            }
            action = CREATE_ACTION_CREATED;
        }
        match vfs::open_raw(&path, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(fd) => (fd, true, false),
            Err(e) => {
                err_resp(tx, h, status::from_errno(e), chain);
                return;
            }
        }
    } else {
        let mut flags = match req.disposition {
            FILE_CREATE => libc::O_CREAT | libc::O_EXCL,
            FILE_OPEN_IF => libc::O_CREAT,
            FILE_OVERWRITE => libc::O_TRUNC,
            FILE_OVERWRITE_IF | FILE_SUPERSEDE => libc::O_CREAT | libc::O_TRUNC,
            _ => 0,
        };
        let try_rw =
            wants_write || (req.desired & MAXIMUM_ALLOWED != 0 && !share.read_only) || creates;
        flags |= if try_rw { libc::O_RDWR } else { libc::O_RDONLY };
        match vfs::open_raw(&path, flags, 0o644) {
            Ok(fd) => {
                if !exists {
                    action = CREATE_ACTION_CREATED;
                } else if flags & libc::O_TRUNC != 0 {
                    action = CREATE_ACTION_OVERWRITTEN;
                }
                (fd, false, try_rw)
            }
            Err(e) if e == libc::EACCES && try_rw && !wants_write => {
                // MAXIMUM_ALLOWED fallback: retry read-only.
                match vfs::open_raw(&path, (flags & !libc::O_RDWR) | libc::O_RDONLY, 0) {
                    Ok(fd) => (fd, false, false),
                    Err(e) => {
                        err_resp(tx, h, status::from_errno(e), chain);
                        return;
                    }
                }
            }
            Err(e) => {
                err_resp(tx, h, status::from_errno(e), chain);
                return;
            }
        }
    };

    let meta = match vfs::fstat_meta(fd) {
        Ok(m) => m,
        Err(e) => {
            unsafe { libc::close(fd) };
            err_resp(tx, h, status::from_errno(e), chain);
            return;
        }
    };
    let leaf = rel.rsplit('\\').next().unwrap_or("").to_string();
    let attrs = vfs::finalize_attrs(meta.attrs, &leaf);
    let fid = pc.handles.insert(OpenFile {
        fd,
        path,
        rel,
        leaf,
        share_idx,
        is_dir,
        writable,
        delete_on_close,
        dir: None,
    });
    chain.last_fid = Some(fid);

    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(89);
    tx.p8(0); // OplockLevel: none
    tx.p8(0);
    tx.p32(action);
    tx.p64(meta.crtime);
    tx.p64(meta.atime);
    tx.p64(meta.mtime);
    tx.p64(meta.ctime);
    tx.p64(meta.alloc);
    tx.p64(meta.size);
    tx.p32(attrs);
    tx.p32(0);
    put_fid(tx, fid);
    tx.p32(0); // CreateContextsOffset
    tx.p32(0); // CreateContextsLength
}

// -------------------------------------------------------------------- CLOSE

fn close(pc: &mut ProtoConn, h: &ReqHdr, body: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 24 {
            return None;
        }
        let flags = r.u16()?;
        r.skip(4)?;
        Some((flags, parse_fid(&mut r, chain)?))
    })();
    let Some((flags, fid)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(of) = pc.handles.remove(fid) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };

    let post_attrib = flags & 0x1 != 0;
    let meta = if post_attrib { vfs::fstat_meta(of.fd).ok() } else { None };

    let mut st = status::SUCCESS;
    if of.delete_on_close {
        let res = if of.is_dir {
            std::fs::remove_dir(&of.path)
        } else {
            std::fs::remove_file(&of.path)
        };
        if let Err(e) = res {
            st = status::from_errno(e.raw_os_error().unwrap_or(libc::EIO));
        }
    }
    if st != status::SUCCESS {
        err_resp(tx, h, st, chain);
        return;
    }

    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(60);
    tx.p16(if post_attrib { 1 } else { 0 });
    tx.p32(0);
    if let Some(m) = meta {
        tx.p64(m.crtime);
        tx.p64(m.atime);
        tx.p64(m.mtime);
        tx.p64(m.ctime);
        tx.p64(m.alloc);
        tx.p64(m.size);
        tx.p32(vfs::finalize_attrs(m.attrs, &of.leaf));
    } else {
        tx.zeros(52);
    }
}

fn flush(pc: &mut ProtoConn, h: &ReqHdr, body: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 24 {
            return None;
        }
        r.skip(2 + 4)?;
        parse_fid(&mut r, chain)
    })();
    let Some(fid) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(of) = pc.handles.get(fid) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    match vfs::fsync(of.fd) {
        Ok(()) => simple_resp(tx, h, chain),
        Err(e) => err_resp(tx, h, status::from_errno(e), chain),
    }
}

// --------------------------------------------------------------------- READ

fn read(
    pc: &mut ProtoConn,
    h: &ReqHdr,
    body: &[u8],
    chain: &mut Chain,
    tx: &mut Vec<u8>,
) -> Option<ZcReadPlan> {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 49 {
            return None;
        }
        r.skip(1 + 1)?; // padding, flags
        let length = r.u32()?;
        let offset = r.u64()?;
        let fid = parse_fid(&mut r, chain)?;
        let min_count = r.u32()?;
        Some((length, offset, fid, min_count))
    })();
    let Some((length, offset, fid, min_count)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return None;
    };
    let max_read = pc.max_read;
    let Some(of) = pc.handles.get(fid) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return None;
    };
    if of.is_dir {
        err_resp(tx, h, status::INVALID_DEVICE_REQUEST, chain);
        return None;
    }
    let length = length.min(max_read);

    // Standalone large reads take the zero-copy splice path.
    if chain.single && length >= ZC_MIN_READ {
        return Some(ZcReadPlan {
            fd: of.fd,
            offset,
            length,
            min_count,
            msg_id: h.msg_id,
            credit_charge: h.credit_charge,
            credits: h.credits,
            tree_id: chain.tree_id,
            session_id: chain.session_id,
        });
    }

    // Buffered fallback (small reads and compounds).
    let mut buf = vec![0u8; length as usize];
    match vfs::pread(of.fd, &mut buf, offset) {
        Ok(0) if length > 0 => err_resp(tx, h, status::END_OF_FILE, chain),
        Ok(n) if (n as u32) < min_count => err_resp(tx, h, status::END_OF_FILE, chain),
        Ok(n) => {
            begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
            tx.p16(17);
            tx.p8(80);
            tx.p8(0);
            tx.p32(n as u32);
            tx.p32(0);
            tx.p32(0);
            tx.pbytes(&buf[..n]);
        }
        Err(e) => err_resp(tx, h, status::from_errno(e), chain),
    }
    None
}

// -------------------------------------------------------------------- WRITE

fn write(pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>, share: &ShareCfg) {
    let parsed = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 49 {
            return None;
        }
        let data_off = r.u16()? as usize;
        let length = r.u32()? as usize;
        let offset = r.u64()?;
        let fid = parse_fid(&mut r, chain)?;
        let data = msg.get(data_off..data_off + length)?;
        Some((data, offset, fid))
    })();
    let Some((data, offset, fid)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    if share.read_only {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }
    let Some(of) = pc.handles.get(fid) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    if !of.writable {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }
    match vfs::pwrite_all(of.fd, data, offset) {
        Ok(()) => {
            begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
            tx.p16(17);
            tx.p16(0);
            tx.p32(data.len() as u32);
            tx.p32(0); // Remaining
            tx.p16(0);
            tx.p16(0);
        }
        Err(e) => err_resp(tx, h, status::from_errno(e), chain),
    }
}

// ---------------------------------------------------------- QUERY_DIRECTORY

const QD_RESTART_SCANS: u8 = 0x01;
const QD_RETURN_SINGLE: u8 = 0x02;
const QD_REOPEN: u8 = 0x10;

fn query_directory(pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 33 {
            return None;
        }
        let class = r.u8()?;
        let flags = r.u8()?;
        let _index = r.u32()?;
        let fid = parse_fid(&mut r, chain)?;
        let name_off = r.u16()? as usize;
        let name_len = r.u16()? as usize;
        let out_len = r.u32()?;
        let pattern = if name_len == 0 {
            String::new()
        } else {
            from_utf16le(msg.get(name_off..name_off + name_len)?)
        };
        Some((class, flags, fid, out_len, pattern))
    })();
    let Some((class, flags, fid, out_len, pattern)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(of) = pc.handles.get(fid) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    if !of.is_dir {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    }

    let restart = flags & (QD_RESTART_SCANS | QD_REOPEN) != 0;
    let need_new = match &of.dir {
        None => true,
        Some(d) => restart || d.pattern != pattern,
    };
    if need_new {
        match vfs::dir_snapshot(of, &pattern) {
            Ok(entries) => of.dir = Some(DirState { entries, pos: 0, pattern: pattern.clone() }),
            Err(e) => {
                err_resp(tx, h, status::from_errno(e), chain);
                return;
            }
        }
    }
    let dstate = of.dir.as_mut().expect("dir state set above");
    if dstate.pos >= dstate.entries.len() {
        let st = if dstate.entries.is_empty() { status::NO_SUCH_FILE } else { status::NO_MORE_FILES };
        err_resp(tx, h, st, chain);
        return;
    }

    let out_len = out_len.min(MAX_TRANSACT) as usize;
    let mut data: Vec<u8> = Vec::with_capacity(out_len.min(64 * 1024));
    let mut last_entry_start = 0usize;
    let mut emitted = 0usize;
    while dstate.pos < dstate.entries.len() {
        let e = &dstate.entries[dstate.pos];
        let mut entry: Vec<u8> = Vec::with_capacity(128 + e.name.len() * 2);
        if !put_dir_entry(&mut entry, class, e) {
            err_resp(tx, h, status::INVALID_PARAMETER, chain);
            return;
        }
        // Align to 8 and stamp NextEntryOffset (rewritten to 0 on the last).
        let pad = (8 - (entry.len() % 8)) % 8;
        entry.resize(entry.len() + pad, 0);
        let next = entry.len() as u32;
        entry[0..4].copy_from_slice(&next.to_le_bytes());
        if data.len() + entry.len() > out_len {
            break;
        }
        last_entry_start = data.len();
        data.pbytes(&entry);
        dstate.pos += 1;
        emitted += 1;
        if flags & QD_RETURN_SINGLE != 0 {
            break;
        }
    }
    if emitted == 0 {
        // First entry alone doesn't fit the client buffer.
        err_resp(tx, h, status::BUFFER_TOO_SMALL, chain);
        return;
    }
    data[last_entry_start..last_entry_start + 4].copy_from_slice(&0u32.to_le_bytes());

    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(9);
    tx.p16(72);
    tx.p32(data.len() as u32);
    tx.pbytes(&data);
}

// File information classes (query directory + query info)
const FILE_DIRECTORY_INFORMATION: u8 = 1;
const FILE_FULL_DIRECTORY_INFORMATION: u8 = 2;
const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 3;
const FILE_NAMES_INFORMATION: u8 = 12;
const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 37;
const FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 38;

fn put_dir_entry(b: &mut Vec<u8>, class: u8, e: &vfs::DirEnt) -> bool {
    let name = utf16le(&e.name);
    let m = &e.meta;
    b.p32(0); // NextEntryOffset, patched by caller
    b.p32(0); // FileIndex
    if class == FILE_NAMES_INFORMATION {
        b.p32(name.len() as u32);
        b.pbytes(&name);
        return true;
    }
    b.p64(m.crtime);
    b.p64(m.atime);
    b.p64(m.mtime);
    b.p64(m.ctime);
    b.p64(m.size);
    b.p64(m.alloc);
    b.p32(m.attrs);
    b.p32(name.len() as u32);
    match class {
        FILE_DIRECTORY_INFORMATION => {}
        FILE_FULL_DIRECTORY_INFORMATION => {
            b.p32(0); // EaSize
        }
        FILE_BOTH_DIRECTORY_INFORMATION => {
            b.p32(0); // EaSize
            b.p8(0); // ShortNameLength
            b.p8(0);
            b.zeros(24); // ShortName
        }
        FILE_ID_BOTH_DIRECTORY_INFORMATION => {
            b.p32(0);
            b.p8(0);
            b.p8(0);
            b.zeros(24);
            b.p16(0); // Reserved2
            b.p64(m.ino);
        }
        FILE_ID_FULL_DIRECTORY_INFORMATION => {
            b.p32(0); // EaSize
            b.p32(0); // Reserved
            b.p64(m.ino);
        }
        _ => return false,
    }
    b.pbytes(&name);
    true
}

// --------------------------------------------------------------- QUERY_INFO

const INFO_FILE: u8 = 1;
const INFO_FILESYSTEM: u8 = 2;

fn query_info(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, body: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 41 {
            return None;
        }
        let info_type = r.u8()?;
        let class = r.u8()?;
        let out_len = r.u32()?;
        r.skip(2 + 2 + 4 + 4 + 4)?; // in off, reserved, in len, addl, flags
        let fid = parse_fid(&mut r, chain)?;
        Some((info_type, class, out_len, fid))
    })();
    let Some((info_type, class, out_len, fid)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(of) = pc.handles.get(fid) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };

    let mut data: Vec<u8> = Vec::new();
    let st = match info_type {
        INFO_FILE => file_info(of, class, &mut data),
        INFO_FILESYSTEM => fs_info(srv, of, class, &mut data),
        _ => status::ACCESS_DENIED, // SECURITY/QUOTA unsupported in phase 1
    };
    if st != status::SUCCESS {
        err_resp(tx, h, st, chain);
        return;
    }
    let mut final_st = status::SUCCESS;
    if data.len() > out_len as usize {
        data.truncate(out_len as usize);
        final_st = status::BUFFER_OVERFLOW;
    }
    begin_resp(tx, h, final_st, chain.related, chain.tree_id, chain.session_id);
    tx.p16(9);
    tx.p16(72);
    tx.p32(data.len() as u32);
    tx.pbytes(&data);
}

fn put_basic_info(b: &mut Vec<u8>, m: &vfs::Meta, attrs: u32) {
    b.p64(m.crtime);
    b.p64(m.atime);
    b.p64(m.mtime);
    b.p64(m.ctime);
    b.p32(attrs);
    b.p32(0);
}

fn put_standard_info(b: &mut Vec<u8>, m: &vfs::Meta, delete_pending: bool) {
    b.p64(m.alloc);
    b.p64(m.size);
    b.p32(m.nlink);
    b.p8(delete_pending as u8);
    b.p8(m.is_dir as u8);
    b.p16(0);
}

fn file_info(of: &vfs::OpenFile, class: u8, b: &mut Vec<u8>) -> u32 {
    let m = match vfs::fstat_meta(of.fd) {
        Ok(m) => m,
        Err(e) => return status::from_errno(e),
    };
    let attrs = vfs::finalize_attrs(m.attrs, &of.leaf);
    match class {
        4 => put_basic_info(b, &m, attrs), // FileBasicInformation
        5 => put_standard_info(b, &m, of.delete_on_close), // FileStandardInformation
        6 => b.p64(m.ino),                 // FileInternalInformation
        7 => b.p32(0),                     // FileEaInformation
        8 => b.p32(MAXIMAL_ACCESS_ALL),    // FileAccessInformation
        9 => {
            // FileNameInformation
            let name = utf16le(&format!("\\{}", of.rel));
            b.p32(name.len() as u32);
            b.pbytes(&name);
        }
        14 => b.p64(0), // FilePositionInformation
        16 => b.p32(0), // FileModeInformation
        17 => b.p32(0), // FileAlignmentInformation
        18 => {
            // FileAllInformation
            put_basic_info(b, &m, attrs);
            put_standard_info(b, &m, of.delete_on_close);
            b.p64(m.ino);
            b.p32(0); // Ea
            b.p32(MAXIMAL_ACCESS_ALL);
            b.p64(0); // Position
            b.p32(0); // Mode
            b.p32(0); // Alignment
            let name = utf16le(&format!("\\{}", of.rel));
            b.p32(name.len() as u32);
            b.pbytes(&name);
        }
        34 => {
            // FileNetworkOpenInformation
            b.p64(m.crtime);
            b.p64(m.atime);
            b.p64(m.mtime);
            b.p64(m.ctime);
            b.p64(m.alloc);
            b.p64(m.size);
            b.p32(attrs);
            b.p32(0);
        }
        35 => {
            // FileAttributeTagInformation
            b.p32(attrs);
            b.p32(0);
        }
        _ => return status::NOT_SUPPORTED,
    }
    status::SUCCESS
}

fn fs_info(srv: &Srv, of: &vfs::OpenFile, class: u8, b: &mut Vec<u8>) -> u32 {
    match class {
        1 => {
            // FileFsVolumeInformation
            let label = utf16le(&srv.cfg.shares[of.share_idx as usize].name);
            b.p64(srv.start_ft);
            b.p32(0x52_4B54); // serial "RKT"
            b.p32(label.len() as u32);
            b.p8(0); // SupportsObjects
            b.p8(0);
            b.pbytes(&label);
        }
        3 => {
            // FileFsSizeInformation
            let (total, avail, _, spu, bps) = match vfs::fs_sizes(of.fd) {
                Ok(v) => v,
                Err(e) => return status::from_errno(e),
            };
            b.p64(total);
            b.p64(avail);
            b.p32(spu);
            b.p32(bps);
        }
        4 => {
            // FileFsDeviceInformation
            b.p32(7); // FILE_DEVICE_DISK
            b.p32(0x20); // FILE_DEVICE_IS_MOUNTED
        }
        5 => {
            // FileFsAttributeInformation
            let name = utf16le("NTFS");
            b.p32(0x47); // case-sensitive | case-preserved | unicode | sparse
            b.p32(255);
            b.p32(name.len() as u32);
            b.pbytes(&name);
        }
        7 => {
            // FileFsFullSizeInformation
            let (total, avail, free, spu, bps) = match vfs::fs_sizes(of.fd) {
                Ok(v) => v,
                Err(e) => return status::from_errno(e),
            };
            b.p64(total);
            b.p64(avail);
            b.p64(free);
            b.p32(spu);
            b.p32(bps);
        }
        _ => return status::NOT_SUPPORTED,
    }
    status::SUCCESS
}

// ----------------------------------------------------------------- SET_INFO

fn set_info(pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>, share: &ShareCfg) {
    let parsed = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 33 {
            return None;
        }
        let info_type = r.u8()?;
        let class = r.u8()?;
        let buf_len = r.u32()? as usize;
        let buf_off = r.u16()? as usize;
        r.skip(2 + 4)?;
        let fid = parse_fid(&mut r, chain)?;
        let data = msg.get(buf_off..buf_off + buf_len)?;
        Some((info_type, class, fid, data))
    })();
    let Some((info_type, class, fid, data)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    if info_type != INFO_FILE {
        err_resp(tx, h, status::NOT_SUPPORTED, chain);
        return;
    }
    if share.read_only {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }
    let share_root = share.path.clone();
    let Some(of) = pc.handles.get(fid) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };

    let st = match class {
        4 => set_basic_info(of, data),
        13 => set_disposition(of, data),
        10 => set_rename(of, data, &share_root),
        19 => status::SUCCESS, // FileAllocationInformation: best-effort no-op
        20 => {
            // FileEndOfFileInformation
            let mut r = Rdr::new(data);
            match r.u64() {
                Some(len) => match vfs::ftruncate(of.fd, len) {
                    Ok(()) => status::SUCCESS,
                    Err(e) => status::from_errno(e),
                },
                None => status::INVALID_PARAMETER,
            }
        }
        _ => status::NOT_SUPPORTED,
    };
    if st != status::SUCCESS {
        err_resp(tx, h, st, chain);
        return;
    }
    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(2);
}

fn set_basic_info(of: &vfs::OpenFile, data: &[u8]) -> u32 {
    let mut r = Rdr::new(data);
    let (Some(_cr), Some(at), Some(mt), Some(_ct), Some(_attrs)) =
        (r.u64(), r.u64(), r.u64(), r.u64(), r.u32())
    else {
        return status::INVALID_PARAMETER;
    };
    fn ts(ft: u64) -> libc::timespec {
        if ft == 0 || ft == u64::MAX {
            libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }
        } else {
            let unix100 = ft as i64 - 116_444_736_000_000_000;
            libc::timespec {
                tv_sec: (unix100 / 10_000_000) as _,
                tv_nsec: ((unix100 % 10_000_000) * 100) as _,
            }
        }
    }
    let times = [ts(at), ts(mt)];
    if unsafe { libc::futimens(of.fd, times.as_ptr()) } < 0 {
        // Attribute-only updates (archive bit etc.) succeed as a no-op.
        let e = vfs::errno();
        if e != libc::EACCES && e != libc::EPERM {
            return status::from_errno(e);
        }
    }
    status::SUCCESS
}

fn set_disposition(of: &mut vfs::OpenFile, data: &[u8]) -> u32 {
    let Some(&flag) = data.first() else {
        return status::INVALID_PARAMETER;
    };
    if flag != 0 && of.is_dir {
        // Windows semantics: refuse marking a non-empty directory.
        match std::fs::read_dir(&of.path) {
            Ok(mut it) => {
                if it.next().is_some() {
                    return status::DIRECTORY_NOT_EMPTY;
                }
            }
            Err(e) => return status::from_errno(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }
    of.delete_on_close = flag != 0;
    status::SUCCESS
}

fn set_rename(of: &mut vfs::OpenFile, data: &[u8], share_root: &Path) -> u32 {
    let mut r = Rdr::new(data);
    let parsed = (|| {
        let replace = r.u8()? != 0;
        r.skip(7 + 8)?; // reserved, RootDirectory
        let name_len = r.u32()? as usize;
        let name = from_utf16le(r.take(name_len)?);
        Some((replace, name))
    })();
    let Some((replace, name)) = parsed else {
        return status::INVALID_PARAMETER;
    };
    let (new_path, new_rel) = match vfs::resolve(share_root, &name) {
        Ok(v) => v,
        Err(st) => return st,
    };
    if !replace && new_path.exists() {
        return status::OBJECT_NAME_COLLISION;
    }
    if let Err(e) = std::fs::rename(&of.path, &new_path) {
        return status::from_errno(e.raw_os_error().unwrap_or(libc::EIO));
    }
    of.leaf = new_rel.rsplit('\\').next().unwrap_or("").to_string();
    of.path = new_path;
    of.rel = new_rel;
    status::SUCCESS
}

// -------------------------------------------------------------------- IOCTL

fn ioctl(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 57 {
            return None;
        }
        r.skip(2)?;
        let ctl = r.u32()?;
        r.skip(16)?; // FileId
        Some(ctl)
    })();
    let Some(ctl) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    if ctl != FSCTL_VALIDATE_NEGOTIATE_INFO {
        err_resp(tx, h, status::NOT_SUPPORTED, chain);
        return;
    }
    // Echo our negotiated parameters so the client can verify them.
    let mut out: Vec<u8> = Vec::with_capacity(24);
    out.p32(CAP_LARGE_MTU);
    out.pbytes(&srv.guid);
    out.p16(SECURITY_MODE_SIGNING_ENABLED);
    out.p16(pc.dialect);

    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(49);
    tx.p16(0);
    tx.p32(ctl);
    tx.p64(u64::MAX); // FileId
    tx.p64(u64::MAX);
    tx.p32(112); // InputOffset
    tx.p32(0); // InputCount
    tx.p32(112); // OutputOffset
    tx.p32(out.len() as u32);
    tx.p32(0); // Flags
    tx.p32(0);
    tx.pbytes(&out);
}
