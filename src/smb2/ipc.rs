//! Requests on an IPC$ tree: named pipes forwarded to the RPC backend (#83),
//! plus the IOCTLs IPC$ always answered (VALIDATE_NEGOTIATE_INFO, network
//! interface info). See `crate::pipe` for the backend side.

use super::*;
use crate::config::Srv;
use crate::pipe::{self, PipeOpen};
use crate::session::{SessionInner, SessionRef};
use crate::status;
use crate::wire::{Put, Rdr};

pub const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
/// Open pipes one session may hold.
const MAX_PIPES_PER_SESSION: usize = 64;
/// Pended pipe reads one connection may hold.
const MAX_PIPE_PENDS_PER_CONN: usize = 64;
/// FILE_ATTRIBUTE_NORMAL
const ATTR_NORMAL: u32 = 0x80;

/// Handle one request on an IPC$ tree.
pub fn dispatch(srv: &Srv, pc: &mut ProtoConn, sref: &SessionRef, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    if h.command == CMD_IOCTL && ioctl_code(msg) != Some(FSCTL_PIPE_TRANSCEIVE) {
        super::handlers::ioctl(srv, pc, h, msg, chain, tx);
        return;
    }
    if !matches!(h.command, CMD_CREATE | CMD_CLOSE | CMD_READ | CMD_WRITE | CMD_IOCTL) {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }
    let mut sess = sref.lock().unwrap();
    if let Err(st) = gate(pc, &sess, h, chain) {
        drop(sess);
        err_resp(tx, h, st, chain);
        return;
    }
    match h.command {
        CMD_CREATE => create(srv, pc, &mut sess, h, msg, chain, tx),
        CMD_CLOSE => close(pc, &mut sess, h, msg, chain, tx),
        CMD_WRITE => write(&mut sess, h, msg, chain, tx),
        CMD_READ => read(pc, &mut sess, h, msg, chain, tx),
        _ => transceive(pc, &mut sess, h, msg, chain, tx),
    }
}

/// Pipes carry the session key to the backend and the backend's answers
/// (SAMR password sets among them) back: only an authenticated user, and
/// only on requests whose integrity is protected — signed, or sealed.
fn gate(pc: &ProtoConn, sess: &SessionInner, h: &ReqHdr, chain: &Chain) -> Result<(), u32> {
    if sess.guest || !sess.established {
        return Err(status::ACCESS_DENIED);
    }
    let sealed = chain.transform_sid.is_some();
    // dispatch() has verified the signature of a request flagged SIGNED.
    let signed = h.flags & FLAG_SIGNED != 0
        && pc.channels.get(&chain.session_id).is_some_and(|c| c.sign.is_some());
    if sealed || signed {
        Ok(())
    } else {
        Err(status::ACCESS_DENIED)
    }
}

fn ioctl_code(msg: &[u8]) -> Option<u32> {
    let b = msg.get(64..)?;
    Some(u32::from_le_bytes(b.get(4..8)?.try_into().ok()?))
}

/// `samr`, `\samr`, `PIPE\samr` and `\PIPE\samr` all name pipe `samr`.
fn pipe_name(raw: &str) -> &str {
    let n = raw.trim_start_matches('\\');
    match n.get(..5) {
        Some(p) if p.eq_ignore_ascii_case("pipe\\") => &n[5..],
        _ => n,
    }
}

fn create(srv: &Srv, pc: &mut ProtoConn, sess: &mut SessionInner, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let Some(ipc) = &srv.cfg.ipc else {
        err_resp(tx, h, status::OBJECT_NAME_NOT_FOUND, chain);
        return;
    };
    let Some(name) = super::handlers::create_name(msg) else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(pipe) = ipc.served(pipe_name(&name)) else {
        err_resp(tx, h, status::OBJECT_NAME_NOT_FOUND, chain);
        return;
    };
    if sess.pipes.len() >= MAX_PIPES_PER_SESSION {
        err_resp(tx, h, status::INSUFFICIENT_RESOURCES, chain);
        return;
    }
    let mut flags = 0u16;
    if h.flags & FLAG_SIGNED != 0 {
        flags |= pipe::FLAG_SIGNED;
    }
    if chain.transform_sid.is_some() {
        flags |= pipe::FLAG_ENCRYPTED;
    }
    if sess.kerberos {
        flags |= pipe::FLAG_KERBEROS;
    }
    let pac = sess.pac.as_ref();
    let id = pipe::Identity {
        pipe: &pipe,
        flags,
        dialect: pc.dialect,
        session_key: &sess.app_key,
        user: &sess.user,
        domain: pac.map(|p| p.domain.as_str()).unwrap_or(""),
        user_sid: pac.and_then(|p| p.user_sid.as_ref()).map(|s| s.to_string()).unwrap_or_default(),
        groups: pac.map(|p| p.groups.iter().map(|g| g.to_string()).collect()).unwrap_or_default(),
    };
    let open = match PipeOpen::open(&ipc.backend, chain.tree_id, &id) {
        Ok(o) => o,
        Err(st) => {
            err_resp(tx, h, st, chain);
            return;
        }
    };
    sess.next_pipe_id += 1;
    let fid = sess.next_pipe_id;
    sess.pipes.insert(fid, open);
    chain.last_fid = Some(fid);
    crate::logi!("session {:x}: pipe {pipe:?} opened for {:?}", chain.session_id, sess.user);

    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(89);
    tx.p8(0); // OplockLevel: none
    tx.p8(0);
    tx.p32(1); // CreateAction: FILE_OPENED
    tx.zeros(32); // creation/access/write/change times
    tx.p64(4096); // AllocationSize
    tx.p64(0); // EndOfFile
    tx.p32(ATTR_NORMAL);
    tx.p32(0);
    tx.p64(fid);
    tx.p64(fid);
    tx.p32(0); // CreateContextsOffset
    tx.p32(0); // CreateContextsLength
}

fn fid_at(r: &mut Rdr, chain: &Chain) -> Option<u64> {
    let persistent = r.u64()?;
    let volatile = r.u64()?;
    if persistent == u64::MAX && volatile == u64::MAX {
        chain.last_fid
    } else {
        Some(volatile)
    }
}

/// End every pend on pipe `fid` with `st`.
fn end_pends(pc: &mut ProtoConn, fid: u64, st: u32) {
    let mut i = 0;
    while i < pc.pipe_active.len() {
        if pc.pipe_active[i].0 == fid {
            let (_, async_id) = pc.pipe_active.remove(i);
            pc.pipe_done.push(NotifyDone { async_id, status: st });
        } else {
            i += 1;
        }
    }
}

/// Close the pipes of IPC$ tree `tree_id` (TREE_DISCONNECT).
pub fn close_tree(pc: &mut ProtoConn, sess: &mut SessionInner, tree_id: u32) {
    let fids: Vec<u64> = sess.pipes.iter().filter(|(_, p)| p.tree_id == tree_id).map(|(&f, _)| f).collect();
    for fid in fids {
        sess.pipes.remove(&fid);
        end_pends(pc, fid, status::CANCELLED);
    }
}

fn close(pc: &mut ProtoConn, sess: &mut SessionInner, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let fid = (|| {
        let mut r = Rdr::new(msg.get(64..)?);
        if r.u16()? != 24 {
            return None;
        }
        r.skip(2 + 4)?; // Flags, Reserved
        fid_at(&mut r, chain)
    })();
    let Some(fid) = fid else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    if !sess.pipes.get(&fid).is_some_and(|p| p.tree_id == chain.tree_id) {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    }
    // Dropping the pipe shuts its socket down: the backend sees the close.
    sess.pipes.remove(&fid);
    end_pends(pc, fid, status::CANCELLED);
    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(60);
    tx.p16(0); // Flags: no attributes returned
    tx.p32(0);
    tx.zeros(52);
}

fn pipe_of<'a>(sess: &'a mut SessionInner, fid: u64, tree_id: u32) -> Option<&'a mut PipeOpen> {
    sess.pipes.get_mut(&fid).filter(|p| p.tree_id == tree_id)
}

fn write(sess: &mut SessionInner, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(msg.get(64..)?);
        if r.u16()? != 49 {
            return None;
        }
        let data_off = r.u16()? as usize;
        let length = r.u32()? as usize;
        r.skip(8)?; // Offset: a pipe is a stream
        let fid = fid_at(&mut r, chain)?;
        Some((msg.get(data_off..data_off.checked_add(length)?)?, fid))
    })();
    let Some((data, fid)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(p) = pipe_of(sess, fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    if let Err(st) = p.write(data) {
        err_resp(tx, h, st, chain);
        return;
    }
    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(17);
    tx.p16(0);
    tx.p32(data.len() as u32); // Count
    tx.p32(0); // Remaining
    tx.p16(0); // WriteChannelInfoOffset
    tx.p16(0); // WriteChannelInfoLength
}

fn read(pc: &mut ProtoConn, sess: &mut SessionInner, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(msg.get(64..)?);
        if r.u16()? != 49 {
            return None;
        }
        r.skip(2)?; // Padding, Flags
        let length = r.u32()?;
        r.skip(8)?; // Offset
        let fid = fid_at(&mut r, chain)?;
        Some((length, fid))
    })();
    let Some((length, fid)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let max = length.min(pc.max_read);
    deliver(pc, sess, h, chain, tx, fid, max, CMD_READ);
}

fn transceive(pc: &mut ProtoConn, sess: &mut SessionInner, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(msg.get(64..)?);
        if r.u16()? != 57 {
            return None;
        }
        r.skip(2 + 4)?; // Reserved, CtlCode
        let fid = fid_at(&mut r, chain)?;
        let in_off = r.u32()? as usize;
        let in_len = r.u32()? as usize;
        r.skip(4 + 4 + 4)?; // MaxInputResponse, OutputOffset, OutputCount
        let max_out = r.u32()?;
        let flags = r.u32()?;
        let input = if in_len == 0 { &[][..] } else { msg.get(in_off..in_off.checked_add(in_len)?)? };
        Some((fid, input, max_out, flags))
    })();
    let Some((fid, input, max_out, flags)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    if flags & 1 == 0 {
        // SMB2_0_IOCTL_IS_FSCTL must be set for an FSCTL.
        err_resp(tx, h, status::INVALID_DEVICE_REQUEST, chain);
        return;
    }
    let Some(p) = pipe_of(sess, fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    if pc.pipe_active.iter().any(|&(f, _)| f == fid) {
        // A read is already waiting on this pipe: its answer would be ours.
        err_resp(tx, h, status::PIPE_BUSY, chain);
        return;
    }
    if let Err(st) = p.write(input) {
        err_resp(tx, h, st, chain);
        return;
    }
    let max = max_out.min(MAX_TRANSACT);
    deliver(pc, sess, h, chain, tx, fid, max, CMD_IOCTL);
}

fn read_body(data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(16 + data.len());
    b.p16(17);
    b.p8(0x50); // DataOffset: right after the 64-byte header + 16
    b.p8(0);
    b.p32(data.len() as u32);
    b.p32(0); // DataRemaining
    b.p32(0);
    b.pbytes(data);
    b
}

fn ioctl_body(fid: u64, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(48 + data.len());
    b.p16(49);
    b.p16(0);
    b.p32(FSCTL_PIPE_TRANSCEIVE);
    b.p64(fid);
    b.p64(fid);
    b.p32(112); // InputOffset
    b.p32(0); // InputCount
    b.p32(112); // OutputOffset: 64-byte header + 48
    b.p32(data.len() as u32);
    b.p32(0); // Flags
    b.p32(0);
    b.pbytes(data);
    b
}

fn body_for(cmd: u16, fid: u64, data: &[u8]) -> Vec<u8> {
    if cmd == CMD_READ {
        read_body(data)
    } else {
        ioctl_body(fid, data)
    }
}

/// Answer a READ / TRANSCEIVE now if the backend's message is there, else
/// pend it for the reactor.
#[allow(clippy::too_many_arguments)]
fn deliver(pc: &mut ProtoConn, sess: &mut SessionInner, h: &ReqHdr, chain: &mut Chain, tx: &mut Vec<u8>, fid: u64, max: u32, cmd: u16) {
    if pc.pipe_active.iter().any(|&(f, _)| f == fid) {
        // A read is already waiting on this pipe; the next message is its.
        err_resp(tx, h, status::PIPE_BUSY, chain);
        return;
    }
    let Some(p) = pipe_of(sess, fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    match p.read(max as usize) {
        Ok(Some((data, overflow))) => {
            let st = if overflow { status::BUFFER_OVERFLOW } else { status::SUCCESS };
            begin_resp(tx, h, st, chain.related, chain.tree_id, chain.session_id);
            tx.pbytes(&body_for(cmd, fid, &data));
        }
        Err(st) => err_resp(tx, h, st, chain),
        Ok(None) => {
            if pc.pipe_active.len() >= MAX_PIPE_PENDS_PER_CONN {
                err_resp(tx, h, status::INSUFFICIENT_RESOURCES, chain);
                return;
            }
            // SAFETY: integer-only syscall; the dup is owned by the pend (the
            // reactor closes it when the pend ends).
            let fd = unsafe { libc::fcntl(p.raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if fd < 0 {
                err_resp(tx, h, status::INSUFFICIENT_RESOURCES, chain);
                return;
            }
            let async_id = pc.next_async_id;
            pc.next_async_id += 1;
            let meta = AsyncMeta {
                msg_id: h.msg_id,
                credit_charge: h.credit_charge,
                session_id: chain.session_id,
                async_id,
                // Sealed requests are answered sealed (build_async_final);
                // the rest arrived signed (gate) and are answered signed.
                want_sign: chain.transform_sid.is_none(),
            };
            pc.pipe_new.push(PipePend { async_id, fid, tree_id: chain.tree_id, fd, max, cmd, meta: meta.clone() });
            pc.pipe_active.push((fid, async_id));
            begin_resp_async(tx, &meta, status::PENDING, h.credits, cmd);
            err_body(tx);
        }
    }
}

/// The reactor saw a pended pipe's socket become readable: the final
/// response if a message (or an error) is there now, `None` to keep waiting.
pub fn pipe_ready(srv: &Srv, pc: &mut ProtoConn, pend: &PipePend) -> Option<Vec<u8>> {
    if !pc.pipe_active.iter().any(|&(_, a)| a == pend.async_id) {
        return None; // already ended by CANCEL / CLOSE
    }
    let res = match srv.sessions.get(pend.meta.session_id) {
        None => Err(status::FILE_CLOSED),
        Some(sref) => {
            let mut s = sref.lock().unwrap();
            match pipe_of(&mut s, pend.fid, pend.tree_id) {
                None => Err(status::FILE_CLOSED),
                Some(p) => p.read(pend.max as usize),
            }
        }
    };
    let resp = match res {
        Ok(None) => return None,
        Ok(Some((data, overflow))) => {
            let st = if overflow { status::BUFFER_OVERFLOW } else { status::SUCCESS };
            build_async_final(pc, &pend.meta, st, pend.cmd, Some(&body_for(pend.cmd, pend.fid, &data)))
        }
        Err(st) => build_async_final(pc, &pend.meta, st, pend.cmd, None),
    };
    pc.pipe_active.retain(|&(_, a)| a != pend.async_id);
    Some(resp)
}

/// The final response of a pend ended by CANCEL / CLOSE.
pub fn pipe_end(pc: &mut ProtoConn, pend: &PipePend, st: u32) -> Vec<u8> {
    build_async_final(pc, &pend.meta, st, pend.cmd, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SignAlg;
    use crate::fuzzing::srv_from_toml;
    use crate::smb2::{process_frame, sign_in_place, verify_signature, ChannelState, FrameAction, SignCtx, FLAG_ASYNC};
    use crate::wire::utf16le;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    struct Bed {
        srv: Srv,
        pc: ProtoConn,
        sid: u64,
        sc: SignCtx,
        listener: UnixListener,
        dir: std::path::PathBuf,
        msg_id: u64,
    }

    impl Drop for Bed {
        fn drop(&mut self) {
            for p in self.pc.pipe_new.drain(..) {
                // SAFETY: the test owns the pend's dup (no reactor here).
                unsafe { libc::close(p.fd) };
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    const APP_KEY: [u8; 16] = [0x11; 16];

    /// A server with `[ipc]` pointing at a listening socket, and one signed
    /// 3.1.1 session (`guest` = a guest session instead).
    fn bed(tag: &str, guest: bool) -> Bed {
        let mut rnd = [0u8; 8];
        crate::config::urandom(&mut rnd);
        let dir = std::env::temp_dir().join(format!("rsmbd-ipc-{tag}-{:x}", u64::from_le_bytes(rnd)));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("rpc.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let srv = srv_from_toml(&format!(
            "server_name = \"T\"\nworkers = 1\ncore_pinning = false\n\
             [ipc]\nbackend = '{}'\n[[share]]\nname = \"t\"\npath = '{}'\n",
            sock.display(),
            dir.display()
        ));
        let mut pc = ProtoConn::new(&srv, 0, 0, 1);
        let (sid, sref) = srv.sessions.create();
        {
            let mut s = sref.lock().unwrap();
            s.established = true;
            s.channels = 1;
            s.guest = guest;
            s.user = "admin".into();
            s.app_key = APP_KEY;
        }
        let sc = SignCtx { alg: SignAlg::AesCmac, key: [5; 16] };
        pc.dialect = 0x0311;
        pc.negotiated = true;
        pc.channels.insert(
            sid,
            ChannelState { established: true, sign: if guest { None } else { Some(sc.clone()) }, ..Default::default() },
        );
        Bed { srv, pc, sid, sc, listener, dir, msg_id: 0 }
    }

    struct R {
        status: u32,
        flags: u32,
        async_id: u64,
        body: Vec<u8>,
        raw: Vec<u8>,
    }

    fn parse(tx: &[u8]) -> R {
        let h = &tx[4..68];
        R {
            status: u32::from_le_bytes(h[8..12].try_into().unwrap()),
            flags: u32::from_le_bytes(h[16..20].try_into().unwrap()),
            async_id: u64::from_le_bytes(h[32..40].try_into().unwrap()),
            body: tx[68..].to_vec(),
            raw: tx[4..].to_vec(),
        }
    }

    impl Bed {
        fn req(&mut self, cmd: u16, tree: u32, body: &[u8], sign: bool) -> R {
            let mut f: Vec<u8> = Vec::new();
            f.pbytes(&[0xFE, b'S', b'M', b'B']);
            f.p16(64);
            f.p16(1);
            f.p32(0);
            f.p16(cmd);
            f.p16(8);
            f.p32(0);
            f.p32(0);
            f.p64(self.msg_id);
            self.msg_id += 1;
            f.p32(0);
            f.p32(tree);
            f.p64(self.sid);
            f.zeros(16);
            f.pbytes(body);
            if sign {
                let n = f.len();
                sign_in_place(&mut f, 0, n, &self.sc);
            }
            let mut tx = Vec::new();
            let act = process_frame(&self.srv, &mut self.pc, &f, &mut tx);
            assert!(matches!(act, FrameAction::Respond));
            parse(&tx)
        }

        fn tree(&mut self) -> u32 {
            let path = utf16le("\\\\srv\\IPC$");
            let mut b = Vec::new();
            b.p16(9);
            b.p16(0);
            b.p16(72);
            b.p16(path.len() as u16);
            b.pbytes(&path);
            let r = self.req(CMD_TREE_CONNECT, 0, &b, true);
            assert_eq!(r.status, status::SUCCESS);
            u32::from_le_bytes(r.raw[36..40].try_into().unwrap())
        }

        fn create(&mut self, tree: u32, name: &str, sign: bool) -> (u32, u64) {
            let n = utf16le(name);
            let mut b = Vec::new();
            b.p16(57);
            b.p8(0);
            b.p8(0);
            b.p32(2);
            b.p64(0);
            b.p64(0);
            b.p32(0x0012_019F); // read/write data
            b.p32(0);
            b.p32(3);
            b.p32(1); // FILE_OPEN
            b.p32(0);
            b.p16(120);
            b.p16(n.len() as u16);
            b.p32(0);
            b.p32(0);
            b.pbytes(&n);
            let r = self.req(CMD_CREATE, tree, &b, sign);
            let fid = if r.status == status::SUCCESS { u64::from_le_bytes(r.body[72..80].try_into().unwrap()) } else { 0 };
            (r.status, fid)
        }

        fn transceive(&mut self, tree: u32, fid: u64, input: &[u8], max_out: u32) -> R {
            let mut b = Vec::new();
            b.p16(57);
            b.p16(0);
            b.p32(FSCTL_PIPE_TRANSCEIVE);
            b.p64(fid);
            b.p64(fid);
            b.p32(120); // InputOffset
            b.p32(input.len() as u32);
            b.p32(0);
            b.p32(0);
            b.p32(0);
            b.p32(max_out);
            b.p32(1); // IS_FSCTL
            b.p32(0);
            b.pbytes(input);
            self.req(CMD_IOCTL, tree, &b, true)
        }

        fn read(&mut self, tree: u32, fid: u64, len: u32) -> R {
            let mut b = Vec::new();
            b.p16(49);
            b.p8(0);
            b.p8(0);
            b.p32(len);
            b.p64(0);
            b.p64(fid);
            b.p64(fid);
            b.p32(0);
            b.p32(0);
            b.p32(0);
            b.p16(0);
            b.p16(0);
            b.p8(0);
            self.req(CMD_READ, tree, &b, true)
        }

        fn write(&mut self, tree: u32, fid: u64, data: &[u8]) -> R {
            let mut b = Vec::new();
            b.p16(49);
            b.p16(112);
            b.p32(data.len() as u32);
            b.p64(0);
            b.p64(fid);
            b.p64(fid);
            b.p32(0);
            b.p32(0);
            b.p16(0);
            b.p16(0);
            b.p32(0);
            b.pbytes(data);
            self.req(CMD_WRITE, tree, &b, true)
        }

        fn close(&mut self, tree: u32, fid: u64) -> R {
            let mut b = Vec::new();
            b.p16(24);
            b.p16(0);
            b.p32(0);
            b.p64(fid);
            b.p64(fid);
            self.req(CMD_CLOSE, tree, &b, true)
        }

        /// The backend side of the pipe just opened, after its preamble.
        fn accept(&self) -> (UnixStream, Vec<u8>) {
            let (mut s, _) = self.listener.accept().unwrap();
            let mut hdr = [0u8; 16];
            s.read_exact(&mut hdr).unwrap();
            let n = u32::from_le_bytes(hdr[12..16].try_into().unwrap()) as usize;
            let mut body = vec![0u8; n];
            s.read_exact(&mut body).unwrap();
            (s, [hdr.to_vec(), body].concat())
        }

        /// Run the reactor's side of a pend: poll until pipe_ready answers.
        fn complete(&mut self) -> R {
            let pend = self.pc.pipe_new.pop().expect("a pend");
            for _ in 0..400 {
                if let Some(tx) = pipe_ready(&self.srv, &mut self.pc, &pend) {
                    // SAFETY: the test owns the pend's dup.
                    unsafe { libc::close(pend.fd) };
                    return parse(&tx);
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            panic!("pend never completed");
        }

        fn verifies(&self, r: &R) -> bool {
            r.flags & FLAG_SIGNED != 0 && verify_signature(&r.raw, &self.sc)
        }
    }

    fn pdu(len: u16, fill: u8) -> Vec<u8> {
        let mut v = vec![5, 0, 2, 3, 0x10, 0, 0, 0];
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&[0; 6]);
        v.resize(len as usize, fill);
        v
    }

    #[test]
    fn pipe_forwarding_end_to_end() {
        let mut b = bed("e2e", false);
        let tree = b.tree();

        // Unknown pipe; unsigned CREATE on a served one.
        assert_eq!(b.create(tree, "spoolss", true).0, status::OBJECT_NAME_NOT_FOUND);
        assert_eq!(b.create(tree, "samr", false).0, status::ACCESS_DENIED);

        let (st, fid) = b.create(tree, "\\PIPE\\SAMR", true);
        assert_eq!(st, status::SUCCESS);
        let (mut be, pre) = b.accept();
        assert_eq!(&pre[..8], crate::pipe::PREAMBLE_MAGIC);
        let id = crate::pipe::Identity {
            pipe: "samr",
            flags: crate::pipe::FLAG_SIGNED,
            dialect: 0x0311,
            session_key: &APP_KEY,
            user: "admin",
            domain: "",
            user_sid: String::new(),
            groups: vec![],
        };
        assert_eq!(pre, crate::pipe::encode_preamble(&id), "preamble carries the app key + user");

        // TRANSCEIVE: request reaches the backend unchanged; nothing back yet
        // → STATUS_PENDING, then the final response carries the reply PDU.
        let req = pdu(72, 0x33);
        let r = b.transceive(tree, fid, &req, 4280);
        assert_eq!(r.status, status::PENDING);
        assert!(b.verifies(&r), "interim is signed");
        let mut got = vec![0u8; req.len()];
        be.read_exact(&mut got).unwrap();
        assert_eq!(got, req);
        let reply = pdu(100, 0x44);
        be.write_all(&reply).unwrap();
        let fin = b.complete();
        assert_eq!(fin.status, status::SUCCESS);
        assert_eq!(fin.async_id, r.async_id);
        assert!(b.verifies(&fin), "final is signed");
        assert_eq!(u32::from_le_bytes(fin.body[4..8].try_into().unwrap()), FSCTL_PIPE_TRANSCEIVE);
        let out_len = u32::from_le_bytes(fin.body[36..40].try_into().unwrap()) as usize;
        assert_eq!(&fin.body[48..48 + out_len], &reply[..]);
        assert!(b.pc.pipe_active.is_empty());

        // WRITE + READ, reply already there → answered at once; a short
        // buffer gets BUFFER_OVERFLOW and the rest on the next READ.
        assert_eq!(b.write(tree, fid, &req).status, status::SUCCESS);
        be.read_exact(&mut got).unwrap();
        be.write_all(&reply).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let r = b.read(tree, fid, 60);
        assert_eq!(r.status, status::BUFFER_OVERFLOW);
        assert_eq!(&r.body[16..16 + 60], &reply[..60]);
        let r = b.read(tree, fid, 4280);
        assert_eq!(r.status, status::SUCCESS);
        assert_eq!(&r.body[16..], &reply[60..]);

        // A pended READ ended by CANCEL; a second read meanwhile is busy.
        let r = b.read(tree, fid, 4280);
        assert_eq!(r.status, status::PENDING);
        assert_eq!(b.read(tree, fid, 4280).status, status::PIPE_BUSY);
        let mut c: Vec<u8> = Vec::new();
        c.pbytes(&[0xFE, b'S', b'M', b'B']);
        c.p16(64);
        c.p16(0);
        c.p32(0);
        c.p16(CMD_CANCEL);
        c.p16(0);
        c.p32(FLAG_ASYNC);
        c.p32(0);
        c.p64(0);
        c.p64(r.async_id);
        c.p64(b.sid);
        c.zeros(16);
        c.p16(4);
        c.p16(0);
        let mut tx = Vec::new();
        process_frame(&b.srv, &mut b.pc, &c, &mut tx);
        assert_eq!(b.pc.pipe_done.len(), 1);
        assert_eq!(b.pc.pipe_done[0].status, status::CANCELLED);
        assert!(b.pc.pipe_active.is_empty());

        // CLOSE: the backend sees the pipe end.
        assert_eq!(b.close(tree, fid).status, status::SUCCESS);
        let mut one = [0u8; 1];
        assert_eq!(be.read(&mut one).unwrap(), 0, "backend sees EOF");
        assert_eq!(b.read(tree, fid, 10).status, status::FILE_CLOSED);
    }

    #[test]
    fn guest_cannot_open_pipes() {
        let mut b = bed("guest", true);
        let tree = b.tree_unsigned();
        assert_eq!(b.create(tree, "samr", false).0, status::ACCESS_DENIED);
    }

    #[test]
    fn backend_down_and_broken() {
        let mut b = bed("down", false);
        let tree = b.tree();
        let (st, fid) = b.create(tree, "lsarpc", true);
        assert_eq!(st, status::SUCCESS);
        let (be, _) = b.accept();
        // Backend dies with a read pended: the pend ends with PIPE_BROKEN.
        let r = b.read(tree, fid, 4280);
        assert_eq!(r.status, status::PENDING);
        drop(be);
        assert_eq!(b.complete().status, status::PIPE_BROKEN);
        // No backend at all: the CREATE fails.
        let sock = b.dir.join("rpc.sock");
        std::fs::remove_file(&sock).unwrap();
        assert_eq!(b.create(tree, "netlogon", true).0, status::PIPE_NOT_AVAILABLE);
    }

    impl Bed {
        fn tree_unsigned(&mut self) -> u32 {
            let path = utf16le("\\\\srv\\IPC$");
            let mut b = Vec::new();
            b.p16(9);
            b.p16(0);
            b.p16(72);
            b.p16(path.len() as u16);
            b.pbytes(&path);
            let r = self.req(CMD_TREE_CONNECT, 0, &b, false);
            assert_eq!(r.status, status::SUCCESS);
            u32::from_le_bytes(r.raw[36..40].try_into().unwrap())
        }
    }
}
