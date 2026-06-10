//! io_uring reactor: one ring per worker thread, SO_REUSEPORT listeners,
//! completion-driven per-connection state machines.
//!
//! Receive and transmit run full-duplex: a recv is kept posted whenever
//! there is buffer room, while the tx side drains. All complete frames in
//! the rx buffer are processed per wakeup and their responses batched into
//! a single send, so pipelined client requests (e.g. streams of 1 MiB
//! WRITEs) don't pay a per-request round trip.
//!
//! Data path for a standalone SMB2 READ is zero-copy: the file is spliced
//! into a per-connection pipe, the response header is sent with MSG_MORE,
//! and the pipe is spliced into the socket. File bytes never enter
//! userspace.

use std::os::fd::RawFd;
use std::sync::Arc;

use io_uring::{opcode, squeue, types, IoUring};

use crate::config::Srv;
use crate::smb2::{self, FrameAction, ProtoConn, ZcReadPlan};
use crate::{logd, logw, status};

const OP_ACCEPT: u8 = 1;
const OP_RECV: u8 = 2;
const OP_SEND: u8 = 3;
const OP_SPLICE_IN: u8 = 4;
const OP_SPLICE_OUT: u8 = 5;
const OP_INOTIFY: u8 = 6;
const OP_CANCEL: u8 = 7;

const IN_MASK: u32 = libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MODIFY
    | libc::IN_ATTRIB
    | libc::IN_CLOSE_WRITE
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO
    | libc::IN_DELETE_SELF;

const RX_INITIAL: usize = 68 * 1024;
/// Minimum spare tail room before re-arming a recv.
const RX_MIN_ROOM: usize = 16 * 1024;
const MAX_FRAME: usize = smb2::MAX_TRANSACT as usize + 0x11000;
/// Flush accumulated responses once the batch reaches this size.
const TX_FLUSH: usize = 1 << 20;
/// Shrink an oversized tx buffer back to this after a send completes.
const TX_KEEP: usize = 1 << 20;

fn ud(op: u8, idx: usize, gen: u16) -> u64 {
    ((op as u64) << 56) | ((idx as u64 & 0xFF_FFFF) << 32) | ((gen as u64) << 16)
}

fn ud_parts(v: u64) -> (u8, usize, u16) {
    ((v >> 56) as u8, ((v >> 32) & 0xFF_FFFF) as usize, (v >> 16) as u16)
}

/// Determine the largest pipe capacity we can get; the advertised
/// MaxReadSize is bounded by it so a zero-copy READ always fits the pipe.
pub fn probe_pipe_size(want: u32) -> u32 {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return 64 * 1024;
    }
    unsafe { libc::fcntl(fds[0], libc::F_SETPIPE_SZ, want as libc::c_int) };
    let got = unsafe { libc::fcntl(fds[0], libc::F_GETPIPE_SZ) };
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    if got <= 0 {
        64 * 1024
    } else {
        (got as u32).min(want)
    }
}

/// Transmit-side state. Only one response stream is in flight at a time;
/// the rx side runs independently.
enum Tx {
    Idle,
    /// Sending a batch of buffered responses from tx.
    Send,
    /// Zero-copy read: filling the pipe from the file.
    ZcIn,
    /// Zero-copy read: sending the response header (MSG_MORE).
    ZcHdr,
    /// Zero-copy read: draining the pipe into the socket.
    ZcOut,
}

struct Zc {
    plan: ZcReadPlan,
    want: u32,
    got: u32,
    out_left: u32,
}

struct Watch {
    wd: i32,
    pend: crate::smb2::NotifyPend,
}

struct Conn {
    fd: RawFd,
    gen: u16,
    proto: ProtoConn,
    rx: Vec<u8>,
    rx_off: usize,
    rx_len: usize,
    recv_inflight: bool,
    tx: Vec<u8>,
    tx_off: usize,
    txm: Tx,
    pending_zc: Option<ZcReadPlan>,
    pipe: Option<(RawFd, RawFd)>,
    pipe_cap: u32,
    zc: Option<Zc>,
    // CHANGE_NOTIFY: inotify instance, live watches, and completed async
    // responses waiting for the tx side to go idle.
    inotify_fd: Option<RawFd>,
    ibuf: Vec<u8>,
    watches: Vec<Watch>,
    deferred: std::collections::VecDeque<Vec<u8>>,
    /// io_uring SQEs submitted for this connection that have not yet
    /// produced a completion. Buffers referenced by in-flight ops must not
    /// be freed, so teardown is deferred until this reaches zero.
    inflight: u32,
    /// Set once teardown has begun: stop submitting new ops and drop the
    /// connection when `inflight` drains to zero.
    closing: bool,
    /// Whether the parked inotify Read has been asked to cancel.
    inotify_cancelled: bool,
}

impl Drop for Conn {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
        if let Some((r, w)) = self.pipe {
            unsafe {
                libc::close(r);
                libc::close(w);
            }
        }
        if let Some(ifd) = self.inotify_fd {
            unsafe { libc::close(ifd) };
        }
        // A zero-copy read in flight owns a dup'd file fd.
        if let Some(zc) = self.zc.take() {
            unsafe { libc::close(zc.plan.fd) };
        }
    }
}

struct Worker {
    srv: Arc<Srv>,
    wid: usize,
    listen_fd: RawFd,
    conns: Vec<Option<Conn>>,
    gens: Vec<u16>,
    free: Vec<usize>,
    conn_seed: u64,
}

pub fn run_worker(wid: usize, srv: Arc<Srv>) -> std::io::Result<()> {
    let addr = srv
        .cfg
        .listen_addr()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let listen_fd = listener(&addr)?;
    let mut ring = IoUring::new(1024)?;
    let mut w = Worker {
        srv,
        wid,
        listen_fd,
        conns: Vec::new(),
        gens: Vec::new(),
        free: Vec::new(),
        conn_seed: (wid as u64) << 20,
    };
    arm_accept(&mut ring, &w);
    logd!("worker {wid} ready");

    let mut cqes: Vec<(u64, i32)> = Vec::with_capacity(256);
    loop {
        match ring.submit_and_wait(1) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(e) => return Err(e),
        }
        cqes.clear();
        {
            let cq = ring.completion();
            for c in cq {
                cqes.push((c.user_data(), c.result()));
            }
        }
        for &(udata, res) in &cqes {
            handle_cqe(&mut ring, &mut w, udata, res);
        }
    }
}

fn listener(addr: &std::net::SocketAddr) -> std::io::Result<RawFd> {
    let (domain, sa, sa_len) = sockaddr(addr);
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            4,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            4,
        );
        if libc::bind(fd, &sa as *const _ as *const libc::sockaddr, sa_len) < 0
            || libc::listen(fd, 1024) < 0
        {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
    }
    Ok(fd)
}

fn sockaddr(addr: &std::net::SocketAddr) -> (libc::c_int, libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        std::net::SocketAddr::V4(a) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sa as *const _ as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            (libc::AF_INET, storage, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        std::net::SocketAddr::V6(a) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: a.ip().octets() },
                sin6_scope_id: a.scope_id(),
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sa as *const _ as *const u8,
                    &mut storage as *mut _ as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            (libc::AF_INET6, storage, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

fn sq_push(ring: &mut IoUring, e: &squeue::Entry) {
    loop {
        if unsafe { ring.submission().push(e) }.is_ok() {
            return;
        }
        let _ = ring.submit();
    }
}

/// Submit one SQE on behalf of a connection, counting it as in-flight so the
/// connection (and the buffers its ops reference) outlives the kernel's use.
fn sq_push_conn(ring: &mut IoUring, w: &mut Worker, idx: usize, e: &squeue::Entry) {
    conn_mut(w, idx).inflight += 1;
    sq_push(ring, e);
}

fn arm_accept(ring: &mut IoUring, w: &Worker) {
    let e = opcode::Accept::new(types::Fd(w.listen_fd), std::ptr::null_mut(), std::ptr::null_mut())
        .build()
        .user_data(ud(OP_ACCEPT, 0, 0));
    sq_push(ring, &e);
}

fn handle_cqe(ring: &mut IoUring, w: &mut Worker, udata: u64, res: i32) {
    let (op, idx, gen) = ud_parts(udata);
    if op == OP_ACCEPT {
        arm_accept(ring, w);
        if res < 0 {
            logw!("worker {}: accept failed: errno {}", w.wid, -res);
            return;
        }
        on_accept(ring, w, res);
        return;
    }
    // Cancel completions carry a sentinel gen and are not counted.
    if op == OP_CANCEL {
        return;
    }
    // Stale completion for a connection slot that has been recycled.
    let Some(conn) = w.conns.get_mut(idx).and_then(|c| c.as_mut()) else {
        return;
    };
    if conn.gen != gen {
        return;
    }
    // This completion retires one in-flight op.
    conn.inflight = conn.inflight.saturating_sub(1);
    if conn.closing {
        // Draining: ignore the result, just account it and finalize when the
        // last in-flight op returns (buffers are now safe to free).
        if conn.inflight == 0 {
            finalize_close(w, idx);
        }
        return;
    }
    match op {
        OP_RECV => on_recv(ring, w, idx, res),
        OP_SEND => on_send(ring, w, idx, res),
        OP_SPLICE_IN => on_splice_in(ring, w, idx, res),
        OP_SPLICE_OUT => on_splice_out(ring, w, idx, res),
        OP_INOTIFY => on_inotify(ring, w, idx, res),
        _ => {}
    }
}

fn on_accept(ring: &mut IoUring, w: &mut Worker, fd: RawFd) {
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const _ as *const libc::c_void,
            4,
        );
    }
    w.conn_seed += 1;
    let proto = ProtoConn::new(&w.srv, w.conn_seed);
    let idx = match w.free.pop() {
        Some(i) => i,
        None => {
            w.conns.push(None);
            w.gens.push(1);
            w.conns.len() - 1
        }
    };
    let gen = w.gens[idx];
    w.conns[idx] = Some(Conn {
        fd,
        gen,
        proto,
        rx: vec![0; RX_INITIAL],
        rx_off: 0,
        rx_len: 0,
        recv_inflight: false,
        tx: Vec::with_capacity(4096),
        tx_off: 0,
        txm: Tx::Idle,
        pending_zc: None,
        pipe: None,
        pipe_cap: 0,
        zc: None,
        inotify_fd: None,
        ibuf: Vec::new(),
        watches: Vec::new(),
        deferred: std::collections::VecDeque::new(),
        inflight: 0,
        closing: false,
        inotify_cancelled: false,
    });
    logd!("worker {}: new connection (slot {idx})", w.wid);
    maybe_arm_recv(ring, w, idx);
}

/// Begin tearing down a connection. New ops stop; the connection is only
/// dropped (freeing buffers the kernel may still reference) once all
/// in-flight ops have completed — see [`finalize_close`]. A parked inotify
/// Read never completes on socket close, so it is explicitly cancelled.
fn close_conn_ring(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    let Some(c) = w.conns[idx].as_mut() else {
        return;
    };
    c.closing = true;
    // Unpark a waiting inotify Read so its buffer can be freed.
    if c.inotify_fd.is_some() && !c.inotify_cancelled {
        c.inotify_cancelled = true;
        let target = ud(OP_INOTIFY, idx, c.gen);
        let e = opcode::AsyncCancel::new(target)
            .build()
            .user_data(ud(OP_CANCEL, 0xFF_FFFF, 0));
        sq_push(ring, &e); // not counted; sentinel completion is ignored
    }
    if c.inflight == 0 {
        finalize_close(w, idx);
    }
}

/// Actually drop the connection and recycle its slot. Only call when no ops
/// reference its buffers.
fn finalize_close(w: &mut Worker, idx: usize) {
    if w.conns[idx].take().is_some() {
        w.gens[idx] = w.gens[idx].wrapping_add(1).max(1);
        w.free.push(idx);
        logd!("worker {}: connection closed (slot {idx})", w.wid);
    }
}

fn conn_mut(w: &mut Worker, idx: usize) -> &mut Conn {
    w.conns[idx].as_mut().expect("live connection")
}

/// Size of the frame starting at rx_off, if its NBT header has arrived.
/// Err(()) means the stream is unsynchronized and the connection must die.
fn frame_total(c: &Conn) -> Result<Option<usize>, ()> {
    let avail = c.rx_len - c.rx_off;
    if avail < 4 {
        return Ok(None);
    }
    let b = &c.rx[c.rx_off..];
    if b[0] != 0 {
        return Err(()); // only NetBIOS session messages on direct TCP 445
    }
    let flen = ((b[1] as usize) << 16) | ((b[2] as usize) << 8) | b[3] as usize;
    if flen > MAX_FRAME {
        return Err(());
    }
    Ok(Some(4 + flen))
}

/// Keep a recv posted whenever there is (or can be made) room. Never moves
/// or reallocates the buffer while a recv is in flight.
fn maybe_arm_recv(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    let c = conn_mut(w, idx);
    if c.recv_inflight || c.closing {
        return;
    }
    // Compact consumed bytes to the front.
    if c.rx_off > 0 {
        c.rx.copy_within(c.rx_off..c.rx_len, 0);
        c.rx_len -= c.rx_off;
        c.rx_off = 0;
    }
    // Grow for a known oversized frame, or to keep minimum room available.
    let needed = match frame_total(c) {
        Ok(Some(total)) => total.max(c.rx_len + RX_MIN_ROOM),
        Ok(None) => c.rx_len + RX_MIN_ROOM,
        Err(()) => {
            close_conn_ring(ring, w, idx);
            return;
        }
    };
    if c.rx.len() < needed {
        c.rx.resize(needed.min(MAX_FRAME + 4 + RX_MIN_ROOM), 0);
    }
    let buf = &mut c.rx[c.rx_len..];
    if buf.is_empty() {
        return; // buffer at hard cap and full; resume after frames drain
    }
    let e = opcode::Recv::new(types::Fd(c.fd), buf.as_mut_ptr(), buf.len() as u32)
        .build()
        .user_data(ud(OP_RECV, idx, c.gen));
    c.recv_inflight = true;
    sq_push_conn(ring, w, idx, &e);
}

fn on_recv(ring: &mut IoUring, w: &mut Worker, idx: usize, res: i32) {
    let c = conn_mut(w, idx);
    c.recv_inflight = false;
    if res == -libc::EINTR {
        maybe_arm_recv(ring, w, idx);
        return;
    }
    if res <= 0 {
        // Peer closed or socket error. If the tx side is mid-stream it will
        // also fail shortly; tearing down now is safe (gen guards CQEs).
        close_conn_ring(ring, w, idx);
        return;
    }
    c.rx_len += res as usize;
    if matches!(c.txm, Tx::Idle) {
        drive(ring, w, idx);
    } else {
        // tx busy: just keep receiving; frames are processed when it frees.
        maybe_arm_recv(ring, w, idx);
    }
}

/// Process complete frames (tx side must be idle), batching responses into
/// tx, then kick the appropriate transmit and keep a recv posted.
fn drive(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    debug_assert!(matches!(conn_mut(w, idx).txm, Tx::Idle));
    let srv = Arc::clone(&w.srv);
    // Completed async (notify) responses go out ahead of new work.
    {
        let c = conn_mut(w, idx);
        while let Some(d) = c.deferred.pop_front() {
            c.tx.extend_from_slice(&d);
            if c.tx.len() >= TX_FLUSH {
                break;
            }
        }
    }
    loop {
        let c = conn_mut(w, idx);
        if c.tx.len() - c.tx_off >= TX_FLUSH {
            break; // flush the batch before processing more
        }
        let total = match frame_total(c) {
            Ok(Some(t)) if c.rx_len - c.rx_off >= t => t,
            Ok(_) => break, // need more bytes
            Err(()) => {
                close_conn_ring(ring, w, idx);
                return;
            }
        };
        let action = {
            let Conn { proto, rx, tx, .. } = c;
            let frame = &rx[c.rx_off + 4..c.rx_off + total];
            smb2::process_frame(&srv, proto, frame, tx)
        };
        c.rx_off += total;
        // Register new CHANGE_NOTIFY pends / complete cancelled ones.
        if !c.proto.notify_new.is_empty() || !c.proto.notify_done.is_empty() {
            service_notify(ring, w, idx);
        }
        match action {
            FrameAction::Respond => {}
            FrameAction::ZcRead(plan) => {
                if conn_mut(w, idx).tx.is_empty() {
                    start_zc(ring, w, idx, plan);
                } else {
                    // Flush buffered responses first, then run the splice
                    // sequence; ordering on the socket is preserved.
                    conn_mut(w, idx).pending_zc = Some(plan);
                    start_send(ring, w, idx);
                }
                maybe_arm_recv(ring, w, idx);
                return;
            }
        }
    }
    let c = conn_mut(w, idx);
    if !c.tx.is_empty() {
        start_send(ring, w, idx);
    }
    maybe_arm_recv(ring, w, idx);
}

/// Drain the protocol layer's notify queues: add inotify watches for new
/// pends, emit final responses for completed ones (cancel / handle close).
fn service_notify(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    let c = conn_mut(w, idx);
    let new = std::mem::take(&mut c.proto.notify_new);
    let done = std::mem::take(&mut c.proto.notify_done);

    for pend in new {
        if c.inotify_fd.is_none() {
            let ifd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            if ifd < 0 {
                complete_notify(c, &pend, status::INSUFFICIENT_RESOURCES, &[]);
                continue;
            }
            c.inotify_fd = Some(ifd);
            c.ibuf = vec![0; 4096];
            arm_inotify(ring, c, idx);
        }
        let ifd = c.inotify_fd.unwrap();
        let wd = match crate::vfs::cpath(&pend.path) {
            Ok(cp) => unsafe { libc::inotify_add_watch(ifd, cp.as_ptr(), IN_MASK) },
            Err(_) => -1,
        };
        if wd < 0 {
            complete_notify(c, &pend, status::INSUFFICIENT_RESOURCES, &[]);
            continue;
        }
        logd!("notify pend on {:?} (wd {wd})", pend.path);
        c.watches.push(Watch { wd, pend });
    }

    for d in done {
        if let Some(pos) = c.watches.iter().position(|x| x.pend.async_id == d.async_id) {
            let watch = c.watches.remove(pos);
            // Same directory can back several watches (same wd): only drop
            // the kernel watch when the last one goes.
            if !c.watches.iter().any(|x| x.wd == watch.wd) {
                if let Some(ifd) = c.inotify_fd {
                    unsafe { libc::inotify_rm_watch(ifd, watch.wd) };
                }
            }
            let resp =
                smb2::build_notify_final(&c.proto, &watch.pend.meta, d.status, &[], watch.pend.out_len);
            c.deferred.push_back(resp);
        }
    }
}

/// Build + queue a final notify response and clear the active entry.
fn complete_notify(c: &mut Conn, pend: &crate::smb2::NotifyPend, st: u32, events: &[(u32, String)]) {
    logd!("notify complete aid={} st={:#x} events={}", pend.async_id, st, events.len());
    let resp = smb2::build_notify_final(&c.proto, &pend.meta, st, events, pend.out_len);
    c.deferred.push_back(resp);
    c.proto.notify_active.retain(|&(_, a)| a != pend.async_id);
}

fn arm_inotify(ring: &mut IoUring, c: &mut Conn, idx: usize) {
    if c.closing {
        return;
    }
    let ifd = c.inotify_fd.expect("inotify created");
    let e = opcode::Read::new(types::Fd(ifd), c.ibuf.as_mut_ptr(), c.ibuf.len() as u32)
        .build()
        .user_data(ud(OP_INOTIFY, idx, c.gen));
    c.inflight += 1;
    sq_push(ring, &e);
}

fn on_inotify(ring: &mut IoUring, w: &mut Worker, idx: usize, res: i32) {
    if res == -libc::EINTR || res == -libc::EAGAIN {
        let c = conn_mut(w, idx);
        arm_inotify(ring, c, idx);
        return;
    }
    if res <= 0 {
        // inotify instance died; pending notifies will complete via
        // cancel/close paths.
        conn_mut(w, idx).inotify_fd.take().map(|fd| unsafe { libc::close(fd) });
        return;
    }
    let c = conn_mut(w, idx);
    let n = res as usize;

    // Parse events, grouped per watch descriptor.
    let mut groups: std::collections::HashMap<i32, Vec<(u32, String)>> =
        std::collections::HashMap::new();
    let mut self_gone: Vec<i32> = Vec::new();
    let mut off = 0usize;
    while off + 16 <= n {
        let wd = i32::from_le_bytes(c.ibuf[off..off + 4].try_into().unwrap());
        let mask = u32::from_le_bytes(c.ibuf[off + 4..off + 8].try_into().unwrap());
        let name_len = u32::from_le_bytes(c.ibuf[off + 12..off + 16].try_into().unwrap()) as usize;
        let name_bytes = &c.ibuf[off + 16..(off + 16 + name_len).min(n)];
        let name = name_bytes
            .split(|&b| b == 0)
            .next()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();
        off += 16 + name_len;

        if mask & (libc::IN_DELETE_SELF | libc::IN_IGNORED | libc::IN_UNMOUNT) != 0 {
            self_gone.push(wd);
            continue;
        }
        let action = if mask & libc::IN_CREATE != 0 {
            1 // FILE_ACTION_ADDED
        } else if mask & libc::IN_DELETE != 0 {
            2 // FILE_ACTION_REMOVED
        } else if mask & libc::IN_MOVED_FROM != 0 {
            4 // FILE_ACTION_RENAMED_OLD_NAME
        } else if mask & libc::IN_MOVED_TO != 0 {
            5 // FILE_ACTION_RENAMED_NEW_NAME
        } else {
            3 // FILE_ACTION_MODIFIED
        };
        if !name.is_empty() {
            groups.entry(wd).or_default().push((action, name));
        } else {
            // Event without a name → make the client re-enumerate.
            groups.entry(wd).or_default();
        }
    }

    // Complete every watch that saw activity (single-shot semantics).
    let mut fired: Vec<(Watch, Vec<(u32, String)>)> = Vec::new();
    for (wd, events) in groups {
        while let Some(pos) = c.watches.iter().position(|x| x.wd == wd) {
            let watch = c.watches.remove(pos);
            fired.push((watch, events.clone()));
        }
        if let Some(ifd) = c.inotify_fd {
            unsafe { libc::inotify_rm_watch(ifd, wd) };
        }
    }
    for wd in self_gone {
        while let Some(pos) = c.watches.iter().position(|x| x.wd == wd) {
            let watch = c.watches.remove(pos);
            fired.push((watch, Vec::new()));
        }
    }
    for (watch, events) in fired {
        complete_notify(c, &watch.pend, status::SUCCESS, &events);
    }

    arm_inotify(ring, c, idx);
    let c = conn_mut(w, idx);
    if matches!(c.txm, Tx::Idle) && !c.deferred.is_empty() {
        drive(ring, w, idx);
    }
}

fn start_send(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    conn_mut(w, idx).txm = Tx::Send;
    submit_send(ring, w, idx, 0);
}

fn submit_send(ring: &mut IoUring, w: &mut Worker, idx: usize, msg_flags: i32) {
    let c = conn_mut(w, idx);
    let buf = &c.tx[c.tx_off..];
    let e = opcode::Send::new(types::Fd(c.fd), buf.as_ptr(), buf.len() as u32)
        .flags(msg_flags)
        .build()
        .user_data(ud(OP_SEND, idx, c.gen));
    sq_push_conn(ring, w, idx, &e);
}

fn on_send(ring: &mut IoUring, w: &mut Worker, idx: usize, res: i32) {
    if res == -libc::EINTR {
        let flags = matches!(conn_mut(w, idx).txm, Tx::ZcHdr) as i32 * libc::MSG_MORE;
        submit_send(ring, w, idx, flags);
        return;
    }
    if res <= 0 {
        close_conn_ring(ring, w, idx);
        return;
    }
    let c = conn_mut(w, idx);
    c.tx_off += res as usize;
    let done = c.tx_off >= c.tx.len();
    match c.txm {
        Tx::ZcHdr => {
            if done {
                c.txm = Tx::ZcOut;
                submit_splice_out(ring, w, idx);
            } else {
                submit_send(ring, w, idx, libc::MSG_MORE);
            }
        }
        _ => {
            if done {
                c.tx.clear();
                c.tx_off = 0;
                if c.tx.capacity() > TX_KEEP {
                    c.tx.shrink_to(TX_KEEP);
                }
                if let Some(plan) = c.pending_zc.take() {
                    start_zc(ring, w, idx, plan);
                } else {
                    c.txm = Tx::Idle;
                    drive(ring, w, idx);
                }
            } else {
                submit_send(ring, w, idx, 0);
            }
        }
    }
}

// ------------------------------------------------------- zero-copy READ path

fn start_zc(ring: &mut IoUring, w: &mut Worker, idx: usize, plan: ZcReadPlan) {
    let max_read = w.srv.max_read;
    let c = conn_mut(w, idx);
    debug_assert!(c.tx.is_empty());
    if c.pipe.is_none() {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            let mut tx = std::mem::take(&mut c.tx);
            smb2::build_read_err(&plan, status::INSUFFICIENT_RESOURCES, &mut tx);
            // The plan owns a dup of the file fd; release it on this error path.
            unsafe { libc::close(plan.fd) };
            c.tx = tx;
            c.tx_off = 0;
            c.txm = Tx::Send;
            submit_send(ring, w, idx, 0);
            return;
        }
        unsafe { libc::fcntl(fds[0], libc::F_SETPIPE_SZ, max_read as libc::c_int) };
        let got = unsafe { libc::fcntl(fds[0], libc::F_GETPIPE_SZ) };
        c.pipe = Some((fds[0], fds[1]));
        c.pipe_cap = if got > 0 { got as u32 } else { 64 * 1024 };
    }
    let want = plan.length.min(c.pipe_cap);
    c.zc = Some(Zc { plan, want, got: 0, out_left: 0 });
    c.txm = Tx::ZcIn;
    submit_splice_in(ring, w, idx);
}

fn submit_splice_in(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    let c = conn_mut(w, idx);
    let zc = c.zc.as_ref().expect("zc in flight");
    let (_, pipe_w) = c.pipe.expect("pipe created");
    let e = opcode::Splice::new(
        types::Fd(zc.plan.fd),
        (zc.plan.offset + zc.got as u64) as i64,
        types::Fd(pipe_w),
        -1,
        zc.want - zc.got,
    )
    .flags(libc::SPLICE_F_MOVE)
    .build()
    .user_data(ud(OP_SPLICE_IN, idx, c.gen));
    sq_push_conn(ring, w, idx, &e);
}

fn on_splice_in(ring: &mut IoUring, w: &mut Worker, idx: usize, res: i32) {
    if res == -libc::EINTR || res == -libc::EAGAIN {
        submit_splice_in(ring, w, idx);
        return;
    }
    let c = conn_mut(w, idx);
    let zc = c.zc.as_mut().expect("zc in flight");

    if res < 0 {
        let st = status::from_errno(-res);
        zc_fail(ring, w, idx, st);
        return;
    }
    if res > 0 {
        zc.got += res as u32;
        if zc.got < zc.want {
            submit_splice_in(ring, w, idx);
            return;
        }
    }
    // res == 0 (EOF) or pipe filled to `want`.
    let got = zc.got;
    if got == 0 || got < zc.plan.min_count {
        zc_fail(ring, w, idx, status::END_OF_FILE);
        return;
    }
    let plan = zc.plan.clone();
    zc.out_left = got;
    let mut tx = std::mem::take(&mut c.tx);
    smb2::build_read_resp_prefix(&plan, got, &mut tx);
    c.tx = tx;
    c.tx_off = 0;
    c.txm = Tx::ZcHdr;
    submit_send(ring, w, idx, libc::MSG_MORE);
}

/// Abort a zero-copy read: drain whatever landed in the pipe, then send an
/// error response instead.
fn zc_fail(ring: &mut IoUring, w: &mut Worker, idx: usize, st: u32) {
    let c = conn_mut(w, idx);
    let zc = c.zc.take().expect("zc in flight");
    if zc.got > 0 {
        let (pipe_r, _) = c.pipe.expect("pipe created");
        let mut left = zc.got as usize;
        let mut scratch = [0u8; 16384];
        while left > 0 {
            let n = unsafe {
                libc::read(pipe_r, scratch.as_mut_ptr() as *mut libc::c_void, scratch.len().min(left))
            };
            if n <= 0 {
                break;
            }
            left -= n as usize;
        }
    }
    let mut tx = std::mem::take(&mut c.tx);
    smb2::build_read_err(&zc.plan, st, &mut tx);
    // Release the plan's dup'd file fd.
    unsafe { libc::close(zc.plan.fd) };
    c.tx = tx;
    c.tx_off = 0;
    c.txm = Tx::Send;
    submit_send(ring, w, idx, 0);
}

fn submit_splice_out(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    let c = conn_mut(w, idx);
    let zc = c.zc.as_ref().expect("zc in flight");
    let (pipe_r, _) = c.pipe.expect("pipe created");
    let e = opcode::Splice::new(types::Fd(pipe_r), -1, types::Fd(c.fd), -1, zc.out_left)
        .flags(libc::SPLICE_F_MOVE)
        .build()
        .user_data(ud(OP_SPLICE_OUT, idx, c.gen));
    sq_push_conn(ring, w, idx, &e);
}

fn on_splice_out(ring: &mut IoUring, w: &mut Worker, idx: usize, res: i32) {
    if res == -libc::EINTR || res == -libc::EAGAIN {
        submit_splice_out(ring, w, idx);
        return;
    }
    if res <= 0 {
        // Socket gone; pipe contents die with the connection.
        close_conn_ring(ring, w, idx);
        return;
    }
    let c = conn_mut(w, idx);
    let zc = c.zc.as_mut().expect("zc in flight");
    zc.out_left -= (res as u32).min(zc.out_left);
    if zc.out_left > 0 {
        submit_splice_out(ring, w, idx);
        return;
    }
    // Zero-copy read done: release the plan's dup'd file fd.
    if let Some(zc) = c.zc.take() {
        unsafe { libc::close(zc.plan.fd) };
    }
    c.tx.clear();
    c.tx_off = 0;
    c.txm = Tx::Idle;
    drive(ring, w, idx);
}
