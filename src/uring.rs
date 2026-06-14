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
use crate::status;

const OP_ACCEPT: u8 = 1;
const OP_RECV: u8 = 2;
const OP_SEND: u8 = 3;
const OP_SPLICE_IN: u8 = 4;
const OP_SPLICE_OUT: u8 = 5;
const OP_INOTIFY: u8 = 6;
const OP_CANCEL: u8 = 7;
/// Worker-level op: the per-worker break mailbox eventfd fired.
const OP_WAKE: u8 = 8;

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

/// Verify the kernel actually provides io_uring before we spawn workers.
/// rocketsmbd is a static binary with no library dependencies, but it has a
/// hard *kernel* dependency: io_uring (Linux ≥ 5.15). Surface that here with
/// a clear message instead of a cryptic per-worker failure.
pub fn probe_io_uring() -> Result<(), String> {
    match IoUring::new(8) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "io_uring is unavailable: {e}. rocketsmbd requires a Linux kernel \
             with io_uring (≥ 5.15; ≥ 6.0 recommended) and io_uring not \
             disabled (check sysctl kernel.io_uring_disabled / seccomp)."
        )),
    }
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
    /// A send_zc completed but its buffer-release notification(s) are still
    /// pending — tx is fully sent but the kernel still references it, so we
    /// wait here before reusing/clearing tx and driving the next response.
    Drain,
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
    /// Linked fast path: splice-in → send → splice-out submitted as one
    /// IO_LINK chain. `chain` counts the original linked CQEs still pending;
    /// `err` records any failure across the chain.
    linked: bool,
    chain: u8,
    err: bool,
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
    /// Outstanding send_zc buffer-release notifications (IORING_CQE_F_NOTIF)
    /// for the current `tx`. The tx buffer is still referenced by the kernel
    /// until these arrive, so it must not be reused/cleared while > 0.
    notif_pending: u32,
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
    /// Whether the running kernel supports IORING_OP_SEND_ZC (≥ 5.19). Older
    /// kernels (down to our 5.15 floor) fall back to a plain copying Send.
    send_zc_ok: bool,
    /// 8-byte landing buffer for the break-mailbox eventfd read (must outlive
    /// the in-flight Read SQE, so it lives on the worker).
    wake_buf: u64,
}

pub fn run_worker(wid: usize, srv: Arc<Srv>) -> std::io::Result<()> {
    let addr = srv
        .cfg
        .listen_addr()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let listen_fd = listener(&addr)?;
    if srv.cfg.core_pinning {
        pin_to_core(wid);
    }
    let ring = if srv.cfg.sqpoll {
        // SQPOLL: a kernel thread polls the SQ (1s idle before it sleeps), so
        // submissions need no syscall. Falls back to a normal ring if the
        // kernel rejects the flag (e.g. lacks CAP_SYS_NICE).
        IoUring::builder()
            .setup_sqpoll(1000)
            .build(1024)
            .or_else(|_| IoUring::new(1024))?
    } else {
        IoUring::new(1024)?
    };
    let send_zc_ok = {
        let mut probe = io_uring::Probe::new();
        ring.submitter().register_probe(&mut probe).is_ok()
            && probe.is_supported(opcode::SendZc::CODE)
    };
    if wid == 0 {
        logd!(
            "send_zc (MSG_ZEROCOPY tx): {}",
            if send_zc_ok { "supported" } else { "unsupported (kernel < 5.19) — using copying send" }
        );
    }
    let mut ring = ring;
    let mut w = Worker {
        srv,
        wid,
        listen_fd,
        conns: Vec::new(),
        gens: Vec::new(),
        free: Vec::new(),
        conn_seed: (wid as u64) << 20,
        send_zc_ok,
        wake_buf: 0,
    };
    arm_accept(&mut ring, &w);
    arm_wake(&mut ring, &mut w);
    logd!("worker {wid} ready");

    let mut cqes: Vec<(u64, i32, u32)> = Vec::with_capacity(256);
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
                cqes.push((c.user_data(), c.result(), c.flags()));
            }
        }
        for &(udata, res, flags) in &cqes {
            handle_cqe(&mut ring, &mut w, udata, res, flags);
        }
    }
}

/// IORING_CQE_F_MORE: another CQE (a zero-copy notification) will follow.
const CQE_F_MORE: u32 = 1 << 1;
/// IORING_CQE_F_NOTIF: this CQE is a send_zc buffer-release notification.
const CQE_F_NOTIF: u32 = 1 << 3;

/// Pin this worker thread to one CPU core (worker N → core N mod ncpu). Keeps
/// each ring, its NIC softirqs, and its cache footprint on a single core,
/// avoiding cross-core traffic under SO_REUSEPORT. Best-effort.
fn pin_to_core(wid: usize) {
    let ncpu = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if ncpu <= 0 {
        return;
    }
    let core = wid % ncpu as usize;
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
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
    let ud = ud(OP_ACCEPT, 0, 0);
    // Multishot accept stays armed and posts a CQE per connection (no SQE per
    // accept). It's a modern-kernel feature; gate it on the same probe as
    // send_zc (≥ 6.0 covers multishot accept's 5.19 floor) and fall back to a
    // re-armed oneshot Accept on older kernels.
    if w.send_zc_ok {
        let e = opcode::AcceptMulti::new(types::Fd(w.listen_fd)).build().user_data(ud);
        sq_push(ring, &e);
    } else {
        let e =
            opcode::Accept::new(types::Fd(w.listen_fd), std::ptr::null_mut(), std::ptr::null_mut())
                .build()
                .user_data(ud);
        sq_push(ring, &e);
    }
}

/// Arm a read on this worker's break-mailbox eventfd. When another worker
/// posts a lease/oplock break, the eventfd fires and `on_wake` drains it.
fn arm_wake(ring: &mut IoUring, w: &mut Worker) {
    let efd = w.srv.mailboxes[w.wid].event_fd();
    if efd < 0 {
        return;
    }
    let e = opcode::Read::new(types::Fd(efd), &mut w.wake_buf as *mut u64 as *mut u8, 8)
        .build()
        .user_data(ud(OP_WAKE, 0, 0));
    sq_push(ring, &e);
}

/// The break mailbox fired: drain queued breaks and deliver them, then re-arm.
fn on_wake(ring: &mut IoUring, w: &mut Worker) {
    let breaks = w.srv.mailboxes[w.wid].drain();
    for b in breaks {
        deliver_break(ring, w, b);
    }
    arm_wake(ring, w);
}

/// Deliver an oplock break to a connection owned by this worker: build the
/// OPLOCK_BREAK notification and queue it on the connection's deferred queue
/// (the same path CHANGE_NOTIFY uses), flushing if the tx side is idle.
fn deliver_break(ring: &mut IoUring, w: &mut Worker, b: crate::lease::BreakMsg) {
    {
        let Some(conn) = w.conns.get_mut(b.conn_idx).and_then(|c| c.as_mut()) else {
            return; // slot recycled — holder already gone
        };
        if conn.gen != b.conn_gen || conn.closing {
            return; // different connection now, or tearing down
        }
        let sign = conn.proto.channels.get(&b.session_id).and_then(|c| c.sign.clone());
        let frame = smb2::build_lease_break(
            &b.lease_key,
            b.cur_state,
            b.new_state,
            b.epoch,
            b.session_id,
            sign.as_ref(),
        );
        conn.deferred.push_back(frame);
        logd!("lease: break -> worker {} slot {} state {}->{}", w.wid, b.conn_idx, b.cur_state, b.new_state);
    }
    // Flush now if nothing else is on the wire (otherwise drains after the
    // in-flight send completes, as deferred frames always do).
    if matches!(conn_mut(w, b.conn_idx).txm, Tx::Idle) {
        drive(ring, w, b.conn_idx);
    }
}

fn handle_cqe(ring: &mut IoUring, w: &mut Worker, udata: u64, res: i32, flags: u32) {
    let (op, idx, gen) = ud_parts(udata);
    if op == OP_ACCEPT {
        // Multishot accept stays armed (F_MORE set); only re-arm when it has
        // terminated. Oneshot accept never sets F_MORE, so it always re-arms.
        if flags & CQE_F_MORE == 0 {
            arm_accept(ring, w);
        }
        if res < 0 {
            logw!("worker {}: accept failed: errno {}", w.wid, -res);
            return;
        }
        on_accept(ring, w, res);
        return;
    }
    if op == OP_WAKE {
        // eventfd read may be short/interrupted; re-arm regardless and drain.
        on_wake(ring, w);
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
    // A send_zc completion with F_MORE will be followed by a buffer-release
    // notification (F_NOTIF) — account that extra CQE so teardown waits for
    // it (the tx buffer is still referenced by the kernel until then).
    if op == OP_SEND && flags & CQE_F_MORE != 0 {
        conn.inflight += 1;
        conn.notif_pending += 1;
    }
    // This completion retires one in-flight op.
    conn.inflight = conn.inflight.saturating_sub(1);
    if conn.closing {
        // Draining: ignore the result, just account it and finalize when the
        // last in-flight op (incl. pending send_zc notifs) returns.
        if conn.inflight == 0 {
            finalize_close(w, idx);
        }
        return;
    }
    match op {
        OP_RECV => on_recv(ring, w, idx, res),
        OP_SEND if flags & CQE_F_NOTIF != 0 => on_send_notif(ring, w, idx),
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
    let idx = match w.free.pop() {
        Some(i) => i,
        None => {
            w.conns.push(None);
            w.gens.push(1);
            w.conns.len() - 1
        }
    };
    let gen = w.gens[idx];
    let proto = ProtoConn::new(&w.srv, w.wid, idx, gen);
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
        notif_pending: 0,
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
        // Release any oplocks this connection held but never cleanly CLOSEd,
        // so a dropped connection doesn't leak grants in the lease table.
        w.srv.leases.release_conn(w.wid, idx, w.gens[idx]);
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
            FrameAction::Close => {
                // Undecryptable encrypted frame (e.g. guest + seal): disconnect
                // rather than leave the client hanging (#26).
                close_conn_ring(ring, w, idx);
                return;
            }
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

/// Buffered sends at or above this size use send_zc (MSG_ZEROCOPY): the kernel
/// pins the tx pages instead of copying them, paying back the extra
/// notification CQE only when the copy it saves is large enough to matter.
/// Encrypted/compound responses (the buffered path) are the beneficiaries; the
/// splice read path is already zero-copy and the MSG_MORE header send is tiny.
const ZC_SEND_MIN: usize = 64 * 1024;

fn submit_send(ring: &mut IoUring, w: &mut Worker, idx: usize, msg_flags: i32) {
    let send_zc_ok = w.send_zc_ok;
    let c = conn_mut(w, idx);
    let buf = &c.tx[c.tx_off..];
    // Only the plain buffered path (msg_flags == 0) is eligible; the ZcHdr
    // send sets MSG_MORE and must stay a regular Send.
    if send_zc_ok && msg_flags == 0 && buf.len() >= ZC_SEND_MIN {
        let e = opcode::SendZc::new(types::Fd(c.fd), buf.as_ptr(), buf.len() as u32)
            .build()
            .user_data(ud(OP_SEND, idx, c.gen));
        sq_push_conn(ring, w, idx, &e);
        return;
    }
    let e = opcode::Send::new(types::Fd(c.fd), buf.as_ptr(), buf.len() as u32)
        .flags(msg_flags)
        .build()
        .user_data(ud(OP_SEND, idx, c.gen));
    sq_push_conn(ring, w, idx, &e);
}

fn on_send(ring: &mut IoUring, w: &mut Worker, idx: usize, res: i32) {
    if conn_mut(w, idx).zc.as_ref().is_some_and(|z| z.linked) {
        on_linked_cqe(ring, w, idx, OP_SEND, res);
        return;
    }
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
                // tx fully sent. If this went out via send_zc, the kernel still
                // references tx until the buffer-release notification(s) land —
                // park in Drain and finish from on_send_notif. Otherwise tx is
                // free now.
                if c.notif_pending > 0 {
                    c.txm = Tx::Drain;
                } else {
                    finish_send(ring, w, idx);
                }
            } else {
                submit_send(ring, w, idx, 0);
            }
        }
    }
}

/// tx is fully sent and no longer referenced by the kernel: release it and
/// drive the next response (or a read queued behind this send).
fn finish_send(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    let c = conn_mut(w, idx);
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
}

/// A send_zc buffer-release notification (IORING_CQE_F_NOTIF) arrived: the
/// kernel is done with that slice of tx. When the last one for the current
/// send clears and the send had already fully completed (Drain), tx is safe to
/// reuse.
fn on_send_notif(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    let c = conn_mut(w, idx);
    c.notif_pending = c.notif_pending.saturating_sub(1);
    if c.notif_pending == 0 && matches!(c.txm, Tx::Drain) {
        finish_send(ring, w, idx);
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
    // Linked fast path: a full read (no EOF) whose data fits the pipe in one
    // splice can go out as a single splice-in → send(hdr) → splice-out chain,
    // eliminating the two userspace round-trips that otherwise bubble the
    // socket between ops. EOF-possible or oversized reads stay sequential.
    if plan.linked && plan.length <= c.pipe_cap {
        let mut tx = std::mem::take(&mut c.tx);
        smb2::build_read_resp_prefix(&plan, plan.length, &mut tx);
        c.tx = tx;
        c.tx_off = 0;
        let out_left = plan.length;
        c.zc = Some(Zc { plan, want, got: want, out_left, linked: true, chain: 3, err: false });
        c.txm = Tx::ZcOut;
        submit_zc_linked(ring, w, idx);
        return;
    }
    c.zc = Some(Zc { plan, want, got: 0, out_left: 0, linked: false, chain: 0, err: false });
    c.txm = Tx::ZcIn;
    submit_splice_in(ring, w, idx);
}

/// Submit the whole zero-copy read as one IO_LINK chain:
/// splice(file→pipe) → send(header, MSG_MORE) → splice(pipe→socket).
fn submit_zc_linked(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    let c = conn_mut(w, idx);
    let zc = c.zc.as_ref().expect("zc in flight");
    let (pipe_r, pipe_w) = c.pipe.expect("pipe created");
    let len = zc.want;
    let splice_in = opcode::Splice::new(
        types::Fd(zc.plan.fd),
        zc.plan.offset as i64,
        types::Fd(pipe_w),
        -1,
        len,
    )
    .flags(libc::SPLICE_F_MOVE)
    .build()
    .flags(squeue::Flags::IO_LINK)
    .user_data(ud(OP_SPLICE_IN, idx, c.gen));
    let send = opcode::Send::new(types::Fd(c.fd), c.tx.as_ptr(), c.tx.len() as u32)
        .flags(libc::MSG_MORE)
        .build()
        .flags(squeue::Flags::IO_LINK)
        .user_data(ud(OP_SEND, idx, c.gen));
    let splice_out = opcode::Splice::new(types::Fd(pipe_r), -1, types::Fd(c.fd), -1, len)
        .flags(libc::SPLICE_F_MOVE)
        .build()
        .user_data(ud(OP_SPLICE_OUT, idx, c.gen));
    conn_mut(w, idx).inflight += 3;
    sq_push(ring, &splice_in);
    sq_push(ring, &send);
    sq_push(ring, &splice_out);
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

/// Retire one CQE of a linked zero-copy chain. The three ops complete in
/// order (splice-in, send, splice-out); we finalize when the last lands.
fn on_linked_cqe(ring: &mut IoUring, w: &mut Worker, idx: usize, op: u8, res: i32) {
    {
        let zc = conn_mut(w, idx).zc.as_mut().expect("zc in flight");
        zc.chain = zc.chain.saturating_sub(1);
        if op == OP_SPLICE_OUT && res > 0 {
            zc.out_left = zc.out_left.saturating_sub(res as u32);
        }
        if res < 0 {
            zc.err = true; // includes -ECANCELED from a broken link
        }
        if zc.chain > 0 {
            return; // wait for the rest of the chain
        }
    }
    let c = conn_mut(w, idx);
    let zc = c.zc.as_mut().expect("zc in flight");
    if zc.err {
        // Rare (e.g. EIO mid-read): drop the connection. Conn::drop releases
        // the dup'd fd and the pipe once in-flight ops drain.
        close_conn_ring(ring, w, idx);
        return;
    }
    if zc.out_left > 0 {
        // Socket took a partial splice-out; the remainder is still in the
        // pipe. Finish it on the normal (non-linked) splice-out path.
        zc.linked = false;
        c.txm = Tx::ZcOut;
        submit_splice_out(ring, w, idx);
        return;
    }
    let dupfd = zc.plan.fd;
    c.zc = None;
    unsafe { libc::close(dupfd) };
    c.tx.clear();
    c.tx_off = 0;
    c.txm = Tx::Idle;
    drive(ring, w, idx);
}

fn on_splice_in(ring: &mut IoUring, w: &mut Worker, idx: usize, res: i32) {
    if conn_mut(w, idx).zc.as_ref().is_some_and(|z| z.linked) {
        on_linked_cqe(ring, w, idx, OP_SPLICE_IN, res);
        return;
    }
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
    if conn_mut(w, idx).zc.as_ref().is_some_and(|z| z.linked) {
        on_linked_cqe(ring, w, idx, OP_SPLICE_OUT, res);
        return;
    }
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
