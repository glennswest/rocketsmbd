//! io_uring reactor: one ring per worker thread, SO_REUSEPORT listeners,
//! completion-driven per-connection state machines.
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

const RX_INITIAL: usize = 68 * 1024;
const MAX_FRAME: usize = smb2::MAX_TRANSACT as usize + 0x11000;

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

enum St {
    Idle,
    Recv,
    /// Sending a fully-buffered response from tx.
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

struct Conn {
    fd: RawFd,
    gen: u16,
    proto: ProtoConn,
    rx: Vec<u8>,
    rx_len: usize,
    tx: Vec<u8>,
    tx_off: usize,
    pipe: Option<(RawFd, RawFd)>,
    pipe_cap: u32,
    zc: Option<Zc>,
    state: St,
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
    // Stale completion for a connection slot that has been recycled.
    let Some(conn) = w.conns.get_mut(idx).and_then(|c| c.as_mut()) else {
        return;
    };
    if conn.gen != gen {
        return;
    }
    match op {
        OP_RECV => on_recv(ring, w, idx, res),
        OP_SEND => on_send(ring, w, idx, res),
        OP_SPLICE_IN => on_splice_in(ring, w, idx, res),
        OP_SPLICE_OUT => on_splice_out(ring, w, idx, res),
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
        rx_len: 0,
        tx: Vec::with_capacity(4096),
        tx_off: 0,
        pipe: None,
        pipe_cap: 0,
        zc: None,
        state: St::Idle,
    });
    logd!("worker {}: new connection (slot {idx})", w.wid);
    start_recv(ring, w, idx);
}

fn close_conn(w: &mut Worker, idx: usize) {
    if w.conns[idx].take().is_some() {
        w.gens[idx] = w.gens[idx].wrapping_add(1).max(1);
        w.free.push(idx);
        logd!("worker {}: connection closed (slot {idx})", w.wid);
    }
}

fn conn_mut(w: &mut Worker, idx: usize) -> &mut Conn {
    w.conns[idx].as_mut().expect("live connection")
}

fn start_recv(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    let c = conn_mut(w, idx);
    if c.rx_len == c.rx.len() {
        let new_len = (c.rx.len() * 2).min(MAX_FRAME + 4);
        c.rx.resize(new_len, 0);
    }
    let buf = &mut c.rx[c.rx_len..];
    let e = opcode::Recv::new(types::Fd(c.fd), buf.as_mut_ptr(), buf.len() as u32)
        .build()
        .user_data(ud(OP_RECV, idx, c.gen));
    c.state = St::Recv;
    sq_push(ring, &e);
}

fn on_recv(ring: &mut IoUring, w: &mut Worker, idx: usize, res: i32) {
    if res == -libc::EINTR {
        start_recv(ring, w, idx);
        return;
    }
    if res <= 0 {
        close_conn(w, idx);
        return;
    }
    conn_mut(w, idx).rx_len += res as usize;
    advance(ring, w, idx);
}

/// Drive the connection: process any complete frame in rx, otherwise arm a
/// recv. Called whenever the previous operation chain finishes.
fn advance(ring: &mut IoUring, w: &mut Worker, idx: usize) {
    loop {
        let srv = Arc::clone(&w.srv);
        let c = conn_mut(w, idx);
        if c.rx_len < 4 {
            start_recv(ring, w, idx);
            return;
        }
        if c.rx[0] != 0 {
            // Only NetBIOS session messages are valid on direct TCP 445.
            close_conn(w, idx);
            return;
        }
        let flen = ((c.rx[1] as usize) << 16) | ((c.rx[2] as usize) << 8) | c.rx[3] as usize;
        if flen > MAX_FRAME {
            close_conn(w, idx);
            return;
        }
        let total = 4 + flen;
        if c.rx_len < total {
            if c.rx.len() < total {
                c.rx.resize(total, 0);
            }
            start_recv(ring, w, idx);
            return;
        }

        // Borrow rx and proto disjointly; process the frame into tx.
        let action = {
            let Conn { proto, rx, tx, .. } = c;
            smb2::process_frame(&srv, proto, &rx[4..total], tx)
        };
        // Consume the frame; keep any pipelined bytes that followed it.
        c.rx.copy_within(total..c.rx_len, 0);
        c.rx_len -= total;

        match action {
            FrameAction::Respond => {
                if c.tx.is_empty() {
                    continue; // no response (e.g. CANCEL) — look for next frame
                }
                c.tx_off = 0;
                c.state = St::Send;
                submit_send(ring, w, idx, 0);
                return;
            }
            FrameAction::ZcRead(plan) => {
                start_zc(ring, w, idx, plan);
                return;
            }
        }
    }
}

fn submit_send(ring: &mut IoUring, w: &mut Worker, idx: usize, msg_flags: i32) {
    let c = conn_mut(w, idx);
    let buf = &c.tx[c.tx_off..];
    let e = opcode::Send::new(types::Fd(c.fd), buf.as_ptr(), buf.len() as u32)
        .flags(msg_flags)
        .build()
        .user_data(ud(OP_SEND, idx, c.gen));
    sq_push(ring, &e);
}

fn on_send(ring: &mut IoUring, w: &mut Worker, idx: usize, res: i32) {
    if res == -libc::EINTR {
        let flags = matches!(conn_mut(w, idx).state, St::ZcHdr) as i32 * libc::MSG_MORE;
        submit_send(ring, w, idx, flags);
        return;
    }
    if res <= 0 {
        close_conn(w, idx);
        return;
    }
    let c = conn_mut(w, idx);
    c.tx_off += res as usize;
    let done = c.tx_off >= c.tx.len();
    match c.state {
        St::ZcHdr => {
            if done {
                c.state = St::ZcOut;
                submit_splice_out(ring, w, idx);
            } else {
                submit_send(ring, w, idx, libc::MSG_MORE);
            }
        }
        _ => {
            if done {
                c.state = St::Idle;
                advance(ring, w, idx);
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
    if c.pipe.is_none() {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            let mut tx = std::mem::take(&mut c.tx);
            smb2::build_read_err(&plan, status::INSUFFICIENT_RESOURCES, &mut tx);
            c.tx = tx;
            c.tx_off = 0;
            c.state = St::Send;
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
    c.state = St::ZcIn;
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
    sq_push(ring, &e);
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
    c.state = St::ZcHdr;
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
    c.tx = tx;
    c.tx_off = 0;
    c.state = St::Send;
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
    sq_push(ring, &e);
}

fn on_splice_out(ring: &mut IoUring, w: &mut Worker, idx: usize, res: i32) {
    if res == -libc::EINTR || res == -libc::EAGAIN {
        submit_splice_out(ring, w, idx);
        return;
    }
    if res <= 0 {
        // Socket gone; pipe contents die with the connection.
        close_conn(w, idx);
        return;
    }
    let c = conn_mut(w, idx);
    let zc = c.zc.as_mut().expect("zc in flight");
    zc.out_left -= (res as u32).min(zc.out_left);
    if zc.out_left > 0 {
        submit_splice_out(ring, w, idx);
        return;
    }
    c.zc = None;
    c.state = St::Idle;
    advance(ring, w, idx);
}
