//! Opt-in HTTP health endpoint (`health_listen`, #46/#49).
//!
//! Off by default: rocketsmbd's SMB surface is TCP 445 only. When an admin
//! address is configured (stormcos sets a loopback one so stormd's HTTP
//! liveness probe has something to call), one plain std thread — not an
//! io_uring worker, so a stuck probe client can't stall SMB traffic — serves:
//!
//! - `GET /healthz` (or `HEAD`) → `200` while every worker thread is alive
//!   and every share path is still a directory, `503` otherwise. The body is
//!   a small JSON object: status, version, live/total workers, shares
//!   ok/total. No share names or paths are disclosed.
//! - any other path → `404`; any other method → `405`.
//!
//! Requests are read with a timeout and a size cap and served one at a time;
//! each connection gets one response and is closed.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Largest request head we read; a probe's request is a few dozen bytes.
const MAX_REQUEST: usize = 4096;
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// What `/healthz` reports on.
pub struct State {
    /// Worker threads spawned.
    pub workers_total: usize,
    /// Worker threads still running (a [`WorkerGuard`] per worker).
    pub workers_live: Arc<AtomicUsize>,
    /// Every share's path, checked on each probe.
    pub share_paths: Vec<PathBuf>,
}

/// Counts a worker as live from creation until drop — including a drop
/// during a panic unwind, so a crashed worker turns `/healthz` to 503.
pub struct WorkerGuard(Arc<AtomicUsize>);

impl WorkerGuard {
    pub fn new(live: &Arc<AtomicUsize>) -> WorkerGuard {
        live.fetch_add(1, Ordering::SeqCst);
        WorkerGuard(Arc::clone(live))
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Bind `addr` and serve health probes on a background thread. Binding
/// happens here, so a bad or busy address fails startup instead of leaving
/// the probe failing later.
pub fn spawn(addr: &str, state: State) -> Result<(), String> {
    let listener =
        TcpListener::bind(addr).map_err(|e| format!("health_listen {addr}: {e}"))?;
    std::thread::Builder::new()
        .name("health".into())
        .spawn(move || serve(listener, state))
        .map_err(|e| format!("spawn health thread: {e}"))?;
    Ok(())
}

fn serve(listener: TcpListener, state: State) {
    for conn in listener.incoming() {
        match conn {
            Ok(s) => handle(s, &state),
            Err(e) => logd!("health accept: {e}"),
        }
    }
}

fn handle(mut s: TcpStream, state: &State) {
    let _ = s.set_read_timeout(Some(IO_TIMEOUT));
    let _ = s.set_write_timeout(Some(IO_TIMEOUT));
    let mut buf = [0u8; MAX_REQUEST];
    let mut n = 0;
    while n < buf.len() && !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    let _ = s.write_all(&respond(&buf[..n], state));
}

/// Build the full HTTP response for a raw request head.
pub fn respond(req: &[u8], state: &State) -> Vec<u8> {
    let line = req.split(|&b| b == b'\r' || b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = target.split('?').next().unwrap_or("");
    let head = method == "HEAD";
    if method != "GET" && !head {
        return reply("405 Method Not Allowed", "{\"error\":\"method not allowed\"}", false);
    }
    if path != "/healthz" {
        return reply("404 Not Found", "{\"error\":\"not found\"}", head);
    }
    let live = state.workers_live.load(Ordering::SeqCst);
    let shares_ok = state.share_paths.iter().filter(|p| p.is_dir()).count();
    let ok = live == state.workers_total && shares_ok == state.share_paths.len();
    let body = format!(
        "{{\"status\":\"{}\",\"version\":\"{}\",\"workers\":{{\"live\":{},\"total\":{}}},\"shares\":{{\"ok\":{},\"total\":{}}}}}",
        if ok { "ok" } else { "degraded" },
        env!("CARGO_PKG_VERSION"),
        live,
        state.workers_total,
        shares_ok,
        state.share_paths.len()
    );
    reply(if ok { "200 OK" } else { "503 Service Unavailable" }, &body, head)
}

fn reply(status: &str, body: &str, head: bool) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    if !head {
        out.extend_from_slice(body.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(total: usize, live: usize, paths: Vec<PathBuf>) -> State {
        State { workers_total: total, workers_live: Arc::new(AtomicUsize::new(live)), share_paths: paths }
    }

    fn status_of(resp: &[u8]) -> String {
        String::from_utf8_lossy(resp).lines().next().unwrap_or("").to_string()
    }

    #[test]
    fn healthy_is_200_with_json() {
        let st = state(2, 2, vec![std::env::temp_dir()]);
        let r = respond(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n", &st);
        assert_eq!(status_of(&r), "HTTP/1.1 200 OK");
        let s = String::from_utf8(r).unwrap();
        assert!(s.ends_with(&format!(
            "{{\"status\":\"ok\",\"version\":\"{}\",\"workers\":{{\"live\":2,\"total\":2}},\"shares\":{{\"ok\":1,\"total\":1}}}}",
            env!("CARGO_PKG_VERSION")
        )));
        // Query strings are ignored; HEAD gets headers only.
        assert_eq!(status_of(&respond(b"GET /healthz?x=1 HTTP/1.0\r\n\r\n", &st)), "HTTP/1.1 200 OK");
        let h = respond(b"HEAD /healthz HTTP/1.1\r\n\r\n", &st);
        assert!(String::from_utf8(h).unwrap().ends_with("\r\n\r\n"));
    }

    #[test]
    fn dead_worker_or_missing_share_is_503() {
        let r = respond(b"GET /healthz HTTP/1.1\r\n\r\n", &state(2, 1, vec![std::env::temp_dir()]));
        assert_eq!(status_of(&r), "HTTP/1.1 503 Service Unavailable");
        let gone = std::env::temp_dir().join("rocketsmbd-health-test-no-such-dir");
        let r = respond(b"GET /healthz HTTP/1.1\r\n\r\n", &state(1, 1, vec![gone]));
        assert_eq!(status_of(&r), "HTTP/1.1 503 Service Unavailable");
        assert!(String::from_utf8(r).unwrap().contains("\"status\":\"degraded\""));
    }

    #[test]
    fn other_paths_and_methods() {
        let st = state(1, 1, vec![]);
        assert_eq!(status_of(&respond(b"GET / HTTP/1.1\r\n\r\n", &st)), "HTTP/1.1 404 Not Found");
        assert_eq!(status_of(&respond(b"POST /healthz HTTP/1.1\r\n\r\n", &st)), "HTTP/1.1 405 Method Not Allowed");
        assert_eq!(status_of(&respond(b"", &st)), "HTTP/1.1 405 Method Not Allowed");
        assert_eq!(status_of(&respond(&[0xff; 64], &st)), "HTTP/1.1 405 Method Not Allowed");
    }

    #[test]
    fn worker_guard_tracks_panics() {
        let live = Arc::new(AtomicUsize::new(0));
        let g = WorkerGuard::new(&live);
        let l2 = Arc::clone(&live);
        let t = std::thread::spawn(move || {
            let _g = WorkerGuard::new(&l2);
            panic!("worker died");
        });
        assert!(t.join().is_err());
        assert_eq!(live.load(Ordering::SeqCst), 1);
        drop(g);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn serves_over_tcp() {
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        spawn(&addr.to_string(), state(1, 1, vec![std::env::temp_dir()])).unwrap();
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let mut resp = String::new();
        c.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        // A second bind of the same address must fail at spawn, not later.
        assert!(spawn(&addr.to_string(), state(1, 1, vec![])).is_err());
    }
}
