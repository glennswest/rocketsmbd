//! rocketsmbd's test container (stormcentral docs/test-standard.md, #44).
//!
//! `/test <short|medium|long>` starts `/rocketsmbd` on loopback with a
//! generated config (a random password, so no secret is baked in) and drives
//! it with the SMB2/3 client in `client.rs`. One JSON line per test, then a
//! summary. Exit 0 = all passed, 1 = a test failed, 2 = could not run (e.g. no
//! io_uring in this kernel/container — the one thing it needs from the node).

mod client;

use client::{Client, R};
use rocketsmbd::crypto;
use rocketsmbd::status;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE_IF: u32 = 5;
const DIRECTORY_FILE: u32 = 0x1;
const NON_DIRECTORY_FILE: u32 = 0x40;
const RW: u32 = 0x0012_019F; // generic read/write file access
const RO: u32 = 0x0012_0089; // read data/attrs/EA, read control, synchronize
const DIR_LIST: u32 = 0x0010_0081; // list directory, read attrs, synchronize
const USER: &str = "tester";

fn main() {
    let suite = std::env::args().nth(1).unwrap_or_default();
    if !matches!(suite.as_str(), "short" | "medium" | "long") {
        eprintln!("usage: /test <short|medium|long>");
        std::process::exit(2);
    }
    let budget = std::env::var("STORM_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(match suite.as_str() {
            "short" => 120,
            "medium" => 1800,
            _ => 900,
        });
    let mut t = Tally::default();
    let env = match Env::start() {
        Ok(e) => e,
        Err(Start::NoIoUring(why)) => {
            t.report("server-start", "skip", 0, &format!("requires io_uring (kernel >= 5.15, not blocked by the container's seccomp): {why}"));
            t.summary();
            std::process::exit(2);
        }
        Err(Start::Other(why)) => {
            t.report("server-start", "fail", 0, &why);
            t.summary();
            std::process::exit(2);
        }
    };
    t.report("server-start", "pass", env.started_ms, &format!("rocketsmbd on {} (pid {})", env.addr, env.child.id()));

    let mut tests: Vec<(&str, fn(&Env) -> R<String>)> = vec![
        ("guest-write-read-dir", guest_write_read_dir),
        ("ntlmv2-signed-311", ntlmv2_signed_311),
        ("sealed-aes128gcm", sealed_aes128gcm),
        ("lease-break-on-write", lease_break_on_write),
        ("healthz", healthz),
    ];
    if suite != "short" {
        tests.extend([
            ("wrong-password-refused", wrong_password_refused as fn(&Env) -> R<String>),
            ("read-only-share", read_only_share),
            ("sealed-all-ciphers", sealed_all_ciphers),
            ("large-file-64mib", large_file),
            ("parallel-clients", parallel_clients),
            ("replay-disconnects", replay_disconnects),
            ("healthz-503-when-share-gone", healthz_503),
        ]);
    }
    for (name, f) in tests {
        t.run(name, || f(&env));
    }
    if suite == "long" {
        let deadline = Instant::now() + Duration::from_secs(budget.saturating_sub(60).max(60));
        t.run("waves-no-leak", || waves(&env, deadline));
    }
    drop(env);
    t.summary();
    std::process::exit(if t.fail > 0 { 1 } else { 0 });
}

// ------------------------------------------------------------------ output

#[derive(Default)]
struct Tally {
    pass: u32,
    fail: u32,
    skip: u32,
}

impl Tally {
    fn report(&mut self, test: &str, st: &str, ms: u128, detail: &str) {
        match st {
            "pass" => self.pass += 1,
            "skip" => self.skip += 1,
            _ => self.fail += 1,
        }
        println!(r#"{{"test": "{}", "status": "{st}", "ms": {ms}, "detail": "{}"}}"#, esc(test), esc(detail));
        let _ = std::io::stdout().flush();
    }
    fn run(&mut self, name: &str, f: impl FnOnce() -> R<String>) {
        let t0 = Instant::now();
        let r = f();
        let ms = t0.elapsed().as_millis();
        match r {
            Ok(d) => self.report(name, "pass", ms, &d),
            Err(e) => self.report(name, "fail", ms, &e),
        }
    }
    fn summary(&self) {
        println!(r#"{{"summary": {{"pass": {}, "fail": {}, "skip": {}}}}}"#, self.pass, self.fail, self.skip);
    }
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

// ---------------------------------------------------------------- the server

enum Start {
    NoIoUring(String),
    Other(String),
}

struct Env {
    child: Child,
    dir: PathBuf,
    addr: String,
    health: String,
    password: String,
    started_ms: u128,
}

fn free_port() -> R<u16> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

impl Env {
    fn start() -> Result<Env, Start> {
        let other = Start::Other;
        let t0 = Instant::now();
        let base = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
        let dir = base.join(format!("rocketsmbd-test-{}", std::process::id()));
        for d in ["data", "ro", "extra"] {
            std::fs::create_dir_all(dir.join(d)).map_err(|e| other(format!("create {}: {e}", dir.join(d).display())))?;
        }
        std::fs::write(dir.join("ro/readme.txt"), b"read-only share\n").map_err(|e| other(e.to_string()))?;
        let mut pw = [0u8; 12];
        rocketsmbd::config::urandom(&mut pw);
        let password: String = pw.iter().map(|b| format!("{b:02x}")).collect();
        let port = free_port().map_err(other)?;
        let hport = free_port().map_err(other)?;
        let addr = format!("127.0.0.1:{port}");
        let health = format!("127.0.0.1:{hport}");
        let cfg = format!(
            "listen = \"{addr}\"\nworkers = 2\nserver_name = \"RSMBDTEST\"\nlog_level = 1\n\
             core_pinning = false\nhealth_listen = \"{health}\"\noplocks = true\n\
             allow_guest = true\nrequire_signing = false\nencrypt = false\n\
             [[share]]\nname = \"data\"\npath = \"{d}/data\"\n\
             [[share]]\nname = \"ro\"\npath = \"{d}/ro\"\nread_only = true\n\
             [[share]]\nname = \"extra\"\npath = \"{d}/extra\"\n\
             [[user]]\nname = \"{USER}\"\npassword = \"{password}\"\n",
            d = dir.display()
        );
        let cfg_path = dir.join("rocketsmbd.toml");
        std::fs::write(&cfg_path, cfg).map_err(|e| other(e.to_string()))?;
        let bin = std::env::var("ROCKETSMBD_BIN").unwrap_or_else(|_| "/rocketsmbd".into());
        let log = std::fs::File::create(dir.join("server.log")).map_err(|e| other(e.to_string()))?;
        let child = Command::new(&bin)
            .arg("--config")
            .arg(&cfg_path)
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| other(e.to_string()))?)
            .stderr(log)
            .spawn()
            .map_err(|e| other(format!("start {bin}: {e}")))?;
        let mut env = Env { child, dir, addr, health, password, started_ms: 0 };
        // Ready when it accepts; gone if it exits (no io_uring, bad config).
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(Some(st)) = env.child.try_wait() {
                let log = std::fs::read_to_string(env.dir.join("server.log")).unwrap_or_default();
                let why = format!("rocketsmbd exited ({st}): {}", log.trim());
                return Err(if log.contains("io_uring") { Start::NoIoUring(why) } else { Start::Other(why) });
            }
            if TcpStream::connect(&env.addr).is_ok() {
                break;
            }
            if Instant::now() > deadline {
                return Err(Start::Other("rocketsmbd did not accept connections within 10 s".into()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        env.started_ms = t0.elapsed().as_millis();
        Ok(env)
    }

    /// An authenticated, signed SMB 3.1.1 session connected to `share`.
    fn user(&self, share: &str, cipher: Option<u16>) -> R<(Client, u32)> {
        let mut c = Client::connect(&self.addr)?;
        c.negotiate(&[0x0311, 0x0302, 0x0300, 0x0210], cipher, true)?;
        let st = c.session_setup(Some((USER, &self.password)), true)?;
        if st != status::SUCCESS {
            return Err(format!("SESSION_SETUP status {st:#x}"));
        }
        if cipher.is_some() {
            c.seal = true;
        }
        let (st, tree) = c.tree_connect(share)?;
        if st != status::SUCCESS {
            return Err(format!("TREE_CONNECT {share} status {st:#x}"));
        }
        Ok((c, tree))
    }

    /// The server's open fds and resident memory (KiB), from /proc.
    fn usage(&self) -> (usize, u64) {
        let pid = self.child.id();
        let fds = std::fs::read_dir(format!("/proc/{pid}/fd")).map(|d| d.count()).unwrap_or(0);
        let rss = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
            })
            .unwrap_or(0);
        (fds, rss)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Keep the server log as an artifact when the results dir exists
        // (/results in the Job; RESULTS_DIR overrides it for local runs).
        let results = std::env::var_os("RESULTS_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/results"));
        if results.is_dir() {
            let _ = std::fs::copy(self.dir.join("server.log"), results.join("rocketsmbd.log"));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ------------------------------------------------------------------ helpers

/// Deterministic pseudo-random bytes (xorshift), so a mismatch is
/// reproducible from the seed.
fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut v = Vec::with_capacity(len + 8);
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    v
}

fn digest(b: &[u8]) -> String {
    crypto::sha512(&[b])[..8].iter().map(|x| format!("{x:02x}")).collect()
}

fn check(cond: bool, msg: impl FnOnce() -> String) -> R<()> {
    if cond {
        Ok(())
    } else {
        Err(msg())
    }
}

/// Write `data` as `name` (create/overwrite), read it back, compare digests.
fn roundtrip(c: &mut Client, tree: u32, name: &str, data: &[u8]) -> R<()> {
    let o = c.create(tree, name, FILE_OVERWRITE_IF, RW, NON_DIRECTORY_FILE, None)?;
    check(o.status == status::SUCCESS, || format!("CREATE {name} status {:#x}", o.status))?;
    c.write_all(tree, o.fid, data)?;
    let back = c.read_all(tree, o.fid, data.len())?;
    c.close(tree, o.fid)?;
    check(back == data, || format!("{name}: read back {} != written {}", digest(&back), digest(data)))
}

// -------------------------------------------------------------------- tests

/// The main job: a guest on SMB 3.0.2 writes 4 MiB, reads it back through
/// the zero-copy READ path (unsigned reads ≥ 8 KiB are spliced), and finds
/// the file in a directory listing.
fn guest_write_read_dir(env: &Env) -> R<String> {
    let mut c = Client::connect(&env.addr)?;
    c.negotiate(&[0x0302, 0x0300, 0x0210], None, false)?;
    let st = c.session_setup(None, false)?;
    check(st == status::SUCCESS && c.guest, || format!("guest SESSION_SETUP status {st:#x}, guest {}", c.guest))?;
    let (st, tree) = c.tree_connect("data")?;
    check(st == status::SUCCESS, || format!("TREE_CONNECT status {st:#x}"))?;
    let data = pattern(4 << 20, 1);
    roundtrip(&mut c, tree, "guest.bin", &data)?;
    let d = c.create(tree, "", FILE_OPEN, DIR_LIST, DIRECTORY_FILE, None)?;
    check(d.status == status::SUCCESS, || format!("open share root status {:#x}", d.status))?;
    let names = c.list(tree, d.fid)?;
    c.close(tree, d.fid)?;
    check(names.iter().any(|n| n == "guest.bin"), || format!("guest.bin not listed: {names:?}"))?;
    c.logoff()?;
    Ok(format!("dialect {:#x}, 4 MiB sha512 {} round-tripped, listed {} entries", c.dialect, digest(&data), names.len()))
}

/// NTLMv2 on SMB 3.1.1 with signing required: every request is signed
/// (AES-CMAC, preauth-derived key) and every reply's signature verifies.
fn ntlmv2_signed_311(env: &Env) -> R<String> {
    let (mut c, tree) = env.user("data", None)?;
    check(c.dialect == 0x0311, || format!("dialect {:#x}, want 3.1.1", c.dialect))?;
    let data = pattern(1 << 20, 2);
    roundtrip(&mut c, tree, "signed.bin", &data)?;
    c.logoff()?;
    Ok("3.1.1, signed requests, every reply signature verified, 1 MiB round-tripped".into())
}

/// SMB3 encryption (AES-128-GCM): requests sealed, replies decrypt; a
/// plaintext request on the sealed session is refused (#39 R1).
fn sealed_aes128gcm(env: &Env) -> R<String> {
    let (mut c, tree) = env.user("data", Some(crypto::CIPHER_AES128_GCM))?;
    check(c.cipher() == crypto::CIPHER_AES128_GCM, || format!("server picked cipher {:#x}", c.cipher()))?;
    let data = pattern(2 << 20, 3);
    roundtrip(&mut c, tree, "sealed.bin", &data)?;
    let mut echo = Vec::new();
    rocketsmbd::wire::Put::p16(&mut echo, 4);
    rocketsmbd::wire::Put::p16(&mut echo, 0);
    let r = c.plain_request(rocketsmbd::smb2::CMD_ECHO, 0, &echo)?;
    check(r.status == status::ACCESS_DENIED, || format!("plaintext ECHO on a sealed session: status {:#x}, want ACCESS_DENIED", r.status))?;
    c.logoff()?;
    Ok("2 MiB round-tripped sealed; plaintext request refused".into())
}

/// Client A holds an R|H lease; client B (another session) writes the file;
/// A must get a lease break notification for its key.
fn lease_break_on_write(env: &Env) -> R<String> {
    let mut a = Client::connect(&env.addr)?;
    a.negotiate(&[0x0302, 0x0210], None, false)?;
    check(a.session_setup(None, false)? == status::SUCCESS, || "A: guest session failed".into())?;
    let (_, ta) = a.tree_connect("data")?;
    let key = [0x5A; 16];
    let o = a.create(ta, "leased.txt", FILE_OVERWRITE_IF, RW, NON_DIRECTORY_FILE, Some(key))?;
    check(o.status == status::SUCCESS, || format!("A: CREATE status {:#x}", o.status))?;
    check(o.oplock == rocketsmbd::smb2::OPLOCK_LEASE && o.lease_state & rocketsmbd::smb2::LEASE_READ_CACHING != 0, || {
        format!("A: no read lease granted (oplock {:#x}, state {:#x})", o.oplock, o.lease_state)
    })?;
    let (mut b, tb) = env.user("data", None)?;
    let ob = b.create(tb, "leased.txt", FILE_OPEN, RW, NON_DIRECTORY_FILE, None)?;
    check(ob.status == status::SUCCESS, || format!("B: CREATE status {:#x}", ob.status))?;
    check(b.write(tb, ob.fid, 0, b"changed by B")? == status::SUCCESS, || "B: WRITE failed".into())?;
    let brk = a.wait_unsolicited(rocketsmbd::smb2::CMD_OPLOCK_BREAK, Duration::from_secs(5))?;
    let brk = brk.ok_or("A: no lease break within 5 s of B's write")?;
    let body = brk.body();
    check(body.len() >= 44 && body[8..24] == key, || "A: lease break for a different key".into())?;
    b.close(tb, ob.fid)?;
    a.close(ta, o.fid)?;
    Ok(format!("lease state {:#x} granted; break received for A's key", o.lease_state))
}

fn http_get(addr: &str, path: &str) -> R<(u16, String)> {
    let mut s = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| e.to_string())?;
    let code = out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or("no HTTP status")?;
    let body = out.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((code, body))
}

fn healthz(env: &Env) -> R<String> {
    let (code, body) = http_get(&env.health, "/healthz")?;
    check(code == 200 && body.contains("\"ok\""), || format!("GET /healthz: {code} {body}"))?;
    Ok(body)
}

fn wrong_password_refused(env: &Env) -> R<String> {
    let mut c = Client::connect(&env.addr)?;
    c.negotiate(&[0x0311], None, true)?;
    let st = c.session_setup(Some((USER, "not-the-password")), true)?;
    check(st == status::LOGON_FAILURE, || format!("status {st:#x}, want LOGON_FAILURE"))?;
    Ok("LOGON_FAILURE".into())
}

/// A read-only share serves reads but refuses writes and creates
/// (including FILE_OPEN_IF of a missing file, #39 R4).
fn read_only_share(env: &Env) -> R<String> {
    let (mut c, tree) = env.user("ro", None)?;
    let o = c.create(tree, "readme.txt", FILE_OPEN, RO, NON_DIRECTORY_FILE, None)?;
    check(o.status == status::SUCCESS, || format!("open readme.txt status {:#x}", o.status))?;
    let (st, d) = c.read(tree, o.fid, 0, 4096)?;
    check(st == status::SUCCESS && d == b"read-only share\n", || format!("read: status {st:#x}, {} bytes", d.len()))?;
    c.close(tree, o.fid)?;
    let w = c.create(tree, "readme.txt", FILE_OPEN, RW, NON_DIRECTORY_FILE, None)?;
    check(w.status == status::ACCESS_DENIED, || format!("open for write: status {:#x}", w.status))?;
    for (disp, what) in [(FILE_CREATE, "FILE_CREATE"), (FILE_OPEN_IF, "FILE_OPEN_IF")] {
        let n = c.create(tree, "new.txt", disp, RO, NON_DIRECTORY_FILE, None)?;
        check(n.status == status::ACCESS_DENIED, || format!("{what} of a new file: status {:#x}", n.status))?;
    }
    check(!env.dir.join("ro/new.txt").exists(), || "a file was created on the read-only share".into())?;
    Ok("reads served; write open, FILE_CREATE and FILE_OPEN_IF refused".into())
}

fn sealed_all_ciphers(env: &Env) -> R<String> {
    let mut done = Vec::new();
    for (cipher, name) in [
        (crypto::CIPHER_AES128_GCM, "AES-128-GCM"),
        (crypto::CIPHER_AES256_GCM, "AES-256-GCM"),
        (crypto::CIPHER_AES128_CCM, "AES-128-CCM"),
        (crypto::CIPHER_AES256_CCM, "AES-256-CCM"),
    ] {
        let (mut c, tree) = env.user("data", Some(cipher))?;
        check(c.cipher() == cipher, || format!("{name}: server picked {:#x}", c.cipher()))?;
        roundtrip(&mut c, tree, &format!("sealed-{cipher}.bin"), &pattern(1 << 20, cipher as u64))
            .map_err(|e| format!("{name}: {e}"))?;
        c.logoff()?;
        done.push(name);
    }
    Ok(format!("1 MiB sealed round trip with {}", done.join(", ")))
}

fn large_file(env: &Env) -> R<String> {
    let (mut c, tree) = env.user("data", None)?;
    let data = pattern(64 << 20, 7);
    let t0 = Instant::now();
    roundtrip(&mut c, tree, "large.bin", &data)?;
    let secs = t0.elapsed().as_secs_f64().max(0.001);
    c.logoff()?;
    Ok(format!("64 MiB written and read back signed, {:.0} MiB/s", 128.0 / secs))
}

fn parallel_clients(env: &Env) -> R<String> {
    let n = 16;
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let (addr, pw) = (env.addr.clone(), env.password.clone());
            std::thread::spawn(move || -> R<()> {
                let mut c = Client::connect(&addr)?;
                c.negotiate(&[0x0311], None, i % 2 == 0)?;
                let st = if i % 2 == 0 { c.session_setup(Some((USER, &pw)), true)? } else { c.session_setup(None, false)? };
                check(st == status::SUCCESS, || format!("client {i}: SESSION_SETUP {st:#x}"))?;
                let (_, tree) = c.tree_connect("data")?;
                roundtrip(&mut c, tree, &format!("par-{i}.bin"), &pattern(4 << 20, 100 + i))
                    .map_err(|e| format!("client {i}: {e}"))
            })
        })
        .collect();
    for h in handles {
        h.join().map_err(|_| "client thread panicked".to_string())??;
    }
    Ok(format!("{n} concurrent clients (signed and guest), 4 MiB each"))
}

/// Re-sending a request's exact bytes (same MessageId and signature) must
/// make the server disconnect (#39 R9).
fn replay_disconnects(env: &Env) -> R<String> {
    let (mut c, _) = env.user("data", None)?;
    check(c.echo()? == status::SUCCESS, || "ECHO failed".into())?;
    let wire = c.last_wire.clone();
    c.send_wire(&wire)?;
    check(c.closed_within(Duration::from_secs(5)), || "server answered a replayed request".into())?;
    Ok("replayed signed ECHO: connection closed".into())
}

fn healthz_503(env: &Env) -> R<String> {
    std::fs::remove_dir_all(env.dir.join("extra")).map_err(|e| e.to_string())?;
    let (code, body) = http_get(&env.health, "/healthz")?;
    let _ = std::fs::create_dir_all(env.dir.join("extra"));
    check(code == 503, || format!("GET /healthz with a share dir gone: {code} {body}"))?;
    let (code, _) = http_get(&env.health, "/healthz")?;
    check(code == 200, || format!("not healthy again after restoring the share: {code}"))?;
    Ok("503 while a share directory is missing, 200 once it is back".into())
}

/// Overnight-style waves: 8–32 parallel clients connect, write, read, close
/// and drop, until the deadline. Fails if the server's fds or RSS grow wave
/// over wave (leaks), or if a wave is much slower than the first.
fn waves(env: &Env, deadline: Instant) -> R<String> {
    let (fd0, rss0) = env.usage();
    let mut wave = 0u64;
    let mut first_ms = 0u128;
    let mut worst = (0usize, 0u64, 0u128);
    while Instant::now() < deadline {
        wave += 1;
        let n = 8 + (wave % 4) * 8;
        let t0 = Instant::now();
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let (addr, pw) = (env.addr.clone(), env.password.clone());
                std::thread::spawn(move || -> R<()> {
                    let mut c = Client::connect(&addr)?;
                    c.negotiate(&[0x0311, 0x0302], None, true)?;
                    c.session_setup(Some((USER, &pw)), true)?;
                    let (_, tree) = c.tree_connect("data")?;
                    roundtrip(&mut c, tree, &format!("wave-{i}.bin"), &pattern(1 << 20, wave * 1000 + i))
                    // dropped without LOGOFF: teardown must free the session
                })
            })
            .collect();
        for h in handles {
            h.join().map_err(|_| "client thread panicked".to_string())?.map_err(|e| format!("wave {wave}: {e}"))?;
        }
        let ms = t0.elapsed().as_millis();
        if wave == 1 {
            first_ms = ms.max(1);
        }
        std::thread::sleep(Duration::from_millis(200)); // let teardown finish
        let (fd, rss) = env.usage();
        worst = (worst.0.max(fd), worst.1.max(rss), worst.2.max(ms));
        if fd > fd0 + 16 {
            return Err(format!("wave {wave}: server fds {fd0} -> {fd} (leak)"));
        }
        if wave > 3 && ms > first_ms * 5 + 2000 {
            return Err(format!("wave {wave} took {ms} ms, first took {first_ms} ms"));
        }
    }
    let (fd, rss) = env.usage();
    if rss0 > 0 && rss > rss0 * 3 + 64 * 1024 {
        return Err(format!("server RSS {rss0} KiB -> {rss} KiB over {wave} waves"));
    }
    Ok(format!(
        "{wave} waves; fds {fd0} -> {fd} (max {}), RSS {rss0} -> {rss} KiB (max {}), slowest wave {} ms (first {first_ms})",
        worst.0, worst.1, worst.2
    ))
}
