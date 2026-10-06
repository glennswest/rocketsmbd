//! rocketsmbd — smbd replacement: io_uring end-to-end, zero-copy file→socket.
//! Thin binary wrapper around the `rocketsmbd` library.

#[macro_use]
extern crate rocketsmbd;

use rocketsmbd::config::Config;
use rocketsmbd::{config, log, vfs};
#[cfg(target_os = "linux")]
use rocketsmbd::{config::Srv, health, lease, net, session, smb2, uring};
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicUsize;
#[cfg(target_os = "linux")]
use std::sync::Arc;

const USAGE: &str = "usage: rocketsmbd [--config <path>] [--check] [--version]";

fn main() {
    let mut config_path = "rocketsmbd.toml".to_string();
    let mut check_only = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-c" => match args.next() {
                Some(p) => config_path = p,
                None => die(USAGE),
            },
            "--check" => check_only = true,
            "--version" | "-V" => {
                println!("rocketsmbd {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => die(USAGE),
        }
    }

    let cfg = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => die(&e),
    };
    log::set_level(cfg.log_level);
    for w in cfg.warnings() {
        eprintln!("rocketsmbd: warning: {w}");
    }
    if check_only {
        println!("config ok: {} share(s)", cfg.shares.len());
        return;
    }

    run(cfg);
}

fn die(msg: &str) -> ! {
    eprintln!("rocketsmbd: {msg}");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn run(cfg: Config) {
    // Hard kernel dependency: io_uring. Fail fast with a clear message.
    if let Err(e) = uring::probe_io_uring() {
        die(&e);
    }
    // splice()d sends must not raise SIGPIPE on dead sockets.
    // SAFETY: installs SIG_IGN (no Rust handler runs) before any thread exists.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    // The keytab is chosen via the environment; set it while still
    // single-threaded (setenv races C getenv in other threads).
    #[cfg(feature = "kerberos")]
    rocketsmbd::krb5::set_keytab_env(cfg.kerberos.as_ref().and_then(|k| k.keytab.as_deref()));

    let mut guid = [0u8; 16];
    config::urandom(&mut guid);
    let max_read = uring::probe_pipe_size(smb2::MAX_READ_TARGET);
    let users = cfg.user_db();
    let allow_guest = cfg.guest_allowed();
    if !users.is_empty() {
        logi!("{} user(s) loaded, guest {}", users.len(), if allow_guest { "allowed" } else { "denied" });
    }
    let mut interfaces = net::interfaces();
    if !cfg.advertise_only.is_empty() {
        interfaces.retain(|i| cfg.advertise_only.iter().any(|ip| ip == &i.addr.to_string()));
    }
    if cfg.multichannel {
        logi!(
            "multichannel enabled, advertising {}",
            interfaces
                .iter()
                .filter(|i| !i.loopback)
                .map(|i| i.addr.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let workers = if cfg.workers > 0 {
        cfg.workers
    } else {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    };

    // One break-delivery mailbox per worker (created before spawn so every
    // worker can reach every other worker's mailbox through the shared Srv).
    let mut mailboxes = Vec::with_capacity(workers);
    for _ in 0..workers {
        mailboxes.push(lease::Mailbox::new().expect("create worker mailbox"));
    }

    let srv = Arc::new(Srv {
        cfg,
        guid,
        max_read,
        start_ft: vfs::filetime_now(),
        users,
        allow_guest,
        interfaces,
        sessions: session::Registry::default(),
        mailboxes,
        leases: lease::LeaseTable::default(),
    });
    logi!(
        "rocketsmbd {} listening on {} ({} workers, max_read {} KiB)",
        env!("CARGO_PKG_VERSION"),
        srv.cfg.listen,
        workers,
        max_read / 1024
    );

    let workers_live = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for wid in 0..workers {
        let srv = Arc::clone(&srv);
        let guard = health::WorkerGuard::new(&workers_live);
        handles.push(
            std::thread::Builder::new()
                .name(format!("worker-{wid}"))
                .spawn(move || {
                    let _guard = guard;
                    if let Err(e) = uring::run_worker(wid, srv) {
                        logw!("worker {wid} exited: {e}");
                    }
                })
                .expect("spawn worker"),
        );
    }
    if let Some(addr) = &srv.cfg.health_listen {
        let state = health::State {
            workers_total: workers,
            workers_live,
            share_paths: srv.cfg.shares.iter().map(|s| s.path.clone()).collect(),
        };
        if let Err(e) = health::spawn(addr, state) {
            die(&e);
        }
        logi!("health endpoint on http://{addr}/healthz");
    }
    for h in handles {
        let _ = h.join();
    }
}

#[cfg(not(target_os = "linux"))]
fn run(_cfg: Config) {
    let _ = &_cfg;
    die("io_uring requires Linux; build/run on a Linux host (use --check to validate config)");
}
