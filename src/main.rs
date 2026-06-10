//! rocketsmbd — smbd replacement: io_uring end-to-end, zero-copy file→socket.

// Off-Linux the reactor is compiled out, so most protocol code is "dead";
// dev hosts (macOS) still run the unit tests.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod config;
mod crypto;
mod log;
mod net;
mod session;
mod ntlm;
mod smb2;
mod status;
mod vfs;
mod wire;

#[cfg(target_os = "linux")]
mod uring;

use config::Config;
#[cfg(target_os = "linux")]
use {config::Srv, std::sync::Arc};

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
    // splice()d sends must not raise SIGPIPE on dead sockets.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

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
    let srv = Arc::new(Srv {
        cfg,
        guid,
        max_read,
        start_ft: vfs::filetime_now(),
        users,
        allow_guest,
        interfaces,
        sessions: session::Registry::default(),
    });

    let workers = if srv.cfg.workers > 0 {
        srv.cfg.workers
    } else {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    };
    logi!(
        "rocketsmbd {} listening on {} ({} workers, max_read {} KiB)",
        env!("CARGO_PKG_VERSION"),
        srv.cfg.listen,
        workers,
        max_read / 1024
    );

    let mut handles = Vec::new();
    for wid in 0..workers {
        let srv = Arc::clone(&srv);
        handles.push(
            std::thread::Builder::new()
                .name(format!("worker-{wid}"))
                .spawn(move || {
                    if let Err(e) = uring::run_worker(wid, srv) {
                        logw!("worker {wid} exited: {e}");
                    }
                })
                .expect("spawn worker"),
        );
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
