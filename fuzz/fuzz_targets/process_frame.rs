#![no_main]
//! Fuzz the SMB2 wire entry point: NetBIOS-framed message → parse_hdr →
//! compound dispatch → every command's body/offset/length parsing. A
//! read-only temp share keeps filesystem side effects minimal; fresh state
//! per input keeps iterations independent.
use libfuzzer_sys::fuzz_target;
use rocketsmbd::config::{Config, ShareCfg, Srv, UserCfg};
use rocketsmbd::session::Registry;
use rocketsmbd::smb2::{self, ProtoConn};

fn make_srv() -> Srv {
    let dir = std::env::temp_dir().join("rsmbd-fuzz-share");
    let _ = std::fs::create_dir_all(&dir);
    let cfg = Config {
        listen: "127.0.0.1:445".into(),
        workers: 1,
        server_name: "FUZZ".into(),
        log_level: 0,
        allow_guest: Some(true),
        require_signing: false,
        multichannel: true,
        encrypt: false,
        advertise_only: vec![],
        shares: vec![ShareCfg { name: "f".into(), path: dir, read_only: true }],
        users: vec![UserCfg { name: "u".into(), password: Some("p".into()), nt_hash: None }],
    };
    let users = cfg.user_db();
    let allow_guest = cfg.guest_allowed();
    Srv {
        cfg,
        guid: [0u8; 16],
        max_read: 1 << 20,
        start_ft: 0,
        users,
        allow_guest,
        interfaces: vec![],
        sessions: Registry::default(),
    }
}

fuzz_target!(|data: &[u8]| {
    let srv = make_srv();
    let mut pc = ProtoConn::new(&srv, 1);
    let mut tx = Vec::new();
    let _ = smb2::process_frame(&srv, &mut pc, data, &mut tx);
});
