//! TOML configuration and resolved server context.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// 0 = one worker per CPU core.
    #[serde(default)]
    pub workers: usize,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// 0 = warn, 1 = info, 2 = debug.
    #[serde(default = "default_log_level")]
    pub log_level: u8,
    /// Allow unauthenticated guest sessions. Defaults to true when no
    /// [[user]] entries exist (compat), false otherwise.
    #[serde(default)]
    pub allow_guest: Option<bool>,
    /// Require SMB2 signing from authenticated sessions.
    #[serde(default)]
    pub require_signing: bool,
    /// Advertise SMB3 multichannel and accept session binding so a single
    /// client can stripe one share across multiple connections (cores).
    #[serde(default)]
    pub multichannel: bool,
    /// Require SMB3 encryption (AES-128-GCM): the server tells clients to seal
    /// all post-auth traffic. When false, client-initiated encryption (e.g.
    /// cifs `seal`) is still honored if a cipher is negotiated.
    #[serde(default)]
    pub encrypt: bool,
    /// Restrict multichannel interface advertisement to these IPs (e.g. a
    /// dedicated storage NIC). Empty = advertise all non-loopback interfaces.
    #[serde(default)]
    pub advertise_only: Vec<String>,
    /// Pin each worker thread to a CPU core (worker N → core N mod ncpu) so a
    /// connection's ring, softirqs, and cache stay on one core. Default on.
    #[serde(default = "default_true")]
    pub core_pinning: bool,
    /// Enable io_uring SQPOLL: a kernel thread polls the submission queue so
    /// submits need no syscall. Helps at high IOPS / many channels; costs a
    /// busy kernel thread per worker, so it is opt-in. Default off.
    #[serde(default)]
    pub sqpoll: bool,
    /// Prefer AES-256 ciphers (GCM then CCM) when the client offers them,
    /// instead of honoring the client's preference order (which usually picks
    /// AES-128-GCM for speed). Default off.
    #[serde(default)]
    pub prefer_aes256: bool,
    /// Grant read-caching leases (SMB2.1+). Default on. Clients cache reads
    /// under a lease; a conflicting write breaks it (lease-break notification)
    /// so they re-read fresh. Validated against cifs.ko and Windows (no stale
    /// reads, breaks honored). Set false to disable. Write/handle caching are
    /// not yet granted (#27).
    #[serde(default = "default_true")]
    pub oplocks: bool,
    #[serde(rename = "share")]
    pub shares: Vec<ShareCfg>,
    #[serde(rename = "user", default)]
    pub users: Vec<UserCfg>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserCfg {
    pub name: String,
    /// Plaintext password (the NT hash is derived at load)…
    pub password: Option<String>,
    /// …or a precomputed NT hash as 32 hex chars.
    pub nt_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareCfg {
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub read_only: bool,
}

fn default_listen() -> String {
    "0.0.0.0:445".into()
}

fn default_server_name() -> String {
    "ROCKETSMBD".into()
}

fn default_log_level() -> u8 {
    1
}

fn default_true() -> bool {
    true
}

impl Config {
    pub fn load(path: &str) -> Result<Config, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {path}: {e}"))?;
        let cfg: Config = toml::from_str(&raw).map_err(|e| format!("config parse error: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        self.listen_addr()?;
        if self.shares.is_empty() {
            return Err("config must define at least one [[share]]".into());
        }
        let mut seen: Vec<String> = Vec::new();
        for s in &self.shares {
            let lower = s.name.to_lowercase();
            if s.name.is_empty() || s.name.contains(['\\', '/']) {
                return Err(format!("invalid share name {:?}", s.name));
            }
            if seen.contains(&lower) {
                return Err(format!("duplicate share name {:?}", s.name));
            }
            seen.push(lower);
            if !s.path.is_dir() {
                return Err(format!("share {:?}: path {:?} is not a directory", s.name, s.path));
            }
            if s.name.eq_ignore_ascii_case("IPC$") {
                return Err("share name IPC$ is reserved".into());
            }
        }
        let mut seen_users: Vec<String> = Vec::new();
        for u in &self.users {
            let lower = u.name.to_lowercase();
            if u.name.is_empty() || seen_users.contains(&lower) {
                return Err(format!("invalid or duplicate user {:?}", u.name));
            }
            seen_users.push(lower);
            match (&u.password, &u.nt_hash) {
                (Some(_), None) => {}
                (None, Some(h)) if h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {}
                _ => {
                    return Err(format!(
                        "user {:?}: set exactly one of password / nt_hash (32 hex chars)",
                        u.name
                    ))
                }
            }
        }
        Ok(())
    }

    /// Resolved (lowercased-name → NT hash) map. NT hashes only feed the NTLM
    /// auth path; in a build without the `ntlm` feature (#30) this is always
    /// empty (the user DB is inert — no auth mechanism consumes it yet).
    #[cfg(feature = "ntlm")]
    pub fn user_db(&self) -> std::collections::HashMap<String, [u8; 16]> {
        self.users
            .iter()
            .map(|u| {
                let hash = match (&u.password, &u.nt_hash) {
                    (Some(p), _) => crate::crypto::nt_hash(p),
                    (_, Some(h)) => {
                        let mut out = [0u8; 16];
                        for (i, b) in out.iter_mut().enumerate() {
                            *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
                        }
                        out
                    }
                    _ => unreachable!("validated"),
                };
                (u.name.to_lowercase(), hash)
            })
            .collect()
    }

    /// Without the `ntlm` feature there is no NTLM verifier to consume NT
    /// hashes, so the resolved user DB is empty.
    #[cfg(not(feature = "ntlm"))]
    pub fn user_db(&self) -> std::collections::HashMap<String, [u8; 16]> {
        std::collections::HashMap::new()
    }

    pub fn guest_allowed(&self) -> bool {
        self.allow_guest.unwrap_or(self.users.is_empty())
    }

    pub fn listen_addr(&self) -> Result<SocketAddr, String> {
        self.listen
            .parse()
            .map_err(|e| format!("invalid listen address {:?}: {e}", self.listen))
    }
}

/// Resolved runtime context shared by all workers.
pub struct Srv {
    pub cfg: Config,
    pub guid: [u8; 16],
    /// Advertised MaxReadSize — bounded by the achievable pipe capacity so a
    /// zero-copy READ always fits in the connection's pipe.
    pub max_read: u32,
    pub start_ft: u64,
    /// lowercased user name → NT hash
    pub users: std::collections::HashMap<String, [u8; 16]>,
    pub allow_guest: bool,
    /// Network interfaces reported for SMB3 multichannel.
    pub interfaces: Vec<crate::net::Iface>,
    /// Cross-connection session table (multichannel).
    pub sessions: crate::session::Registry,
    /// Per-worker wakeable mailboxes for cross-worker lease/oplock break
    /// delivery (indexed by worker id). See `crate::lease`.
    pub mailboxes: Vec<crate::lease::Mailbox>,
    /// File-keyed lease registry, shared across all workers.
    pub leases: crate::lease::LeaseTable,
}

pub fn urandom(buf: &mut [u8]) {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    f.read_exact(buf).expect("read /dev/urandom");
}
