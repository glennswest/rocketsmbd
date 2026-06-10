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
    /// Restrict multichannel interface advertisement to these IPs (e.g. a
    /// dedicated storage NIC). Empty = advertise all non-loopback interfaces.
    #[serde(default)]
    pub advertise_only: Vec<String>,
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

    /// Resolved (lowercased-name → NT hash) map.
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
}

pub fn urandom(buf: &mut [u8]) {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    f.read_exact(buf).expect("read /dev/urandom");
}
