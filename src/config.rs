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
    #[serde(rename = "share")]
    pub shares: Vec<ShareCfg>,
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
        }
        Ok(())
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
}

pub fn urandom(buf: &mut [u8]) {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    f.read_exact(buf).expect("read /dev/urandom");
}
