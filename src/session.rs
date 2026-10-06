//! Cross-connection session registry for SMB3 multichannel.
//!
//! Sessions and their open-file handles are shared across all worker
//! connections (channels) so a single client can stripe one share over many
//! TCP connections, one per core. Each session is behind its own `Mutex`, so
//! different sessions never contend; within a session the lock is held only
//! briefly (handle/tree lookup, fd dup) — the slow path (splice I/O) runs
//! lock-free in the reactor after the lock is dropped.
//!
//! Per-channel signing state stays connection-local (in `ProtoConn`), so the
//! signature verify/sign hot path needs no registry lock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::smb2::Tree;
use crate::vfs::HandleTable;

/// Shared, lock-protected state of one SMB session, reachable from every
/// channel (connection) bound to it.
pub struct SessionInner {
    /// Original exported session key (from the first authentication). All
    /// channels derive their signing keys from this, regardless of the
    /// per-channel KEY_EXCH randomness in a binding auth.
    pub session_key: [u8; 16],
    pub established: bool,
    pub guest: bool,
    pub signing_required: bool,
    pub user: String,
    /// `user` is a Kerberos principal (vs. a local NTLM user).
    pub kerberos: bool,
    /// Verified PAC of a Kerberos (AD) session: user + group SIDs (#40).
    pub pac: Option<crate::pac::LogonInfo>,
    pub trees: HashMap<u32, Tree>,
    pub next_tree_id: u32,
    pub handles: HandleTable,
    /// Number of channels (connections) currently bound to this session.
    pub channels: u32,
}

impl SessionInner {
    fn new() -> Self {
        Self {
            session_key: [0; 16],
            established: false,
            guest: false,
            signing_required: false,
            user: String::new(),
            kerberos: false,
            pac: None,
            trees: HashMap::new(),
            next_tree_id: 0,
            handles: HandleTable::default(),
            channels: 0,
        }
    }
}

pub type SessionRef = Arc<Mutex<SessionInner>>;

/// Global session table shared by all workers via `Srv`.
#[derive(Default)]
pub struct Registry {
    sessions: Mutex<HashMap<u64, SessionRef>>,
}

impl Registry {
    /// Allocate a fresh session and insert an empty (un-established) entry.
    /// Ids are random, so one client can't guess another's session id to
    /// target it (#39 R10); never 0 or all-ones (protocol sentinels).
    pub fn create(&self) -> (u64, SessionRef) {
        let sref = Arc::new(Mutex::new(SessionInner::new()));
        let mut map = self.sessions.lock().unwrap();
        let id = loop {
            let mut b = [0u8; 8];
            crate::config::urandom(&mut b);
            let id = u64::from_le_bytes(b);
            if id != 0 && id != u64::MAX && !map.contains_key(&id) {
                break id;
            }
        };
        map.insert(id, Arc::clone(&sref));
        (id, sref)
    }

    /// Number of sessions (established or mid-setup).
    pub fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, id: u64) -> Option<SessionRef> {
        self.sessions.lock().unwrap().get(&id).cloned()
    }

    pub fn remove(&self, id: u64) -> Option<SessionRef> {
        self.sessions.lock().unwrap().remove(&id)
    }
}
