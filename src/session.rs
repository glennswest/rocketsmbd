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
use std::sync::atomic::{AtomicU64, Ordering};
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
            trees: HashMap::new(),
            next_tree_id: 0,
            handles: HandleTable::default(),
            channels: 0,
        }
    }
}

pub type SessionRef = Arc<Mutex<SessionInner>>;

/// Global session table shared by all workers via `Srv`.
pub struct Registry {
    sessions: Mutex<HashMap<u64, SessionRef>>,
    next_id: AtomicU64,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            // Start high and odd so ids look like real SMB session handles
            // and never collide with 0 / all-ones sentinels.
            next_id: AtomicU64::new(0x1000_0000_0001),
        }
    }
}

impl Registry {
    /// Allocate a fresh session and insert an empty (un-established) entry.
    pub fn create(&self) -> (u64, SessionRef) {
        let id = self.next_id.fetch_add(2, Ordering::Relaxed);
        let sref = Arc::new(Mutex::new(SessionInner::new()));
        self.sessions.lock().unwrap().insert(id, Arc::clone(&sref));
        (id, sref)
    }

    pub fn get(&self, id: u64) -> Option<SessionRef> {
        self.sessions.lock().unwrap().get(&id).cloned()
    }

    pub fn remove(&self, id: u64) -> Option<SessionRef> {
        self.sessions.lock().unwrap().remove(&id)
    }
}
