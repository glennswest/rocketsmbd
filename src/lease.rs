//! Cross-worker lease/oplock break delivery.
//!
//! Workers are independent threads behind `SO_REUSEPORT`, so two opens of the
//! same file can be owned by different workers. A write (or conflicting open)
//! arriving on one worker may need to break a lease held by a connection on
//! another worker — but a `Conn` is owned by its worker's thread and is not
//! shared. The shared `Srv` is reachable from every worker, so it holds a
//! per-worker [`Mailbox`]: any worker enqueues a [`BreakMsg`] for the owning
//! worker and wakes it via an eventfd registered in that worker's ring; the
//! owning worker drains the queue in its reactor loop and pushes the break
//! onto the target connection's deferred queue (the same path CHANGE_NOTIFY
//! uses for async server→client frames).
//!
//! See `docs/OPLOCKS.md` for the full design.

use std::collections::HashMap;
use std::os::fd::RawFd;
use std::sync::Mutex;

/// A pending lease/oplock break to deliver to a connection owned by a
/// (possibly different) worker.
#[derive(Debug, Clone)]
pub struct BreakMsg {
    /// Owning worker id — selects the mailbox to post to.
    pub wid: usize,
    /// Target connection slot in the owning worker's `conns` vec.
    pub conn_idx: usize,
    /// Generation guard — the break is dropped if the slot was recycled.
    pub conn_gen: u16,
    /// The client's 16-byte lease key (identifies which lease breaks).
    pub lease_key: [u8; 16],
    /// Lease state before and after the break (we break read-caching → none).
    pub cur_state: u32,
    pub new_state: u32,
    /// Lease epoch to advertise in the break (v2 leases; 0 for v1).
    pub epoch: u16,
    /// Session id, for building the break-notification header.
    pub session_id: u64,
}

/// A granted lease on a file, plus where its holder connection lives so a
/// break raised on any worker can be routed back to it.
#[derive(Debug, Clone)]
pub struct LeaseGrant {
    pub lease_key: [u8; 16],
    pub state: u32, // currently-granted caching bits (read-caching only today)
    pub epoch: u16,
    pub session_id: u64,
    pub wid: usize,
    pub conn_idx: usize,
    pub conn_gen: u16,
}

/// File-keyed lease registry, shared across all workers (lives in `Srv`).
/// Keyed by `(share_idx, inode)`. Read-caching leases held by distinct lease
/// keys (clients) coexist; a conflicting write breaks the *other* keys to none.
#[derive(Default)]
pub struct LeaseTable {
    map: Mutex<HashMap<(u32, u64), Vec<LeaseGrant>>>,
}

impl LeaseTable {
    /// Grant (or refresh) a lease for `g.lease_key` on a file. One lease per
    /// (file, lease key): a re-open with the same key replaces the prior grant.
    pub fn grant(&self, key: (u32, u64), g: LeaseGrant) {
        let mut m = self.map.lock().unwrap();
        let v = m.entry(key).or_default();
        if let Some(e) = v.iter_mut().find(|e| e.lease_key == g.lease_key) {
            *e = g;
        } else {
            v.push(g);
        }
    }

    /// A conflicting access from a holder with lease key `writer_key`
    /// (`None` = an un-leased writer). Break every lease with a *different* key
    /// to none, remove them, and return the break messages. A read-caching →
    /// none break carries no dirty data and needs no ack, so it's fire-and-forget.
    pub fn break_conflicts(&self, key: (u32, u64), writer_key: Option<[u8; 16]>) -> Vec<BreakMsg> {
        let mut m = self.map.lock().unwrap();
        let Some(v) = m.get_mut(&key) else {
            return Vec::new();
        };
        let mut breaks = Vec::new();
        v.retain(|g| {
            if writer_key == Some(g.lease_key) {
                true // the writer's own lease is not broken
            } else {
                breaks.push(BreakMsg {
                    wid: g.wid,
                    conn_idx: g.conn_idx,
                    conn_gen: g.conn_gen,
                    lease_key: g.lease_key,
                    cur_state: g.state,
                    new_state: 0,
                    epoch: g.epoch.wrapping_add(1),
                    session_id: g.session_id,
                });
                false
            }
        });
        if v.is_empty() {
            m.remove(&key);
        }
        breaks
    }

    /// Release one lease (on CLOSE).
    pub fn release(&self, key: (u32, u64), lease_key: [u8; 16]) {
        let mut m = self.map.lock().unwrap();
        if let Some(v) = m.get_mut(&key) {
            v.retain(|g| g.lease_key != lease_key);
            if v.is_empty() {
                m.remove(&key);
            }
        }
    }

    /// Release every lease held by a connection (on teardown / disconnect),
    /// so a connection that drops without a clean CLOSE doesn't leak grants.
    pub fn release_conn(&self, wid: usize, idx: usize, gen: u16) {
        let mut m = self.map.lock().unwrap();
        m.retain(|_, v| {
            v.retain(|g| !(g.wid == wid && g.conn_idx == idx && g.conn_gen == gen));
            !v.is_empty()
        });
    }
}

/// Per-worker wakeable break mailbox. `Sync` (eventfd + `Mutex`), so it lives
/// in the shared `Srv` and any thread can `post` to any worker.
pub struct Mailbox {
    efd: RawFd,
    queue: Mutex<Vec<BreakMsg>>,
}

impl Mailbox {
    /// Create a mailbox with its own eventfd (semaphore-free counter).
    pub fn new() -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        let efd = {
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            fd
        };
        #[cfg(not(target_os = "linux"))]
        let efd = -1; // server runs only on Linux; this keeps the host build compiling
        Ok(Mailbox { efd, queue: Mutex::new(Vec::new()) })
    }

    /// The eventfd to register in the owning worker's ring (`POLL`/`Read`).
    pub fn event_fd(&self) -> RawFd {
        self.efd
    }

    /// Enqueue a break for the owning worker and wake it via the eventfd.
    /// Safe to call from any thread.
    #[allow(dead_code)] // used by the grant/break increment
    pub fn post(&self, msg: BreakMsg) {
        self.queue.lock().unwrap().push(msg);
        if self.efd >= 0 {
            let one: u64 = 1;
            unsafe {
                libc::write(self.efd, &one as *const u64 as *const libc::c_void, 8);
            }
        }
    }

    /// Drain all queued breaks (called by the owning worker on wake).
    pub fn drain(&self) -> Vec<BreakMsg> {
        std::mem::take(&mut *self.queue.lock().unwrap())
    }
}

impl Drop for Mailbox {
    fn drop(&mut self) {
        if self.efd >= 0 {
            unsafe { libc::close(self.efd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg() -> BreakMsg {
        BreakMsg {
            wid: 0,
            conn_idx: 3,
            conn_gen: 7,
            lease_key: [0x5A; 16],
            cur_state: 1,
            new_state: 0,
            epoch: 1,
            session_id: 0xDEAD_BEEF,
        }
    }

    #[test]
    fn post_then_drain_roundtrips() {
        let mb = Mailbox::new().expect("mailbox");
        assert!(mb.drain().is_empty());
        mb.post(msg());
        mb.post(msg());
        let got = mb.drain();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].conn_idx, 3);
        assert_eq!(got[0].session_id, 0xDEAD_BEEF);
        // Drained queue is empty again.
        assert!(mb.drain().is_empty());
    }

    fn g(lk: u8, wid: usize, idx: usize, gen: u16) -> LeaseGrant {
        LeaseGrant {
            lease_key: [lk; 16],
            state: 1,
            epoch: 0,
            session_id: 9,
            wid,
            conn_idx: idx,
            conn_gen: gen,
        }
    }

    #[test]
    fn grant_break_release() {
        let t = LeaseTable::default();
        let key = (0u32, 42u64);
        t.grant(key, g(0xAA, 0, 2, 5));
        t.grant(key, g(0xBB, 1, 3, 6));
        // A write from the holder of key 0xAA breaks only the other key (0xBB).
        let breaks = t.break_conflicts(key, Some([0xAA; 16]));
        assert_eq!(breaks.len(), 1);
        assert_eq!(breaks[0].lease_key, [0xBB; 16]);
        assert_eq!(breaks[0].wid, 1);
        assert_eq!(breaks[0].new_state, 0);
        // The writer's own lease remains; release it → table empties.
        t.release(key, [0xAA; 16]);
        assert!(t.break_conflicts(key, None).is_empty());
    }

    #[test]
    fn unleased_writer_breaks_all() {
        let t = LeaseTable::default();
        let key = (0u32, 7u64);
        t.grant(key, g(0xAA, 0, 1, 1));
        t.grant(key, g(0xBB, 0, 2, 1));
        // A writer with no lease key breaks every holder.
        assert_eq!(t.break_conflicts(key, None).len(), 2);
    }

    #[test]
    fn release_conn_drops_all_grants_for_a_connection() {
        let t = LeaseTable::default();
        t.grant((0, 10), g(0xAA, 0, 2, 5));
        t.grant((0, 11), g(0xAA, 0, 2, 5));
        t.grant((0, 11), g(0xCC, 1, 4, 9));
        // Connection (0,2,5) drops: its two grants go, the other stays.
        t.release_conn(0, 2, 5);
        assert!(t.break_conflicts((0, 10), None).is_empty());
        let b = t.break_conflicts((0, 11), None);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].lease_key, [0xCC; 16]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_signals_eventfd() {
        let mb = Mailbox::new().expect("mailbox");
        mb.post(msg());
        mb.post(msg());
        // EFD_NONBLOCK read returns the accumulated counter (2) and clears it.
        let mut v: u64 = 0;
        let n = unsafe { libc::read(mb.event_fd(), &mut v as *mut u64 as *mut libc::c_void, 8) };
        assert_eq!(n, 8);
        assert_eq!(v, 2);
    }
}
