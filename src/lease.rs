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
    /// The client's 16-byte lease key being broken.
    pub lease_key: [u8; 16],
    /// New lease state to break down to (e.g. `LEASE_READ_CACHING` or 0/none).
    pub new_state: u32,
    /// Session id, for building the async break-notification header.
    pub session_id: u64,
}

/// A granted lease on a file, plus where its holder connection lives so a
/// break raised on any worker can be routed back to it.
#[derive(Debug, Clone)]
pub struct LeaseGrant {
    pub lease_key: [u8; 16],
    pub state: u32, // currently-granted caching bits (read-caching only today)
    pub session_id: u64,
    pub wid: usize,
    pub conn_idx: usize,
    pub conn_gen: u16,
}

/// File-keyed lease registry, shared across all workers (lives in `Srv`).
/// Keyed by `(share_idx, inode)`. Read-caching leases may be held by several
/// clients at once; a conflicting write breaks them all to none.
#[derive(Default)]
pub struct LeaseTable {
    map: Mutex<HashMap<(u32, u64), Vec<LeaseGrant>>>,
}

impl LeaseTable {
    /// Grant (or refresh) a read-caching lease for `g.lease_key` on a file.
    /// Coexists with other holders' read leases.
    pub fn grant_read(&self, key: (u32, u64), g: LeaseGrant) {
        let mut m = self.map.lock().unwrap();
        let v = m.entry(key).or_default();
        if let Some(existing) = v.iter_mut().find(|e| e.lease_key == g.lease_key) {
            *existing = g;
        } else {
            v.push(g);
        }
    }

    /// A conflicting access (write, or a second opener) arrived from the
    /// connection identified by `(wid, idx, gen)`. Break every *other* holder
    /// to none: remove them and return the break messages to deliver.
    pub fn break_conflicts(
        &self,
        key: (u32, u64),
        wid: usize,
        idx: usize,
        gen: u16,
    ) -> Vec<BreakMsg> {
        let mut m = self.map.lock().unwrap();
        let Some(v) = m.get_mut(&key) else {
            return Vec::new();
        };
        let mut breaks = Vec::new();
        v.retain(|g| {
            let same_conn = g.wid == wid && g.conn_idx == idx && g.conn_gen == gen;
            if same_conn {
                true // the actor keeps its own lease
            } else {
                breaks.push(BreakMsg {
                    wid: g.wid,
                    conn_idx: g.conn_idx,
                    conn_gen: g.conn_gen,
                    lease_key: g.lease_key,
                    new_state: 0, // break read-caching down to none
                    session_id: g.session_id,
                });
                false // drop the broken holder
            }
        });
        if v.is_empty() {
            m.remove(&key);
        }
        breaks
    }

    /// Release one holder's lease (on CLOSE).
    pub fn release(&self, key: (u32, u64), lease_key: [u8; 16]) {
        let mut m = self.map.lock().unwrap();
        if let Some(v) = m.get_mut(&key) {
            v.retain(|g| g.lease_key != lease_key);
            if v.is_empty() {
                m.remove(&key);
            }
        }
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
            new_state: 0,
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
