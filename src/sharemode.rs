//! CREATE share modes (MS-FSA 2.1.5.1.2.1), shared across all workers.
//!
//! Every open that has data access (read, write, append, execute or delete)
//! is recorded under the file's `(st_dev, st_ino)` with its granted access and
//! the ShareAccess it allows others. A new open is refused with
//! STATUS_SHARING_VIOLATION when it wants access an existing open does not
//! share, or an existing open has access the new one does not share. Opens
//! with attribute-only access neither conflict nor are recorded (as Windows'
//! IoCheckShareAccess). The record is dropped with the handle ([`Reg`] is held
//! by `OpenFile`), so CLOSE, LOGOFF, TREE_DISCONNECT and connection teardown
//! all release it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_EXECUTE: u32 = 0x0000_0020;
pub const DELETE: u32 = 0x0001_0000;

pub const FILE_SHARE_READ: u32 = 0x1;
pub const FILE_SHARE_WRITE: u32 = 0x2;
pub const FILE_SHARE_DELETE: u32 = 0x4;

/// Access bits that take part in sharing checks.
const DATA_ACCESS: u32 = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_EXECUTE | DELETE;

/// File identity: `(st_dev, st_ino)`.
pub type Key = (u64, u64);

struct Entry {
    id: u64,
    access: u32,
    share: u32,
}

/// One-sided test: does an open holding `access` collide with an open that
/// allows only `share`?
fn denied_by(access: u32, share: u32) -> bool {
    (access & (FILE_READ_DATA | FILE_EXECUTE) != 0 && share & FILE_SHARE_READ == 0)
        || (access & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0 && share & FILE_SHARE_WRITE == 0)
        || (access & DELETE != 0 && share & FILE_SHARE_DELETE == 0)
}

fn conflicts(e: &Entry, access: u32, share: u32) -> bool {
    denied_by(access, e.share) || denied_by(e.access, share)
}

#[derive(Default)]
pub struct Table {
    map: Mutex<HashMap<Key, Vec<Entry>>>,
    next_id: AtomicU64,
}

/// A recorded open; dropping it removes the record.
pub struct Reg {
    table: Arc<Table>,
    key: Key,
    id: u64,
}

impl Drop for Reg {
    fn drop(&mut self) {
        let mut map = self.table.map.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(v) = map.get_mut(&self.key) {
            v.retain(|e| e.id != self.id);
            if v.is_empty() {
                map.remove(&self.key);
            }
        }
    }
}

impl Table {
    /// Would an open of `key` with `access`/`share` be granted? (No record.)
    pub fn check(&self, key: Key, access: u32, share: u32) -> bool {
        let access = access & DATA_ACCESS;
        if access == 0 {
            return true;
        }
        let map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        map.get(&key).is_none_or(|v| !v.iter().any(|e| conflicts(e, access, share)))
    }

    /// Check and record atomically. `Err(())` = sharing violation;
    /// `Ok(None)` = attribute-only open, nothing to record.
    #[allow(clippy::result_unit_err)]
    pub fn register(table: &Arc<Table>, key: Key, access: u32, share: u32) -> Result<Option<Reg>, ()> {
        let access = access & DATA_ACCESS;
        if access == 0 {
            return Ok(None);
        }
        let mut map = table.map.lock().unwrap_or_else(|p| p.into_inner());
        let v = map.entry(key).or_default();
        if v.iter().any(|e| conflicts(e, access, share)) {
            if v.is_empty() {
                map.remove(&key);
            }
            return Err(());
        }
        let id = table.next_id.fetch_add(1, Ordering::Relaxed);
        v.push(Entry { id, access, share: share & (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) });
        Ok(Some(Reg { table: Arc::clone(table), key, id }))
    }

    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.map.lock().unwrap().values().map(Vec::len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    #[test]
    fn share_none_excludes_everyone_until_dropped() {
        let t = Arc::new(Table::default());
        let k = (1, 2);
        let a = Table::register(&t, k, FILE_READ_DATA | FILE_WRITE_DATA, 0).unwrap();
        assert!(a.is_some());
        assert!(Table::register(&t, k, FILE_READ_DATA, ALL).is_err());
        assert!(!t.check(k, FILE_WRITE_DATA, ALL));
        // Attribute-only opens never conflict.
        assert!(Table::register(&t, k, 0x80, ALL).unwrap().is_none());
        // Another file is unaffected.
        assert!(Table::register(&t, (1, 3), FILE_READ_DATA, 0).unwrap().is_some());
        drop(a);
        assert!(Table::register(&t, k, FILE_READ_DATA, ALL).unwrap().is_some());
    }

    #[test]
    fn both_directions_are_checked() {
        let t = Arc::new(Table::default());
        let k = (1, 2);
        // Reader that shares read only.
        let _r = Table::register(&t, k, FILE_READ_DATA, FILE_SHARE_READ).unwrap();
        // A second reader sharing read+write is fine.
        let _r2 = Table::register(&t, k, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE).unwrap();
        // A writer is refused (the first reader does not share write).
        assert!(Table::register(&t, k, FILE_WRITE_DATA, ALL).is_err());
        // A reader that refuses to share read collides with the existing readers.
        assert!(Table::register(&t, k, FILE_READ_DATA, FILE_SHARE_WRITE).is_err());
        // DELETE needs FILE_SHARE_DELETE from every holder.
        assert!(Table::register(&t, k, DELETE, ALL).is_err());
        assert_eq!(t.count(), 2);
    }
}
