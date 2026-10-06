//! SMB2 command handlers.

use std::path::Path;

use super::*;
use crate::config::{ShareCfg, Srv};
#[cfg(feature = "ntlm")]
use crate::ntlm;
use crate::status;
use crate::vfs::{self, DirState, OpenFile};
use crate::wire::{from_utf16le, utf16le, Put, Rdr};

// DesiredAccess bits
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const WRITE_BITS: u32 = FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL;
/// Access a read-only tree refuses at CREATE: writing data, plus DELETE,
/// FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, WRITE_DAC and WRITE_OWNER.
const READ_ONLY_DENIED: u32 = WRITE_BITS | 0x0001_0000 | 0x10 | 0x100 | 0x0004_0000 | 0x0008_0000;

// CreateDisposition
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

// CreateOptions
const FILE_DIRECTORY_FILE: u32 = 0x0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0040;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;

// CreateAction
const CREATE_ACTION_OPENED: u32 = 1;
const CREATE_ACTION_CREATED: u32 = 2;
const CREATE_ACTION_OVERWRITTEN: u32 = 3;

const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
const FSCTL_QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_01FC;

const SUPPORTED_DIALECTS: [u16; 5] = [0x0311, 0x0302, 0x0300, 0x0210, 0x0202];
const CAP_LEASING: u32 = 0x2;
const CAP_LARGE_MTU: u32 = 0x4;
const CAP_MULTI_CHANNEL: u32 = 0x8;
const SECURITY_MODE_SIGNING_ENABLED: u16 = 0x1;
const SECURITY_MODE_SIGNING_REQUIRED: u16 = 0x2;
#[cfg(feature = "ntlm")]
const SESSION_FLAG_IS_GUEST: u16 = 0x1;
#[cfg(any(feature = "ntlm", feature = "kerberos"))]
const SESSION_FLAG_ENCRYPT_DATA: u16 = 0x4;
const MAXIMAL_ACCESS_ALL: u32 = 0x001F_01FF;
/// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE: a read-only tree's MaximalAccess.
const MAXIMAL_ACCESS_READ: u32 = 0x0012_00A9;
/// Max credits a connection may hold (window accounting).
const CREDIT_WINDOW: i64 = 512;

pub fn dispatch(
    srv: &Srv,
    pc: &mut ProtoConn,
    h: &ReqHdr,
    msg: &[u8],
    chain: &mut Chain,
    tx: &mut Vec<u8>,
) -> Option<ZcReadPlan> {
    let body = &msg[64..];

    // Each MessageId (CreditCharge of them, from MessageId up) is used once
    // per connection: a replayed signed or sealed request — whose signature
    // or AEAD tag still verifies — is a protocol violation, and MS-SMB2
    // disconnects (#39 R9). CANCEL reuses the id of the request it cancels.
    if h.command != CMD_CANCEL && !consume_msg_ids(pc, h.msg_id, h.credit_charge) {
        crate::logw!("message id {} reused or out of window: disconnecting", h.msg_id);
        pc.close = true;
        return None;
    }

    // Resolve effective session/tree for related compound operations.
    if h.flags & FLAG_RELATED != 0 {
        chain.related = true;
        if h.session_id != 0 && h.session_id != u64::MAX {
            chain.session_id = h.session_id;
        }
        if h.tree_id != 0 && h.tree_id != u32::MAX {
            chain.tree_id = h.tree_id;
        }
    } else {
        chain.related = false;
        chain.session_id = h.session_id;
        chain.tree_id = h.tree_id;
    }

    // Credit accounting: consume the charge, grant within the window.
    pc.credits_out = (pc.credits_out - h.credit_charge.max(1) as i64).max(0);
    let avail = (CREDIT_WINDOW - pc.credits_out).max(1);
    let grant = (h.credits as i64).clamp(1, avail) as u16;
    pc.credits_out += grant as i64;
    let mut h = h.clone();
    h.credits = grant;
    let h = &h;

    // A sealed compound may only carry its own session's requests: the
    // transform's key authenticated that session, not any other (#39 R18).
    if let Some(tsid) = chain.transform_sid {
        if chain.session_id != tsid {
            crate::logw!("sealed frame for session {tsid:x} carries session {:x}: disconnecting", chain.session_id);
            pc.close = true;
            return None;
        }
    }

    // Verify signatures on signed requests; reject unsigned requests on
    // signing-required channels. Signing state is connection-local. A request
    // that arrived sealed is not separately signed: its AEAD tag (verified
    // during decryption) is the integrity check. A channel that is encrypting
    // — `encrypt = true`, or since the client's first sealed request — takes
    // nothing in plaintext but NEGOTIATE/SESSION_SETUP (MS-SMB2 3.3.5.2.9);
    // before, it skipped signature checks on plaintext too (#39 R1).
    if let Some(ch) = pc.channels.get(&chain.session_id) {
        let sealed = chain.transform_sid.is_some();
        if ch.encrypt && !sealed && !matches!(h.command, CMD_NEGOTIATE | CMD_SESSION_SETUP) {
            err_resp(tx, h, status::ACCESS_DENIED, chain);
            return None;
        }
        if !sealed {
            if let Some(sc) = &ch.sign {
                if h.flags & FLAG_SIGNED != 0 {
                    if !verify_signature(msg, sc) {
                        err_resp(tx, h, status::ACCESS_DENIED, chain);
                        return None;
                    }
                } else if ch.signing_required
                    && !matches!(h.command, CMD_NEGOTIATE | CMD_SESSION_SETUP | CMD_CANCEL)
                {
                    err_resp(tx, h, status::ACCESS_DENIED, chain);
                    return None;
                }
            }
        }
    }

    match h.command {
        CMD_NEGOTIATE => negotiate(srv, pc, h, msg, chain, tx),
        CMD_ECHO => simple_resp(tx, h, chain),
        CMD_CANCEL => cancel(pc, h),
        CMD_SESSION_SETUP => session_setup(srv, pc, h, msg, chain, tx),
        CMD_LOGOFF => logoff(srv, pc, h, chain, tx),
        _ => {
            // Established session required. The channel proves this
            // connection is bound; the shared session holds trees + handles.
            let established =
                pc.channels.get(&chain.session_id).map(|c| c.established).unwrap_or(false);
            if !established {
                err_resp(tx, h, status::USER_SESSION_DELETED, chain);
                return None;
            }
            let Some(sref) = srv.sessions.get(chain.session_id) else {
                err_resp(tx, h, status::USER_SESSION_DELETED, chain);
                return None;
            };
            let mut sess = sref.lock().unwrap();

            if h.command == CMD_TREE_CONNECT {
                tree_connect(srv, &mut sess, h, msg, chain, tx);
                return None;
            }
            let Some(tree) = sess.trees.get(&chain.tree_id).copied() else {
                err_resp(tx, h, status::NETWORK_NAME_DELETED, chain);
                return None;
            };
            if h.command == CMD_TREE_DISCONNECT {
                sess.trees.remove(&chain.tree_id);
                // The tree's opens close with it.
                let ids = sess.handles.ids_in_tree(chain.tree_id);
                for fid in ids {
                    if let Some(of) = sess.handles.remove(fid, chain.tree_id) {
                        finish_close(srv, &of);
                    }
                    notify_cleanup(pc, fid);
                }
                simple_resp(tx, h, chain);
                return None;
            }
            if tree.ipc {
                drop(sess);
                match h.command {
                    CMD_IOCTL => ioctl(srv, pc, h, msg, chain, tx),
                    _ => err_resp(tx, h, status::ACCESS_DENIED, chain),
                }
                return None;
            }
            let share = &srv.cfg.shares[tree.share_idx as usize];
            // This connection's reactor location, for routing oplock breaks.
            let cid = (pc.wid, pc.conn_idx, pc.conn_gen);
            // Only grant oplocks on non-encrypted sessions: a break notification
            // on an encrypted session would need to be sealed too (a follow-up).
            let allow_oplock = !pc.channels.get(&h.session_id).map(|c| c.encrypt).unwrap_or(false);
            match h.command {
                CMD_CREATE => {
                    create(srv, &mut sess, h, msg, chain, tx, share, tree, cid, allow_oplock)
                }
                CMD_CLOSE => close(srv, pc, &mut sess, h, body, chain, tx),
                CMD_FLUSH => flush(&mut sess, h, body, chain, tx),
                CMD_READ => {
                    // Read briefly re-locks the session itself (dup the fd,
                    // then do I/O lock-free) so concurrent reads across
                    // channels don't serialize on the session lock.
                    drop(sess);
                    return read(pc, &sref, h, body, chain, tx);
                }
                CMD_WRITE => write(srv, &mut sess, h, msg, chain, tx, tree),
                CMD_QUERY_DIRECTORY => query_directory(&mut sess, h, msg, chain, tx),
                CMD_QUERY_INFO => query_info(srv, &mut sess, h, body, chain, tx),
                CMD_SET_INFO => set_info(srv, &mut sess, h, msg, chain, tx, share, tree.read_only),
                CMD_IOCTL => {
                    drop(sess);
                    ioctl(srv, pc, h, msg, chain, tx);
                }
                CMD_LOCK => lock(&mut sess, h, body, chain, tx),
                CMD_CHANGE_NOTIFY => change_notify(pc, &mut sess, h, body, chain, tx),
                _ => err_resp(tx, h, status::NOT_SUPPORTED, chain),
            }
        }
    }
    None
}

/// Unfinished session setups one connection may hold at once.
const MAX_PENDING_SETUPS: usize = 4;

/// How far past the lowest unused MessageId a request may reach. Far above any
/// real client's spread (at most CREDIT_WINDOW credits outstanding, ≤ 64 per
/// request); bounds what a client can make the server remember.
const MSG_WINDOW: u64 = 1 << 16;
/// If this many ids sit above a gap the client never filled, give up on the
/// gap: everything below the lowest remembered id counts as used.
const MSG_SEEN_MAX: usize = 4096;

/// Record MessageIds `id .. id + max(charge, 1)` as used. False if any was
/// already used, is below the window, or lies beyond it.
pub fn consume_msg_ids(pc: &mut ProtoConn, id: u64, charge: u16) -> bool {
    let n = charge.max(1) as u64;
    let Some(end) = id.checked_add(n) else {
        return false;
    };
    if id < pc.msg_low || end > pc.msg_low.saturating_add(MSG_WINDOW) {
        return false;
    }
    if pc.msg_seen.range(id..end).next().is_some() {
        return false;
    }
    pc.msg_seen.extend(id..end);
    loop {
        while pc.msg_seen.remove(&pc.msg_low) {
            pc.msg_low += 1;
        }
        if pc.msg_seen.len() <= MSG_SEEN_MAX {
            break;
        }
        pc.msg_low = *pc.msg_seen.iter().next().unwrap();
    }
    true
}

/// LOGOFF: drop this connection's channel; tear down the shared session when
/// its last channel goes away.
fn logoff(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, chain: &Chain, tx: &mut Vec<u8>) {
    // Only an established channel can log off: a pending one (a binding still
    // mid-handshake) proves nothing, and would let anyone tear down another
    // client's session by its id (#39 R10).
    if !pc.channels.get(&chain.session_id).is_some_and(|c| c.established) {
        err_resp(tx, h, status::USER_SESSION_DELETED, chain);
        return;
    }
    pc.channels.remove(&chain.session_id);
    if let Some(sref) = srv.sessions.get(chain.session_id) {
        let drop_session = {
            let mut s = sref.lock().unwrap();
            s.channels = s.channels.saturating_sub(1);
            s.channels == 0
        };
        if drop_session {
            end_session(srv, chain.session_id);
        }
    }
    simple_resp(tx, h, chain);
}

/// Remove a session from the registry and close its opens (lease release,
/// delete-on-close; dropping each handle closes its fd and OFD locks).
pub fn end_session(srv: &Srv, sid: u64) {
    if let Some(sref) = srv.sessions.remove(sid) {
        let opens = {
            let mut s = sref.lock().unwrap();
            s.trees.clear();
            s.handles.take_all()
        };
        for of in opens {
            finish_close(srv, &of);
        }
    }
}

/// A connection is gone: release what it held in the shared registry. Each
/// established channel drops its session's channel count, and the session
/// ends with its last channel (as if logged off). A session this connection
/// created but never finished authenticating ends too. Before, only LOGOFF
/// removed sessions, so dropped connections leaked sessions, open fds and
/// byte-range locks until restart (#39 R5).
pub fn teardown_conn(srv: &Srv, pc: &mut ProtoConn) {
    for (sid, ch) in pc.channels.drain() {
        let Some(sref) = srv.sessions.get(sid) else {
            continue;
        };
        let end = {
            let mut s = sref.lock().unwrap();
            if ch.established {
                s.channels = s.channels.saturating_sub(1);
                s.channels == 0
            } else {
                // A pending channel: either this connection's own unfinished
                // setup (ends), or a binding to someone's live session (stays).
                !s.established
            }
        };
        if end {
            end_session(srv, sid);
        }
    }
}

/// CANCEL: no response of its own; a matching pended operation completes
/// with STATUS_CANCELLED via the notify queues.
fn cancel(pc: &mut ProtoConn, h: &ReqHdr) {
    let Some(aid) = h.async_id else {
        return; // sync cancel of an already-completed op: nothing pended
    };
    if let Some(pos) = pc.notify_active.iter().position(|&(_, a)| a == aid) {
        let (_, async_id) = pc.notify_active.remove(pos);
        pc.notify_done.push(crate::smb2::NotifyDone { async_id, status: status::CANCELLED });
    }
}

fn simple_resp(tx: &mut Vec<u8>, h: &ReqHdr, chain: &Chain) {
    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(4);
    tx.p16(0);
}

/// Parse a 16-byte FileId; all-ones means "use the previous handle in the
/// compound chain".
fn parse_fid(r: &mut Rdr, chain: &Chain) -> Option<u64> {
    let persistent = r.u64()?;
    let volatile = r.u64()?;
    if persistent == u64::MAX && volatile == u64::MAX {
        chain.last_fid
    } else {
        Some(volatile)
    }
}

fn put_fid(tx: &mut Vec<u8>, fid: u64) {
    tx.p64(fid);
    tx.p64(fid);
}

// ---------------------------------------------------------------- NEGOTIATE

fn negotiate(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &Chain, tx: &mut Vec<u8>) {
    let body = &msg[64..];
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 36 {
            return None;
        }
        let count = r.u16()? as usize;
        let secmode = r.u16()?;
        r.skip(2)?; // reserved
        let caps = r.u32()?;
        let guid: [u8; 16] = r.take(16)?.try_into().ok()?;
        let ctx_off = r.u32()? as usize;
        let ctx_count = r.u16()? as usize;
        r.skip(2)?;
        let mut dialects = Vec::with_capacity(count.min(16));
        for _ in 0..count.min(16) {
            dialects.push(r.u16()?);
        }
        Some((dialects, ctx_off, ctx_count, crate::smb2::ClientNeg { secmode, caps, guid }))
    })();
    // One NEGOTIATE per connection: a second would reset dialect, cipher and
    // the preauth hash under live sessions. MS-SMB2 disconnects (#39 R17).
    if pc.negotiated {
        crate::logw!("second NEGOTIATE on a connection: disconnecting");
        pc.close = true;
        return;
    }
    let Some((dialects, ctx_off, ctx_count, client_neg)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(&chosen) = SUPPORTED_DIALECTS.iter().find(|d| dialects.contains(d)) else {
        err_resp(tx, h, status::NOT_SUPPORTED, chain);
        return;
    };

    // For 3.1.1, require the preauth integrity context (SHA-512) and pick a
    // cipher from the client's encryption-capabilities (AES-128-GCM only).
    let mut cipher: u16 = 0;
    if chosen == 0x0311 {
        let mut have_preauth = false;
        let mut off = ctx_off;
        for _ in 0..ctx_count.min(16) {
            let Some((t, data_len)) = (|| {
                let mut r = Rdr::new(msg.get(off..)?);
                let t = r.u16()?;
                let l = r.u16()? as usize;
                r.skip(4)?;
                Some((t, l))
            })() else {
                break;
            };
            match t {
                1 => {
                    let ok = (|| {
                        let mut r = Rdr::new(msg.get(off + 8..off + 8 + data_len)?);
                        let n = r.u16()? as usize;
                        let _salt = r.u16()?;
                        for _ in 0..n.min(8) {
                            if r.u16()? == 1 {
                                return Some(true);
                            }
                        }
                        Some(false)
                    })();
                    have_preauth = ok == Some(true);
                }
                2 => {
                    // SMB2_ENCRYPTION_CAPABILITIES: CipherCount + CipherIds.
                    // Pick the first cipher in the client's (preference-ordered)
                    // list that we support: AES-128/256-GCM and AES-128/256-CCM.
                    use crate::crypto::{
                        CIPHER_AES128_CCM, CIPHER_AES128_GCM, CIPHER_AES256_CCM, CIPHER_AES256_GCM,
                    };
                    let _ = (|| {
                        let mut r = Rdr::new(msg.get(off + 8..off + 8 + data_len)?);
                        let n = r.u16()? as usize;
                        let mut offered = Vec::new();
                        for _ in 0..n.min(8) {
                            let c = r.u16()?;
                            if matches!(
                                c,
                                CIPHER_AES128_GCM
                                    | CIPHER_AES256_GCM
                                    | CIPHER_AES128_CCM
                                    | CIPHER_AES256_CCM
                            ) {
                                offered.push(c);
                            }
                        }
                        cipher = if srv.cfg.prefer_aes256 {
                            // server preference: strongest GCM, then CCM
                            [CIPHER_AES256_GCM, CIPHER_AES256_CCM, CIPHER_AES128_GCM, CIPHER_AES128_CCM]
                                .into_iter()
                                .find(|c| offered.contains(c))
                                .unwrap_or(0)
                        } else {
                            // honor the client's preference order
                            offered.first().copied().unwrap_or(0)
                        };
                        Some(())
                    })();
                }
                _ => {}
            }
            off += 8 + data_len;
            off = (off + 7) & !7;
        }
        if !have_preauth {
            err_resp(tx, h, status::INVALID_PARAMETER, chain);
            return;
        }
    }

    pc.dialect = chosen;
    pc.cipher = cipher;
    pc.negotiated = true;
    pc.client_neg = Some(client_neg);
    if cipher != 0 {
        crate::logd!("negotiated dialect {chosen:#x} cipher {cipher:#x}");
    }
    let start = begin_resp(tx, h, status::SUCCESS, false, 0, 0);
    negotiate_body(srv, pc, chosen, cipher, start, tx);
}

pub fn negotiate_resp_smb1_wildcard(srv: &Srv, pc: &mut ProtoConn, tx: &mut Vec<u8>) {
    let h = ReqHdr {
        credit_charge: 0,
        command: CMD_NEGOTIATE,
        credits: 1,
        flags: 0,
        next: 0,
        msg_id: 0,
        tree_id: 0,
        session_id: 0,
        async_id: None,
    };
    let start = begin_resp(tx, &h, status::SUCCESS, false, 0, 0);
    negotiate_body(srv, pc, 0x02FF, 0, start, tx);
}

fn negotiate_body(
    srv: &Srv,
    pc: &ProtoConn,
    dialect: u16,
    cipher: u16,
    resp_start: usize,
    tx: &mut Vec<u8>,
) {
    let mut secmode = SECURITY_MODE_SIGNING_ENABLED;
    if srv.cfg.require_signing {
        secmode |= SECURITY_MODE_SIGNING_REQUIRED;
    }
    // SPNEGO NegTokenInit2 hint advertises the NTLM mechtype. Without the
    // `ntlm` feature there is no mechanism to advertise yet (Kerberos is #31),
    // so the security buffer is empty.
    #[cfg(feature = "ntlm")]
    let hint = crate::ntlm::spnego_hint();
    #[cfg(not(feature = "ntlm"))]
    let hint: Vec<u8> = Vec::new();
    let body = resp_start + 64;
    tx.p16(65);
    tx.p16(secmode);
    tx.p16(dialect);
    tx.p16(0); // NegotiateContextCount, patched below for 3.1.1
    tx.pbytes(&srv.guid);
    // MULTI_CHANNEL is an SMB 3.x capability; it lets a client open several
    // connections to one share and stripe I/O across them (and across our
    // workers/cores). Advertised only when multichannel is enabled.
    let mut caps = CAP_LARGE_MTU;
    if dialect >= 0x0300 && srv.cfg.multichannel {
        caps |= CAP_MULTI_CHANNEL;
    }
    // Advertise leasing (SMB 2.1+) so clients request leases (RqLs) instead of
    // legacy oplocks; our caching/break path is lease-based. Gated on `oplocks`.
    if dialect >= 0x0210 && srv.cfg.oplocks {
        caps |= CAP_LEASING;
    }
    pc.server_caps = caps;
    tx.p32(caps);
    tx.p32(MAX_TRANSACT);
    tx.p32(pc.max_read);
    tx.p32(MAX_WRITE);
    tx.p64(vfs::filetime_now());
    tx.p64(srv.start_ft);
    tx.p16(128); // SecurityBufferOffset (header 64 + fixed body 64)
    tx.p16(hint.len() as u16);
    tx.p32(0); // NegotiateContextOffset, patched below
    debug_assert_eq!(tx.len() - body, 64);
    tx.pbytes(&hint);

    if dialect == 0x0311 {
        tx.pad8(resp_start);
        let ctx_off = tx.len() - resp_start;
        let mut count = 1u16;
        // PREAUTH_INTEGRITY_CAPABILITIES: SHA-512 + 32-byte salt.
        let mut salt = [0u8; 32];
        crate::config::urandom(&mut salt);
        tx.p16(1);
        tx.p16(38);
        tx.p32(0);
        tx.p16(1);
        tx.p16(32);
        tx.p16(1); // SHA-512
        tx.pbytes(&salt);
        if cipher != 0 {
            tx.pad8(resp_start);
            // SMB2_ENCRYPTION_CAPABILITIES: select AES-128-GCM.
            count += 1;
            tx.p16(2);
            tx.p16(4);
            tx.p32(0);
            tx.p16(1); // CipherCount
            tx.p16(cipher);
        }
        tx.patch32(body + 60, ctx_off as u32);
        let cnt_off = body + 6;
        tx[cnt_off..cnt_off + 2].copy_from_slice(&count.to_le_bytes());
    }
}

// ------------------------------------------------------------ SESSION_SETUP

#[cfg(any(feature = "ntlm", feature = "kerberos"))]
fn ss_resp(tx: &mut Vec<u8>, h: &ReqHdr, st: u32, related: bool, sid: u64, flags: u16, blob: &[u8]) {
    begin_resp(tx, h, st, related, 0, sid);
    tx.p16(9);
    tx.p16(flags);
    tx.p16(72); // SecurityBufferOffset
    tx.p16(blob.len() as u16);
    tx.pbytes(blob);
}

#[cfg(feature = "ntlm")]
const SESSION_FLAG_BINDING: u8 = 0x01;

/// SESSION_SETUP dispatcher: classify the SPNEGO/raw security blob and route it
/// to the mechanism that owns it, subject to the `auth` policy (#36) and the
/// built features (#30 `ntlm`, #31 `kerberos`). Kerberos is preferred when both
/// are offered. A token for a mechanism that is disabled by policy or not built
/// is rejected with `STATUS_NOT_SUPPORTED` (fail loudly).
// In a build with neither `ntlm` nor `kerberos`, every arm rejects without
// touching `pc`/`msg`, so they read as unused — that is the intended no-auth
// build (#30), not a bug.
#[cfg_attr(
    not(any(feature = "ntlm", feature = "kerberos")),
    allow(unused_variables)
)]
fn session_setup(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    // Extract the security buffer to classify it (the mechanism handlers
    // re-read what they need from `msg`).
    let blob = (|| {
        let mut r = Rdr::new(&msg[64..]);
        if r.u16()? != 25 {
            return None;
        }
        r.skip(1 + 1 + 4 + 4)?; // flags, secmode, caps, channel
        let off = r.u16()? as usize;
        let len = r.u16()? as usize;
        if len == 0 {
            return Some(&[][..]);
        }
        msg.get(off..off + len)
    })();
    let Some(blob) = blob else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };

    use crate::spnego::Mech;
    let mech = crate::spnego::classify(blob).mech;
    let allow_krb = srv.cfg.auth.allows_kerberos();
    let allow_ntlm = srv.cfg.auth.allows_ntlm();

    match mech {
        Mech::Krb5 if allow_krb => {
            #[cfg(feature = "kerberos")]
            kerberos_session_setup(srv, pc, h, msg, chain, tx);
            #[cfg(not(feature = "kerberos"))]
            {
                crate::logi!("session_setup: Kerberos token, but server built without the `kerberos` feature");
                err_resp(tx, h, status::NOT_SUPPORTED, chain);
            }
        }
        // NTLMSSP, or an unrecognized/empty blob (raw anonymous → guest, which
        // the NTLM handler owns). Routed to NTLM when policy + build allow.
        Mech::Ntlmssp | Mech::Unknown if allow_ntlm => {
            #[cfg(feature = "ntlm")]
            ntlm_session_setup(srv, pc, h, msg, chain, tx);
            #[cfg(not(feature = "ntlm"))]
            {
                crate::logi!("session_setup: NTLM token, but server built without the `ntlm` feature");
                err_resp(tx, h, status::NOT_SUPPORTED, chain);
            }
        }
        _ => {
            crate::logi!("session_setup: no enabled auth mechanism for the offered token (auth={:?})", srv.cfg.auth);
            err_resp(tx, h, status::NOT_SUPPORTED, chain);
        }
    }
}

#[cfg(feature = "ntlm")]
fn ntlm_session_setup(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 25 {
            return None;
        }
        let flags = r.u8()?;
        let secmode = r.u8()?;
        r.skip(4 + 4)?; // caps, channel
        let off = r.u16()? as usize;
        let len = r.u16()? as usize;
        let _prev = r.u64()?;
        let blob = if len == 0 { &[][..] } else { msg.get(off..off + len)? };
        Some((flags, secmode, blob))
    })();
    let Some((ss_flags, client_secmode, blob)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let spnego = ntlm::is_spnego(blob);
    let binding = ss_flags & SESSION_FLAG_BINDING != 0;
    let signing_required =
        srv.cfg.require_signing || client_secmode as u16 & SECURITY_MODE_SIGNING_REQUIRED != 0;

    match ntlm::classify(blob) {
        ntlm::Token::Negotiate => {
            // Interim: assign/locate the session id, stash a challenge in this
            // connection's channel state, respond with the NTLM CHALLENGE.
            let sid = if binding {
                // Bind to an existing session: only with multichannel on, on
                // SMB 3.x, and to an established non-guest session — a guest
                // session has no key to prove, so anyone could join it (#39 R10).
                if !srv.cfg.multichannel || pc.dialect < 0x0300 {
                    err_resp(tx, h, status::REQUEST_NOT_ACCEPTED, chain);
                    return;
                }
                let bindable = srv.sessions.get(h.session_id).is_some_and(|s| {
                    let s = s.lock().unwrap();
                    s.established && !s.guest
                });
                if h.session_id == 0 || !bindable {
                    err_resp(tx, h, status::USER_SESSION_DELETED, chain);
                    return;
                }
                if pc.channels.get(&h.session_id).is_some_and(|c| c.established) {
                    // Already bound here: a binding leg can't reset it.
                    err_resp(tx, h, status::REQUEST_NOT_ACCEPTED, chain);
                    return;
                }
                h.session_id
            } else {
                // Each NTLM NEGOTIATE creates a registry entry before any
                // credential is checked; bound how many one connection can
                // hold half-open (#39 R5).
                let pending = pc.channels.values().filter(|c| !c.established).count();
                if pending >= MAX_PENDING_SETUPS {
                    err_resp(tx, h, status::INSUFFICIENT_RESOURCES, chain);
                    return;
                }
                let (id, _sref) = srv.sessions.create();
                id
            };
            chain.session_id = sid;
            let mut chal = [0u8; 8];
            crate::config::urandom(&mut chal);
            let mut ch = crate::smb2::ChannelState {
                pending: Some(crate::smb2::PendingAuth { challenge: chal, spnego, binding }),
                preauth: pc.preauth_neg,
                ..Default::default()
            };
            if pc.dialect == 0x0311 {
                ch.preauth = crate::crypto::sha512(&[&ch.preauth, msg]);
            }
            pc.channels.insert(sid, ch);

            let mut token = ntlm::challenge(&srv.cfg.server_name, chal);
            if spnego {
                token = ntlm::spnego_wrap_challenge(&token);
            }
            ss_resp(tx, h, status::MORE_PROCESSING_REQUIRED, chain.related, sid, 0, &token);
        }
        ntlm::Token::Authenticate => {
            let sid = h.session_id;
            chain.session_id = sid;
            let Some(ch) = pc.channels.get_mut(&sid) else {
                err_resp(tx, h, status::USER_SESSION_DELETED, chain);
                return;
            };
            if pc.dialect == 0x0311 {
                ch.preauth = crate::crypto::sha512(&[&ch.preauth, msg]);
            }
            let Some(pending) = ch.pending.take() else {
                // Re-auth on an already-established channel: acknowledge.
                let flags = if ch.sign.is_none() { SESSION_FLAG_IS_GUEST } else { 0 };
                ss_resp(tx, h, status::SUCCESS, chain.related, sid, flags, &[]);
                return;
            };
            let ch_preauth = ch.preauth;
            let wrapped = pending.spnego || spnego;
            let done = if wrapped { ntlm::spnego_accept_completed() } else { Vec::new() };
            let dialect = pc.dialect;
            let cipher = pc.cipher;

            let Some(sref) = srv.sessions.get(sid) else {
                err_resp(tx, h, status::USER_SESSION_DELETED, chain);
                return;
            };
            let auth = ntlm::parse_authenticate(blob);

            if pending.binding {
                // Channel binding: prove the same identity, then derive this
                // channel's signing key from the session's original key.
                let mut s = sref.lock().unwrap();
                let ok = if !s.established || s.guest {
                    false
                } else {
                    match &auth {
                        Some(a) if !a.is_anonymous() => {
                            a.user.eq_ignore_ascii_case(&s.user)
                                && srv
                                    .users
                                    .get(&a.user.to_lowercase())
                                    .map(|nt| ntlm::verify_ntlmv2(nt, a, &pending.challenge).is_some())
                                    .unwrap_or(false)
                        }
                        _ => false,
                    }
                };
                if !ok {
                    crate::logw!(
                        "session {:x}: channel bind rejected (established={} guest={} sess_user={:?} bind_user={:?} anon={})",
                        sid,
                        s.established,
                        s.guest,
                        s.user,
                        auth.as_ref().map(|a| a.user.clone()).unwrap_or_default(),
                        auth.as_ref().map(|a| a.is_anonymous()).unwrap_or(true),
                    );
                    drop(s);
                    pc.channels.remove(&sid);
                    err_resp(tx, h, status::ACCESS_DENIED, chain);
                    return;
                }
                if srv.cfg.encrypt && !(cipher != 0 && dialect == 0x0311) {
                    crate::logw!("session {:x}: channel bind denied — encryption is required but no cipher was negotiated", sid);
                    drop(s);
                    pc.channels.remove(&sid);
                    err_resp(tx, h, status::ACCESS_DENIED, chain);
                    return;
                }
                let key = s.session_key;
                let guest = s.guest;
                s.channels += 1;
                drop(s);
                let chm = pc.channels.get_mut(&sid).unwrap();
                chm.established = true;
                chm.signing_required = signing_required && !guest;
                chm.sign = if guest {
                    None
                } else {
                    Some(crate::smb2::derive_sign_ctx(dialect, &key, &ch_preauth))
                };
                // This channel's own encryption keys (per-connection preauth).
                let mut flags = if guest { SESSION_FLAG_IS_GUEST } else { 0 };
                if !guest && cipher != 0 && dialect == 0x0311 {
                    let (c2s, s2c) = crate::crypto::smb311_encryption_keys(cipher, &key, &ch_preauth);
                    chm.enc = Some(crate::smb2::EncCtx { cipher, c2s, s2c, nonce_ctr: 0 });
                    if srv.cfg.encrypt {
                        chm.encrypt = true;
                        flags |= SESSION_FLAG_ENCRYPT_DATA;
                    }
                }
                crate::logi!("session {:x}: channel bound (now striping)", sid);
                ss_resp(tx, h, status::SUCCESS, chain.related, sid, flags, &done);
                return;
            }

            // First authentication on a fresh session.
            enum Verdict {
                User([u8; 16], String),
                Guest,
                Reject,
            }
            let verdict = match &auth {
                Some(a) if !a.is_anonymous() => match srv.users.get(&a.user.to_lowercase()) {
                    Some(nt) => match ntlm::verify_ntlmv2(nt, a, &pending.challenge) {
                        Some(key) => Verdict::User(key, a.user.clone()),
                        None => Verdict::Reject,
                    },
                    None if srv.allow_guest => Verdict::Guest,
                    None => Verdict::Reject,
                },
                _ if srv.allow_guest => Verdict::Guest,
                _ => Verdict::Reject,
            };
            // `encrypt = true` means every session is sealed. Without an
            // SMB 3.1.1 cipher (2.x/3.0.x, or no encryption context) this one
            // can't be: refuse it rather than run it in cleartext (#39 R8).
            let verdict = match verdict {
                Verdict::User(..) if srv.cfg.encrypt && !(cipher != 0 && dialect == 0x0311) => {
                    crate::logw!("session {:x}: denied — encryption is required but no cipher was negotiated", sid);
                    pc.channels.remove(&sid);
                    srv.sessions.remove(sid);
                    err_resp(tx, h, status::ACCESS_DENIED, chain);
                    return;
                }
                v => v,
            };
            match verdict {
                Verdict::User(key, user) => {
                    {
                        let mut s = sref.lock().unwrap();
                        s.session_key = key;
                        s.established = true;
                        s.guest = false;
                        s.signing_required = signing_required;
                        s.user = user.clone();
                        s.channels = 1;
                    }
                    let chm = pc.channels.get_mut(&sid).unwrap();
                    chm.established = true;
                    chm.signing_required = signing_required;
                    chm.sign = Some(crate::smb2::derive_sign_ctx(dialect, &key, &ch_preauth));
                    // SMB3 encryption: derive keys when a cipher is negotiated.
                    // If the server requires encryption, set ENCRYPT_DATA so the
                    // client seals all subsequent traffic; otherwise stay ready
                    // to honor client-initiated encryption (e.g. cifs `seal`).
                    let mut ss_flags = 0u16;
                    if cipher != 0 && dialect == 0x0311 {
                        let (c2s, s2c) = crate::crypto::smb311_encryption_keys(cipher, &key, &ch_preauth);
                        chm.enc = Some(crate::smb2::EncCtx { cipher, c2s, s2c, nonce_ctr: 0 });
                        if srv.cfg.encrypt {
                            chm.encrypt = true;
                            ss_flags |= SESSION_FLAG_ENCRYPT_DATA;
                        }
                    }
                    crate::logi!(
                        "session {:x}: user {:?} authenticated (signing {}, encryption {})",
                        sid,
                        user,
                        if signing_required { "required" } else { "optional" },
                        if chm.enc.is_some() { "ready" } else { "off" }
                    );
                    ss_resp(tx, h, status::SUCCESS, chain.related, sid, ss_flags, &done);
                }
                Verdict::Guest if srv.cfg.encrypt => {
                    // Guest/anonymous sessions carry no key and cannot be
                    // encrypted; refuse rather than let the client seal traffic
                    // the server can't decrypt (which would hang it, #26).
                    crate::logw!(
                        "session {:x}: guest denied — encryption is required but guest sessions cannot be encrypted",
                        sid
                    );
                    pc.channels.remove(&sid);
                    srv.sessions.remove(sid);
                    err_resp(tx, h, status::ACCESS_DENIED, chain);
                }
                Verdict::Guest => {
                    {
                        let mut s = sref.lock().unwrap();
                        s.established = true;
                        s.guest = true;
                        s.channels = 1;
                    }
                    let chm = pc.channels.get_mut(&sid).unwrap();
                    chm.established = true;
                    ss_resp(tx, h, status::SUCCESS, chain.related, sid, SESSION_FLAG_IS_GUEST, &done);
                }
                Verdict::Reject => {
                    let user = auth.map(|a| a.user).unwrap_or_default();
                    crate::logw!("session {:x}: logon failure for user {:?}", sid, user);
                    pc.channels.remove(&sid);
                    srv.sessions.remove(sid);
                    err_resp(tx, h, status::LOGON_FAILURE, chain);
                }
            }
        }
        ntlm::Token::Other => {
            // No NTLMSSP token at all (e.g. pure anonymous): guest if allowed.
            // Guest/anonymous sessions carry no key, so they cannot be
            // encrypted — if encryption is required, deny rather than let the
            // client seal traffic we can't decrypt (#26).
            if srv.allow_guest && srv.cfg.encrypt {
                crate::logw!(
                    "anonymous session denied: encryption is required but guest sessions cannot be encrypted"
                );
                err_resp(tx, h, status::ACCESS_DENIED, chain);
            } else if srv.allow_guest {
                let (sid, sref) = srv.sessions.create();
                {
                    let mut s = sref.lock().unwrap();
                    s.established = true;
                    s.guest = true;
                    s.channels = 1;
                }
                pc.channels.insert(
                    sid,
                    crate::smb2::ChannelState {
                        established: true,
                        preauth: pc.preauth_neg,
                        ..Default::default()
                    },
                );
                chain.session_id = sid;
                ss_resp(tx, h, status::SUCCESS, chain.related, sid, SESSION_FLAG_IS_GUEST, &[]);
            } else {
                err_resp(tx, h, status::LOGON_FAILURE, chain);
            }
        }
    }
}

/// Kerberos SESSION_SETUP (#31). Unwraps the GSS AP-REQ from SPNEGO, runs it
/// through the per-connection GSS acceptor, and on success establishes the
/// session using the Kerberos sub-session key for SMB signing/encryption.
///
/// Single-leg only for now: a Kerberos AP-REQ from cifs.ko / Windows completes
/// in one `gss_accept_sec_context`. A multi-leg exchange (rare) is logged and
/// rejected pending per-channel GSS-context persistence (#35).
#[cfg(feature = "kerberos")]
fn kerberos_session_setup(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    // Re-extract the security blob and its flags.
    let parsed = (|| {
        let mut r = Rdr::new(&msg[64..]);
        if r.u16()? != 25 {
            return None;
        }
        let _flags = r.u8()?;
        let secmode = r.u8()?;
        r.skip(4 + 4)?; // caps, channel
        let off = r.u16()? as usize;
        let len = r.u16()? as usize;
        let _prev = r.u64()?;
        let blob = if len == 0 { &[][..] } else { msg.get(off..off + len)? };
        Some((secmode, blob))
    })();
    let Some((client_secmode, blob)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let incoming = crate::spnego::classify(blob);
    let wrapped = incoming.spnego;
    let signing_required =
        srv.cfg.require_signing || client_secmode as u16 & SECURITY_MODE_SIGNING_REQUIRED != 0;
    let dialect = pc.dialect;
    let cipher = pc.cipher;

    // Lazily acquire the acceptor credential for this connection.
    if pc.krb_acceptor.is_none() {
        let kcfg = srv.cfg.kerberos.as_ref();
        if kcfg.map(|k| !k.enabled).unwrap_or(false) {
            crate::logw!("kerberos: token received but [kerberos].enabled = false");
            err_resp(tx, h, status::NOT_SUPPORTED, chain);
            return;
        }
        let spn = kcfg
            .and_then(|k| k.spn.clone())
            .unwrap_or_else(|| format!("cifs/{}", srv.cfg.server_name));
        match crate::krb5::Acceptor::new(&spn) {
            Ok(a) => pc.krb_acceptor = Some(a),
            Err(e) => {
                crate::logw!("kerberos: acceptor init failed ({e})");
                err_resp(tx, h, status::LOGON_FAILURE, chain);
                return;
            }
        }
    }

    // Run one acceptor leg. Scope the GSS borrow so we can mutate `pc` after.
    let step = {
        let mut ctx = pc.krb_acceptor.as_ref().unwrap().begin();
        ctx.step(incoming.token)
    };
    use crate::krb5::Step;
    let est = match step {
        Step::Done(est) => est,
        Step::Continue(_) => {
            crate::logw!("kerberos: multi-leg exchange not yet supported (#35)");
            err_resp(tx, h, status::LOGON_FAILURE, chain);
            return;
        }
        Step::Failed(e) => {
            let st = crate::krb5::status_for_failure(&e);
            crate::logw!("kerberos: authentication failed ({e})");
            err_resp(tx, h, st, chain);
            return;
        }
    };

    // `encrypt = true` and no 3.1.1 cipher: the session can't be sealed (#39 R8).
    if srv.cfg.encrypt && !(pc.cipher != 0 && pc.dialect == 0x0311) {
        crate::logw!("kerberos: session for {} denied — encryption is required but no cipher was negotiated", est.client);
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }

    // SMB session key: first 16 bytes of the Kerberos sub-session key.
    let mut key = [0u8; 16];
    let n = est.session_key.len().min(16);
    key[..n].copy_from_slice(&est.session_key[..n]);

    // Fresh session; chain the 3.1.1 preauth over this single setup message.
    let (sid, sref) = srv.sessions.create();
    chain.session_id = sid;
    let ch_preauth = if dialect == 0x0311 {
        crate::crypto::sha512(&[&pc.preauth_neg, msg])
    } else {
        [0u8; 64]
    };

    {
        let mut s = sref.lock().unwrap();
        s.session_key = key;
        s.established = true;
        s.guest = false;
        s.signing_required = signing_required;
        s.user = est.client.clone();
        s.kerberos = true;
        s.pac = est.pac.clone();
        s.channels = 1;
    }
    let mut ch = crate::smb2::ChannelState {
        established: true,
        signing_required,
        sign: Some(crate::smb2::derive_sign_ctx(dialect, &key, &ch_preauth)),
        preauth: ch_preauth,
        ..Default::default()
    };
    let mut ss_flags = 0u16;
    if cipher != 0 && dialect == 0x0311 {
        let (c2s, s2c) = crate::crypto::smb311_encryption_keys(cipher, &key, &ch_preauth);
        ch.enc = Some(crate::smb2::EncCtx { cipher, c2s, s2c, nonce_ctr: 0 });
        if srv.cfg.encrypt {
            ch.encrypt = true;
            ss_flags |= SESSION_FLAG_ENCRYPT_DATA;
        }
    }
    pc.channels.insert(sid, ch);

    if let Some(p) = &est.pac {
        crate::logi!(
            "session {:x}: PAC {}\\{} sid {} groups [{}]",
            sid,
            p.domain,
            p.user,
            p.user_sid.as_ref().map(|s| s.to_string()).unwrap_or_default(),
            p.groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(", ")
        );
    }
    crate::logi!(
        "session {:x}: kerberos principal {:?} authenticated (signing {}, encryption {})",
        sid,
        est.client,
        if signing_required { "required" } else { "optional" },
        if cipher != 0 && dialect == 0x0311 { "ready" } else { "off" }
    );

    // Wrap the AP-REP (if any) in a SPNEGO accept-completed when the request
    // was SPNEGO-wrapped; otherwise return the raw GSS output token.
    let done = if wrapped {
        crate::spnego::neg_resp(crate::spnego::ACCEPT_COMPLETED, crate::spnego::Mech::Krb5, &est.out)
    } else {
        est.out.clone()
    };
    ss_resp(tx, h, status::SUCCESS, chain.related, sid, ss_flags, &done);
}

// ------------------------------------------------------------- TREE_CONNECT

fn tree_connect(srv: &Srv, sess: &mut SessionInner, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let path = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 9 {
            return None;
        }
        r.skip(2)?;
        let off = r.u16()? as usize;
        let len = r.u16()? as usize;
        msg.get(off..off + len).map(from_utf16le)
    })();
    let Some(path) = path else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    // "\\server\share" → "share"
    let share_name = path.rsplit('\\').next().unwrap_or("");
    let ipc = share_name.eq_ignore_ascii_case("IPC$");
    let share_idx = if ipc {
        u32::MAX
    } else {
        match srv.cfg.shares.iter().position(|s| s.name.eq_ignore_ascii_case(share_name)) {
            Some(i) => i as u32,
            None => {
                err_resp(tx, h, status::BAD_NETWORK_NAME, chain);
                return;
            }
        }
    };
    // Per-share authorization (#40): valid/invalid/read_only_users.
    let read_only = if ipc {
        false
    } else {
        let share = &srv.cfg.shares[share_idx as usize];
        let who = crate::authz::Who {
            guest: sess.guest,
            user: &sess.user,
            kerberos: sess.kerberos,
            pac: sess.pac.as_ref(),
        };
        match crate::authz::check(&srv.cfg, share, &who) {
            crate::authz::Access::Denied => {
                crate::logi!(
                    "session {:x}: tree connect to {:?} denied for {}",
                    chain.session_id,
                    share.name,
                    if sess.guest { "guest".to_string() } else { format!("{:?}", sess.user) }
                );
                err_resp(tx, h, status::ACCESS_DENIED, chain);
                return;
            }
            crate::authz::Access::ReadOnly => true,
            crate::authz::Access::ReadWrite => false,
        }
    };
    sess.next_tree_id += 1;
    let tree_id = sess.next_tree_id;
    sess.trees.insert(tree_id, crate::smb2::Tree { share_idx, ipc, read_only });
    chain.tree_id = tree_id;

    begin_resp(tx, h, status::SUCCESS, chain.related, tree_id, chain.session_id);
    tx.p16(16);
    tx.p8(if ipc { 2 } else { 1 }); // ShareType: pipe / disk
    tx.p8(0);
    tx.p32(0); // ShareFlags
    tx.p32(0); // Capabilities
    tx.p32(if ipc {
        0x001F_00A9
    } else if read_only {
        MAXIMAL_ACCESS_READ
    } else {
        MAXIMAL_ACCESS_ALL
    });
}

// ------------------------------------------------------------------- CREATE

/// A parsed lease request from the `RqLs` create context (v1 = 32-byte data,
/// v2 = 52-byte data, distinguished by `v2`/`parent`/`epoch`). Parsed now;
/// consumed by the grant path once cross-worker lease-break delivery lands.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct LeaseReq {
    key: [u8; 16],
    state: u32,
    v2: bool,
    parent: [u8; 16],
    epoch: u16,
}

struct CreateReq {
    desired: u32,
    disposition: u32,
    options: u32,
    name: String,
    /// RequestedOplockLevel byte (OPLOCK_NONE/LEVEL_II/EXCLUSIVE/BATCH, or
    /// OPLOCK_LEASE=0xFF when a lease is requested via the RqLs context).
    #[allow(dead_code)]
    oplock: u8,
    /// Parsed RqLs lease request, if present.
    #[allow(dead_code)]
    lease: Option<LeaseReq>,
}

fn parse_create(msg: &[u8]) -> Option<CreateReq> {
    let body = msg.get(64..)?;
    let mut r = Rdr::new(body);
    if r.u16()? != 57 {
        return None;
    }
    r.skip(1)?; // SecurityFlags
    let oplock = r.u8()?; // RequestedOplockLevel
    r.skip(4 + 8 + 8)?; // ImpersonationLevel, SmbCreateFlags, Reserved
    let desired = r.u32()?;
    let _attrs = r.u32()?;
    let _share_access = r.u32()?;
    let disposition = r.u32()?;
    let options = r.u32()?;
    let name_off = r.u16()? as usize;
    let name_len = r.u16()? as usize;
    let cc_off = r.u32()? as usize; // CreateContextsOffset (from header start)
    let cc_len = r.u32()? as usize; // CreateContextsLength
    let name = if name_len == 0 {
        String::new()
    } else {
        from_utf16le(msg.get(name_off..name_off + name_len)?)
    };
    let lease = if cc_len > 0 {
        msg.get(cc_off..cc_off.checked_add(cc_len)?)
            .and_then(parse_lease_ctx)
    } else {
        None
    };
    Some(CreateReq { desired, disposition, options, name, oplock, lease })
}

/// Walk the chained SMB2_CREATE_CONTEXT list and return the parsed `RqLs`
/// lease request if one is present.
fn parse_lease_ctx(mut buf: &[u8]) -> Option<LeaseReq> {
    loop {
        if buf.len() < 16 {
            return None;
        }
        let next = u32::from_le_bytes(buf[0..4].try_into().ok()?) as usize;
        let name_off = u16::from_le_bytes(buf[4..6].try_into().ok()?) as usize;
        let name_len = u16::from_le_bytes(buf[6..8].try_into().ok()?) as usize;
        let data_off = u16::from_le_bytes(buf[10..12].try_into().ok()?) as usize;
        let data_len = u32::from_le_bytes(buf[12..16].try_into().ok()?) as usize;
        if name_len == 4 {
            if let (Some(nm), Some(data)) = (
                buf.get(name_off..name_off + 4),
                buf.get(data_off..data_off.checked_add(data_len)?),
            ) {
                if nm == CTX_NAME_RQLS && data.len() >= 32 {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&data[0..16]);
                    let state = u32::from_le_bytes(data[16..20].try_into().ok()?);
                    let v2 = data.len() >= 52;
                    let mut parent = [0u8; 16];
                    let mut epoch = 0u16;
                    if v2 {
                        parent.copy_from_slice(&data[32..48]);
                        epoch = u16::from_le_bytes(data[48..50].try_into().ok()?);
                    }
                    return Some(LeaseReq { key, state, v2, parent, epoch });
                }
            }
        }
        if next == 0 || next >= buf.len() {
            return None;
        }
        buf = &buf[next..];
    }
}

#[allow(clippy::too_many_arguments)]
fn create(
    srv: &Srv,
    sess: &mut SessionInner,
    h: &ReqHdr,
    msg: &[u8],
    chain: &mut Chain,
    tx: &mut Vec<u8>,
    share: &ShareCfg,
    tree: crate::smb2::Tree,
    cid: (usize, usize, u16),
    allow_oplock: bool,
) {
    let share_idx = tree.share_idx;
    let Some(req) = parse_create(msg) else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let (path, rel) = match vfs::resolve(&share.path, &req.name) {
        Ok(v) => v,
        Err(st) => {
            err_resp(tx, h, st, chain);
            return;
        }
    };

    let wants_write = req.desired & WRITE_BITS != 0;
    let creates = matches!(
        req.disposition,
        FILE_SUPERSEDE | FILE_CREATE | FILE_OVERWRITE | FILE_OVERWRITE_IF
    );
    let delete_on_close = req.options & FILE_DELETE_ON_CLOSE != 0;
    if tree.read_only && (req.desired & READ_ONLY_DENIED != 0 || creates || delete_on_close) {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }

    let existing = vfs::stat_meta(&path).ok();
    let exists = existing.is_some();
    let existing_dir = existing.map(|m| m.is_dir).unwrap_or(false);
    // FILE_OPEN_IF creates a missing file (or directory): not on a read-only
    // tree (#39 R4).
    if tree.read_only && !exists && req.disposition == FILE_OPEN_IF {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }
    // The share root itself is never deleted (#39 R21).
    if delete_on_close && rel.is_empty() {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }

    if exists && req.disposition == FILE_CREATE {
        err_resp(tx, h, status::OBJECT_NAME_COLLISION, chain);
        return;
    }
    if !exists && matches!(req.disposition, FILE_OPEN | FILE_OVERWRITE) {
        err_resp(tx, h, status::OBJECT_NAME_NOT_FOUND, chain);
        return;
    }

    let dir_requested = req.options & FILE_DIRECTORY_FILE != 0;
    let treat_as_dir = existing_dir || (dir_requested && !exists);

    if existing_dir && req.options & FILE_NON_DIRECTORY_FILE != 0 {
        err_resp(tx, h, status::FILE_IS_A_DIRECTORY, chain);
        return;
    }
    if exists && !existing_dir && dir_requested {
        err_resp(tx, h, status::NOT_A_DIRECTORY, chain);
        return;
    }

    let mut action = CREATE_ACTION_OPENED;
    let (fd, is_dir, writable) = if treat_as_dir {
        if !exists {
            let c = match vfs::cpath(&path) {
                Ok(c) => c,
                Err(e) => {
                    err_resp(tx, h, status::from_errno(e), chain);
                    return;
                }
            };
            // SAFETY: c is a NUL-terminated CString alive for the call; the kernel copies
            // the path.
            if unsafe { libc::mkdir(c.as_ptr(), 0o755) } < 0 {
                err_resp(tx, h, status::from_errno(vfs::errno()), chain);
                return;
            }
            action = CREATE_ACTION_CREATED;
        }
        match vfs::open_raw(&path, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(fd) => (fd, true, false),
            Err(e) => {
                err_resp(tx, h, status::from_errno(e), chain);
                return;
            }
        }
    } else {
        let mut flags = match req.disposition {
            FILE_CREATE => libc::O_CREAT | libc::O_EXCL,
            FILE_OPEN_IF => libc::O_CREAT,
            FILE_OVERWRITE => libc::O_TRUNC,
            FILE_OVERWRITE_IF | FILE_SUPERSEDE => libc::O_CREAT | libc::O_TRUNC,
            _ => 0,
        };
        let try_rw =
            wants_write || (req.desired & MAXIMUM_ALLOWED != 0 && !tree.read_only) || creates;
        flags |= if try_rw { libc::O_RDWR } else { libc::O_RDONLY };
        match vfs::open_raw(&path, flags, 0o644) {
            Ok(fd) => {
                if !exists {
                    action = CREATE_ACTION_CREATED;
                } else if flags & libc::O_TRUNC != 0 {
                    action = CREATE_ACTION_OVERWRITTEN;
                }
                (fd, false, try_rw)
            }
            Err(e) if e == libc::EACCES && try_rw && !wants_write => {
                // MAXIMUM_ALLOWED fallback: retry read-only.
                match vfs::open_raw(&path, (flags & !libc::O_RDWR) | libc::O_RDONLY, 0) {
                    Ok(fd) => (fd, false, false),
                    Err(e) => {
                        err_resp(tx, h, status::from_errno(e), chain);
                        return;
                    }
                }
            }
            Err(e) => {
                err_resp(tx, h, status::from_errno(e), chain);
                return;
            }
        }
    };

    let meta = match vfs::fstat_meta(fd) {
        Ok(m) => m,
        Err(e) => {
            // SAFETY: fd was opened above and not yet stored in the handle table; this
            // error path is its only owner.
            unsafe { libc::close(fd) };
            err_resp(tx, h, status::from_errno(e), chain);
            return;
        }
    };
    // Prefetch hint for streamed file reads (helps cold-storage throughput).
    if !is_dir {
        vfs::advise_sequential(fd);
    }
    // An overwrite/supersede truncated an existing file: every other client's
    // cached data for it is now stale (#42).
    if action == CREATE_ACTION_OVERWRITTEN {
        break_leases(srv, (share_idx, meta.ino), req.lease.as_ref().map(|l| l.key));
    }
    let leaf = rel.rsplit('\\').next().unwrap_or("").to_string();
    let attrs = vfs::finalize_attrs(meta.attrs, &leaf);
    // Grant a read-caching lease when the client requests one (RqLs) on a file.
    // Read-caching is the safe subset: distinct lease keys coexist, there's no
    // dirty client data, and a conflicting write breaks it to none. On by
    // default; `oplocks = false` disables (Config::oplocks). The client's lease key is recorded on the
    // handle regardless (so a WRITE can exempt the client's own lease).
    let lease_req = req.lease.clone();
    let grant_lease = srv.cfg.oplocks
        && allow_oplock
        && !is_dir
        && lease_req.as_ref().is_some_and(|l| l.state & LEASE_READ_CACHING != 0);
    // Grant read-caching, plus handle-caching if the client asked for it — that
    // lets the client keep its lease (and cache) across CLOSE, avoiding re-opens.
    // Never write-caching (dirty client data needs break-with-ack — not yet).
    let granted_state = if grant_lease {
        LEASE_READ_CACHING | (lease_req.as_ref().unwrap().state & LEASE_HANDLE_CACHING)
    } else {
        0
    };
    let fid = sess.handles.insert(OpenFile {
        fd,
        path,
        rel,
        leaf,
        share_idx,
        tree_id: chain.tree_id,
        is_dir,
        writable,
        delete_on_close,
        dir: None,
        oplock_ino: if grant_lease { Some(meta.ino) } else { None },
        lease_key: lease_req.as_ref().map(|l| l.key),
        lease_granted: granted_state,
    });
    chain.last_fid = Some(fid);
    if grant_lease {
        let l = lease_req.as_ref().unwrap();
        srv.leases.grant(
            (share_idx, meta.ino),
            crate::lease::LeaseGrant {
                lease_key: l.key,
                state: granted_state,
                epoch: l.epoch,
                session_id: chain.session_id,
                wid: cid.0,
                conn_idx: cid.1,
                conn_gen: cid.2,
            },
        );
        crate::logd!("lease: granted {granted_state:#x} (share {share_idx}, ino {})", meta.ino);
    }

    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(89);
    tx.p8(if grant_lease { OPLOCK_LEASE } else { OPLOCK_NONE }); // OplockLevel
    tx.p8(0);
    tx.p32(action);
    tx.p64(meta.crtime);
    tx.p64(meta.atime);
    tx.p64(meta.mtime);
    tx.p64(meta.ctime);
    tx.p64(meta.alloc);
    tx.p64(meta.size);
    tx.p32(attrs);
    tx.p32(0);
    put_fid(tx, fid);
    if grant_lease {
        // Echo an RqLs response context with the granted lease state. The
        // context list begins at a fixed offset from the SMB2 header (64-byte
        // header + 88-byte fixed CREATE response = 152), 8-byte aligned.
        let l = lease_req.as_ref().unwrap();
        let data_len: u32 = if l.v2 { 52 } else { 32 };
        tx.p32(152); // CreateContextsOffset (from SMB2 header)
        tx.p32(24 + data_len); // CreateContextsLength (16 hdr + 4 name + 4 pad + data)
        tx.p32(0); // Next
        tx.p16(16); // NameOffset
        tx.p16(4); // NameLength
        tx.p16(0); // Reserved
        tx.p16(24); // DataOffset
        tx.p32(data_len); // DataLength
        tx.pbytes(CTX_NAME_RQLS); // "RqLs" at offset 16
        tx.zeros(4); // pad → data 8-aligned at offset 24
        tx.pbytes(&l.key); // LeaseKey
        tx.p32(granted_state); // LeaseState (granted: read, + handle if asked)
        tx.p32(0); // LeaseFlags
        tx.p64(0); // LeaseDuration
        if l.v2 {
            tx.pbytes(&l.parent); // ParentLeaseKey
            tx.p16(l.epoch); // Epoch
            tx.p16(0); // Reserved
        }
    } else {
        tx.p32(0); // CreateContextsOffset
        tx.p32(0); // CreateContextsLength
    }
}

// ------------------------------------------------------------ lease breaks

/// Break every lease on file `key` except the one held under `except` (the
/// acting handle's own lease key), and post each break to the worker that owns
/// the holder's connection. Called after any operation that changes what a
/// read- or handle-caching holder has cached: WRITE, truncate, overwriting
/// CREATE, rename and delete (#42). R/H → none needs no ack, so the caller
/// doesn't wait.
fn break_leases(srv: &Srv, key: (u32, u64), except: Option<[u8; 16]>) {
    for b in srv.leases.break_conflicts(key, except) {
        crate::logd!("lease: breaking {:#x} → none (share {}, ino {})", b.cur_state, key.0, key.1);
        if let Some(mb) = srv.mailboxes.get(b.wid) {
            mb.post(b);
        }
    }
}

// -------------------------------------------------------------------- CLOSE

fn close(srv: &Srv, pc: &mut ProtoConn, sess: &mut SessionInner, h: &ReqHdr, body: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 24 {
            return None;
        }
        let flags = r.u16()?;
        r.skip(4)?;
        Some((flags, parse_fid(&mut r, chain)?))
    })();
    let Some((flags, fid)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(of) = sess.handles.remove(fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    notify_cleanup(pc, fid);

    let post_attrib = flags & 0x1 != 0;
    let meta = if post_attrib { vfs::fstat_meta(of.fd).ok() } else { None };

    let st = finish_close(srv, &of);
    if st != status::SUCCESS {
        err_resp(tx, h, st, chain);
        return;
    }

    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(60);
    tx.p16(if post_attrib { 1 } else { 0 });
    tx.p32(0);
    if let Some(m) = meta {
        tx.p64(m.crtime);
        tx.p64(m.atime);
        tx.p64(m.mtime);
        tx.p64(m.ctime);
        tx.p64(m.alloc);
        tx.p64(m.size);
        tx.p32(vfs::finalize_attrs(m.attrs, &of.leaf));
    } else {
        tx.zeros(52);
    }
}

/// Complete any CHANGE_NOTIFY pended on handle `fid` (NOTIFY_CLEANUP).
fn notify_cleanup(pc: &mut ProtoConn, fid: u64) {
    let mut i = 0;
    while i < pc.notify_active.len() {
        if pc.notify_active[i].0 == fid {
            let (_, async_id) = pc.notify_active.remove(i);
            pc.notify_done
                .push(crate::smb2::NotifyDone { async_id, status: status::NOTIFY_CLEANUP });
        } else {
            i += 1;
        }
    }
}

/// The CLOSE side effects of a handle leaving the table, whether by CLOSE,
/// TREE_DISCONNECT, LOGOFF or the connection dropping: release its lease
/// (unless handle-caching keeps it alive past CLOSE — then it is broken later
/// or released by `release_conn`), and carry out delete-on-close. Dropping
/// `of` afterwards closes the fd (and with it any OFD byte-range locks).
pub fn finish_close(srv: &Srv, of: &OpenFile) -> u32 {
    if let (Some(ino), Some(lk)) = (of.oplock_ino, of.lease_key) {
        if of.lease_granted & LEASE_HANDLE_CACHING == 0 {
            srv.leases.release((of.share_idx, ino), lk);
        }
    }
    if !of.delete_on_close {
        return status::SUCCESS;
    }
    // The file goes away: break other holders' leases on it (#42).
    if !of.is_dir {
        if let Ok(m) = vfs::fstat_meta(of.fd) {
            break_leases(srv, (of.share_idx, m.ino), of.lease_key);
        }
    }
    let res = if of.is_dir { std::fs::remove_dir(&of.path) } else { std::fs::remove_file(&of.path) };
    match res {
        Ok(()) => status::SUCCESS,
        Err(e) => status::from_errno(e.raw_os_error().unwrap_or(libc::EIO)),
    }
}

fn flush(sess: &mut SessionInner, h: &ReqHdr, body: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 24 {
            return None;
        }
        r.skip(2 + 4)?;
        parse_fid(&mut r, chain)
    })();
    let Some(fid) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(of) = sess.handles.get(fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    match vfs::fsync(of.fd) {
        Ok(()) => simple_resp(tx, h, chain),
        Err(e) => err_resp(tx, h, status::from_errno(e), chain),
    }
}

// --------------------------------------------------------------------- READ

fn read(
    pc: &mut ProtoConn,
    sref: &crate::session::SessionRef,
    h: &ReqHdr,
    body: &[u8],
    chain: &mut Chain,
    tx: &mut Vec<u8>,
) -> Option<ZcReadPlan> {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 49 {
            return None;
        }
        r.skip(1 + 1)?; // padding, flags
        let length = r.u32()?;
        let offset = r.u64()?;
        let fid = parse_fid(&mut r, chain)?;
        let min_count = r.u32()?;
        Some((length, offset, fid, min_count))
    })();
    let Some((length, offset, fid, min_count)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return None;
    };
    let max_read = pc.max_read;
    // A signed or encrypted response covers the payload, which rules out
    // splicing — those channels always take the buffered path (the reactor
    // can't splice file pages into an encrypted/MAC'd frame). Per-channel.
    let must_sign = pc
        .channels
        .get(&chain.session_id)
        .map(|c| {
            c.encrypt
                || (c.sign.is_some()
                    && (c.signing_required || h.flags & crate::smb2::FLAG_SIGNED != 0))
        })
        .unwrap_or(false);

    // Hold the session lock only long enough to validate the handle and dup
    // its fd. All subsequent I/O (splice or buffered pread) runs lock-free,
    // so reads on different channels of the same session run in parallel
    // instead of serializing — and a concurrent CLOSE can't free the fd
    // mid-read (the dup keeps it alive; the reactor/handler closes it).
    let dup = {
        let mut sess = sref.lock().unwrap();
        let Some(of) = sess.handles.get(fid, chain.tree_id) else {
            err_resp(tx, h, status::FILE_CLOSED, chain);
            return None;
        };
        if of.is_dir {
            err_resp(tx, h, status::INVALID_DEVICE_REQUEST, chain);
            return None;
        }
        // SAFETY: the session lock is held, so of.fd can't be closed under us;
        // the dup (close-on-exec) is owned by the caller — closed below, or by
        // the reactor via the ZcReadPlan.
        unsafe { libc::fcntl(of.fd, libc::F_DUPFD_CLOEXEC, 0) }
    };
    if dup < 0 {
        err_resp(tx, h, status::INSUFFICIENT_RESOURCES, chain);
        return None;
    }
    let length = length.min(max_read);

    // Standalone large unsigned reads take the zero-copy splice path; the
    // plan owns the dup and the reactor closes it when the splice finishes.
    if chain.single && length >= ZC_MIN_READ && !must_sign {
        // A full read (offset+length within the file) can never hit EOF, so
        // the reactor can submit the whole splice→send→splice as one linked
        // chain (no userspace round-trips). EOF-region reads stay sequential.
        let linked = vfs::fstat_meta(dup)
            .map(|m| offset.saturating_add(length as u64) <= m.size)
            .unwrap_or(false);
        return Some(ZcReadPlan {
            fd: dup,
            offset,
            length,
            min_count,
            msg_id: h.msg_id,
            credit_charge: h.credit_charge,
            credits: h.credits,
            tree_id: chain.tree_id,
            session_id: chain.session_id,
            linked,
        });
    }

    // Buffered path (small reads, compounds, signed) — lock-free pread.
    let mut buf = vec![0u8; length as usize];
    let res = vfs::pread(dup, &mut buf, offset);
    // SAFETY: dup is owned solely by this buffered-read path (it was not handed to a
    // ZcReadPlan); closed once.
    unsafe { libc::close(dup) };
    match res {
        Ok(0) if length > 0 => err_resp(tx, h, status::END_OF_FILE, chain),
        Ok(n) if (n as u32) < min_count => err_resp(tx, h, status::END_OF_FILE, chain),
        Ok(n) => {
            begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
            tx.p16(17);
            tx.p8(80);
            tx.p8(0);
            tx.p32(n as u32);
            tx.p32(0);
            tx.p32(0);
            tx.pbytes(&buf[..n]);
        }
        Err(e) => err_resp(tx, h, status::from_errno(e), chain),
    }
    None
}

// -------------------------------------------------------------------- WRITE

#[allow(clippy::too_many_arguments)]
fn write(
    srv: &Srv,
    sess: &mut SessionInner,
    h: &ReqHdr,
    msg: &[u8],
    chain: &mut Chain,
    tx: &mut Vec<u8>,
    tree: crate::smb2::Tree,
) {
    let share_idx = tree.share_idx;
    let parsed = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 49 {
            return None;
        }
        let data_off = r.u16()? as usize;
        let length = r.u32()? as usize;
        let offset = r.u64()?;
        let fid = parse_fid(&mut r, chain)?;
        let data = msg.get(data_off..data_off + length)?;
        Some((data, offset, fid))
    })();
    let Some((data, offset, fid)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    if tree.read_only {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }
    let Some(of) = sess.handles.get(fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    if !of.writable {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }
    let writer_key = of.lease_key;
    let ino = vfs::fstat_meta(of.fd).ok().map(|m| m.ino);
    match vfs::pwrite_all(of.fd, data, offset) {
        Ok(()) => {
            // Break read-caching leases held by *other* clients (different lease
            // key) AFTER the data is durable, so a broken holder's re-read sees
            // the final content rather than racing a mid-write partial. The
            // write handle's own lease key is exempt; read → none needs no ack.
            if let Some(ino) = ino {
                break_leases(srv, (share_idx, ino), writer_key);
            }
            begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
            tx.p16(17);
            tx.p16(0);
            tx.p32(data.len() as u32);
            tx.p32(0); // Remaining
            tx.p16(0);
            tx.p16(0);
        }
        Err(e) => err_resp(tx, h, status::from_errno(e), chain),
    }
}

// ---------------------------------------------------------- QUERY_DIRECTORY

const QD_RESTART_SCANS: u8 = 0x01;
const QD_RETURN_SINGLE: u8 = 0x02;
const QD_REOPEN: u8 = 0x10;

fn query_directory(sess: &mut SessionInner, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 33 {
            return None;
        }
        let class = r.u8()?;
        let flags = r.u8()?;
        let _index = r.u32()?;
        let fid = parse_fid(&mut r, chain)?;
        let name_off = r.u16()? as usize;
        let name_len = r.u16()? as usize;
        let out_len = r.u32()?;
        let pattern = if name_len == 0 {
            String::new()
        } else {
            from_utf16le(msg.get(name_off..name_off + name_len)?)
        };
        Some((class, flags, fid, out_len, pattern))
    })();
    let Some((class, flags, fid, out_len, pattern)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(of) = sess.handles.get(fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    if !of.is_dir {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    }

    let restart = flags & (QD_RESTART_SCANS | QD_REOPEN) != 0;
    let need_new = match &of.dir {
        None => true,
        Some(d) => restart || d.pattern != pattern,
    };
    if need_new {
        match vfs::dir_snapshot(of, &pattern) {
            Ok(entries) => of.dir = Some(DirState { entries, pos: 0, pattern: pattern.clone() }),
            Err(e) => {
                err_resp(tx, h, status::from_errno(e), chain);
                return;
            }
        }
    }
    let dstate = of.dir.as_mut().expect("dir state set above");
    if dstate.pos >= dstate.entries.len() {
        let st = if dstate.entries.is_empty() { status::NO_SUCH_FILE } else { status::NO_MORE_FILES };
        err_resp(tx, h, st, chain);
        return;
    }

    let out_len = out_len.min(MAX_TRANSACT) as usize;
    let mut data: Vec<u8> = Vec::with_capacity(out_len.min(64 * 1024));
    let mut last_entry_start = 0usize;
    let mut emitted = 0usize;
    while dstate.pos < dstate.entries.len() {
        let e = &dstate.entries[dstate.pos];
        let mut entry: Vec<u8> = Vec::with_capacity(128 + e.name.len() * 2);
        if !put_dir_entry(&mut entry, class, e) {
            err_resp(tx, h, status::INVALID_PARAMETER, chain);
            return;
        }
        // Align to 8 and stamp NextEntryOffset (rewritten to 0 on the last).
        let pad = (8 - (entry.len() % 8)) % 8;
        entry.resize(entry.len() + pad, 0);
        let next = entry.len() as u32;
        entry[0..4].copy_from_slice(&next.to_le_bytes());
        if data.len() + entry.len() > out_len {
            break;
        }
        last_entry_start = data.len();
        data.pbytes(&entry);
        dstate.pos += 1;
        emitted += 1;
        if flags & QD_RETURN_SINGLE != 0 {
            break;
        }
    }
    if emitted == 0 {
        // First entry alone doesn't fit the client buffer.
        err_resp(tx, h, status::BUFFER_TOO_SMALL, chain);
        return;
    }
    data[last_entry_start..last_entry_start + 4].copy_from_slice(&0u32.to_le_bytes());

    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(9);
    tx.p16(72);
    tx.p32(data.len() as u32);
    tx.pbytes(&data);
}

// File information classes (query directory + query info)
const FILE_DIRECTORY_INFORMATION: u8 = 1;
const FILE_FULL_DIRECTORY_INFORMATION: u8 = 2;
const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 3;
const FILE_NAMES_INFORMATION: u8 = 12;
const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 37;
const FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 38;

fn put_dir_entry(b: &mut Vec<u8>, class: u8, e: &vfs::DirEnt) -> bool {
    let name = utf16le(&e.name);
    let m = &e.meta;
    b.p32(0); // NextEntryOffset, patched by caller
    b.p32(0); // FileIndex
    if class == FILE_NAMES_INFORMATION {
        b.p32(name.len() as u32);
        b.pbytes(&name);
        return true;
    }
    b.p64(m.crtime);
    b.p64(m.atime);
    b.p64(m.mtime);
    b.p64(m.ctime);
    b.p64(m.size);
    b.p64(m.alloc);
    b.p32(m.attrs);
    b.p32(name.len() as u32);
    match class {
        FILE_DIRECTORY_INFORMATION => {}
        FILE_FULL_DIRECTORY_INFORMATION => {
            b.p32(0); // EaSize
        }
        FILE_BOTH_DIRECTORY_INFORMATION => {
            b.p32(0); // EaSize
            b.p8(0); // ShortNameLength
            b.p8(0);
            b.zeros(24); // ShortName
        }
        FILE_ID_BOTH_DIRECTORY_INFORMATION => {
            b.p32(0);
            b.p8(0);
            b.p8(0);
            b.zeros(24);
            b.p16(0); // Reserved2
            b.p64(m.ino);
        }
        FILE_ID_FULL_DIRECTORY_INFORMATION => {
            b.p32(0); // EaSize
            b.p32(0); // Reserved
            b.p64(m.ino);
        }
        _ => return false,
    }
    b.pbytes(&name);
    true
}

// --------------------------------------------------------------- QUERY_INFO

const INFO_FILE: u8 = 1;
const INFO_FILESYSTEM: u8 = 2;
const INFO_SECURITY: u8 = 3;

fn query_info(srv: &Srv, sess: &mut SessionInner, h: &ReqHdr, body: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 41 {
            return None;
        }
        let info_type = r.u8()?;
        let class = r.u8()?;
        let out_len = r.u32()?;
        r.skip(2 + 2 + 4 + 4 + 4)?; // in off, reserved, in len, addl, flags
        let fid = parse_fid(&mut r, chain)?;
        Some((info_type, class, out_len, fid))
    })();
    let Some((info_type, class, out_len, fid)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(of) = sess.handles.get(fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };

    let mut data: Vec<u8> = Vec::new();
    let st = match info_type {
        INFO_FILE => file_info(of, class, &mut data),
        INFO_FILESYSTEM => fs_info(srv, of, class, &mut data),
        INFO_SECURITY => {
            security_descriptor(&mut data);
            status::SUCCESS
        }
        _ => status::NOT_SUPPORTED,
    };
    if st != status::SUCCESS {
        crate::logd!("QUERY_INFO unsupported: info_type={} class={} -> {:#x}", info_type, class, st);
        err_resp(tx, h, st, chain);
        return;
    }
    let mut final_st = status::SUCCESS;
    if data.len() > out_len as usize {
        data.truncate(out_len as usize);
        final_st = status::BUFFER_OVERFLOW;
    }
    begin_resp(tx, h, final_st, chain.related, chain.tree_id, chain.session_id);
    tx.p16(9);
    tx.p16(72);
    tx.p32(data.len() as u32);
    tx.pbytes(&data);
}

fn put_basic_info(b: &mut Vec<u8>, m: &vfs::Meta, attrs: u32) {
    b.p64(m.crtime);
    b.p64(m.atime);
    b.p64(m.mtime);
    b.p64(m.ctime);
    b.p32(attrs);
    b.p32(0);
}

fn put_standard_info(b: &mut Vec<u8>, m: &vfs::Meta, delete_pending: bool) {
    b.p64(m.alloc);
    b.p64(m.size);
    b.p32(m.nlink);
    b.p8(delete_pending as u8);
    b.p8(m.is_dir as u8);
    b.p16(0);
}

fn file_info(of: &vfs::OpenFile, class: u8, b: &mut Vec<u8>) -> u32 {
    let m = match vfs::fstat_meta(of.fd) {
        Ok(m) => m,
        Err(e) => return status::from_errno(e),
    };
    let attrs = vfs::finalize_attrs(m.attrs, &of.leaf);
    match class {
        4 => put_basic_info(b, &m, attrs), // FileBasicInformation
        5 => put_standard_info(b, &m, of.delete_on_close), // FileStandardInformation
        6 => b.p64(m.ino),                 // FileInternalInformation
        7 => b.p32(0),                     // FileEaInformation
        8 => b.p32(MAXIMAL_ACCESS_ALL),    // FileAccessInformation
        9 => {
            // FileNameInformation
            let name = utf16le(&format!("\\{}", of.rel));
            b.p32(name.len() as u32);
            b.pbytes(&name);
        }
        14 => b.p64(0), // FilePositionInformation
        16 => b.p32(0), // FileModeInformation
        17 => b.p32(0), // FileAlignmentInformation
        18 => {
            // FileAllInformation
            put_basic_info(b, &m, attrs);
            put_standard_info(b, &m, of.delete_on_close);
            b.p64(m.ino);
            b.p32(0); // Ea
            b.p32(MAXIMAL_ACCESS_ALL);
            b.p64(0); // Position
            b.p32(0); // Mode
            b.p32(0); // Alignment
            let name = utf16le(&format!("\\{}", of.rel));
            b.p32(name.len() as u32);
            b.pbytes(&name);
        }
        34 => {
            // FileNetworkOpenInformation
            b.p64(m.crtime);
            b.p64(m.atime);
            b.p64(m.mtime);
            b.p64(m.ctime);
            b.p64(m.alloc);
            b.p64(m.size);
            b.p32(attrs);
            b.p32(0);
        }
        35 => {
            // FileAttributeTagInformation
            b.p32(attrs);
            b.p32(0);
        }
        22 => {
            // FileStreamInformation: a regular file has one data stream
            // (the default ::$DATA); a directory has none. .NET's FileStream
            // queries this on open, so returning NOT_SUPPORTED broke it.
            if !m.is_dir {
                let name = utf16le("::$DATA");
                b.p32(0); // NextEntryOffset (single entry)
                b.p32(name.len() as u32); // StreamNameLength
                b.p64(m.size); // StreamSize
                b.p64(m.alloc); // StreamAllocationSize
                b.pbytes(&name);
            }
            // directory → zero entries (empty buffer, SUCCESS)
        }
        _ => return status::NOT_SUPPORTED,
    }
    status::SUCCESS
}

/// Minimal self-relative SECURITY_DESCRIPTOR: owner/group = BUILTIN
/// Administrators (S-1-5-32-544), a DACL granting Everyone (S-1-1-0) full
/// access. We don't enforce ACLs, but Windows/.NET query the descriptor on
/// open and choke on an error reply, so we synthesize a permissive one.
fn security_descriptor(b: &mut Vec<u8>) {
    // SID S-1-5-32-544 (Administrators), 16 bytes.
    let admins: [u8; 16] = [
        1, 2, 0, 0, 0, 0, 0, 5, // rev=1, subauth=2, idauth=5
        32, 0, 0, 0, // 0x20
        32, 2, 0, 0, // 0x220 = 544
    ];
    // SID S-1-1-0 (Everyone), 12 bytes.
    let everyone: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];

    // Layout: header(20) | DACL(28) | owner(16) | group(16) = 80 bytes.
    let off_dacl = 20u32;
    let off_owner = 48u32;
    let off_group = 64u32;
    // Header (self-relative).
    b.p8(1); // Revision
    b.p8(0); // Sbz1
    b.p16(0x8004); // Control: SE_DACL_PRESENT | SE_SELF_RELATIVE
    b.p32(off_owner);
    b.p32(off_group);
    b.p32(0); // OffsetSacl
    b.p32(off_dacl);
    // DACL: ACL header(8) + one ACCESS_ALLOWED_ACE(8 + 12 SID = 20) = 28.
    b.p8(2); // AclRevision
    b.p8(0); // Sbz1
    b.p16(28); // AclSize
    b.p16(1); // AceCount
    b.p16(0); // Sbz2
    // ACE
    b.p8(0); // ACCESS_ALLOWED_ACE_TYPE
    b.p8(0); // AceFlags
    b.p16(20); // AceSize (8 + 12)
    b.p32(0x001F_01FF); // FILE_ALL_ACCESS
    b.pbytes(&everyone);
    // Owner + Group SIDs
    b.pbytes(&admins);
    b.pbytes(&admins);
}

fn fs_info(srv: &Srv, of: &vfs::OpenFile, class: u8, b: &mut Vec<u8>) -> u32 {
    match class {
        1 => {
            // FileFsVolumeInformation
            let label = utf16le(&srv.cfg.shares[of.share_idx as usize].name);
            b.p64(srv.start_ft);
            b.p32(0x52_4B54); // serial "RKT"
            b.p32(label.len() as u32);
            b.p8(0); // SupportsObjects
            b.p8(0);
            b.pbytes(&label);
        }
        3 => {
            // FileFsSizeInformation
            let (total, avail, _, spu, bps) = match vfs::fs_sizes(of.fd) {
                Ok(v) => v,
                Err(e) => return status::from_errno(e),
            };
            b.p64(total);
            b.p64(avail);
            b.p32(spu);
            b.p32(bps);
        }
        4 => {
            // FileFsDeviceInformation
            b.p32(7); // FILE_DEVICE_DISK
            b.p32(0x20); // FILE_DEVICE_IS_MOUNTED
        }
        5 => {
            // FileFsAttributeInformation
            let name = utf16le("NTFS");
            b.p32(0x47); // case-sensitive | case-preserved | unicode | sparse
            b.p32(255);
            b.p32(name.len() as u32);
            b.pbytes(&name);
        }
        7 => {
            // FileFsFullSizeInformation
            let (total, avail, free, spu, bps) = match vfs::fs_sizes(of.fd) {
                Ok(v) => v,
                Err(e) => return status::from_errno(e),
            };
            b.p64(total);
            b.p64(avail);
            b.p64(free);
            b.p32(spu);
            b.p32(bps);
        }
        _ => return status::NOT_SUPPORTED,
    }
    status::SUCCESS
}

// ----------------------------------------------------------------- SET_INFO

#[allow(clippy::too_many_arguments)]
fn set_info(
    srv: &Srv,
    sess: &mut SessionInner,
    h: &ReqHdr,
    msg: &[u8],
    chain: &mut Chain,
    tx: &mut Vec<u8>,
    share: &ShareCfg,
    read_only: bool,
) {
    let parsed = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 33 {
            return None;
        }
        let info_type = r.u8()?;
        let class = r.u8()?;
        let buf_len = r.u32()? as usize;
        let buf_off = r.u16()? as usize;
        r.skip(2 + 4)?;
        let fid = parse_fid(&mut r, chain)?;
        let data = msg.get(buf_off..buf_off + buf_len)?;
        Some((info_type, class, fid, data))
    })();
    let Some((info_type, class, fid, data)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    if info_type != INFO_FILE {
        err_resp(tx, h, status::NOT_SUPPORTED, chain);
        return;
    }
    if read_only {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }
    let share_root = share.path.clone();
    let Some(of) = sess.handles.get(fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };

    // Leases to break once the change has been made (#42): the file's own
    // (from other lease keys), plus a rename's replaced target.
    let own = vfs::fstat_meta(of.fd).ok().filter(|m| !m.is_dir).map(|m| (of.share_idx, m.ino));
    let mut broken: Vec<(u32, u64)> = Vec::new();
    let st = match class {
        4 => set_basic_info(of, data),
        13 => {
            let st = set_disposition(of, data);
            if st == status::SUCCESS && of.delete_on_close {
                broken.extend(own);
            }
            st
        }
        10 => {
            let (st, replaced) = set_rename(of, data, &share_root);
            if st == status::SUCCESS {
                broken.extend(own);
                broken.extend(replaced.map(|ino| (of.share_idx, ino)));
            }
            st
        }
        // FileAllocationInformation: a no-op here (the data doesn't change),
        // so there's nothing to break.
        19 => status::SUCCESS,
        20 => {
            // FileEndOfFileInformation: truncate or extend.
            let mut r = Rdr::new(data);
            match r.u64() {
                Some(len) => match vfs::ftruncate(of.fd, len) {
                    Ok(()) => {
                        broken.extend(own);
                        status::SUCCESS
                    }
                    Err(e) => status::from_errno(e),
                },
                None => status::INVALID_PARAMETER,
            }
        }
        _ => status::NOT_SUPPORTED,
    };
    let except = of.lease_key;
    for key in broken {
        break_leases(srv, key, except);
    }
    if st != status::SUCCESS {
        err_resp(tx, h, st, chain);
        return;
    }
    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(2);
}

fn set_basic_info(of: &vfs::OpenFile, data: &[u8]) -> u32 {
    let mut r = Rdr::new(data);
    let (Some(_cr), Some(at), Some(mt), Some(_ct), Some(_attrs)) =
        (r.u64(), r.u64(), r.u64(), r.u64(), r.u32())
    else {
        return status::INVALID_PARAMETER;
    };
    fn ts(ft: u64) -> libc::timespec {
        if ft == 0 || ft == u64::MAX {
            libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }
        } else {
            let unix100 = ft as i64 - 116_444_736_000_000_000;
            libc::timespec {
                // Euclidean: pre-1970 times keep tv_nsec in 0..1e9 (futimens
                // rejects a negative one with EINVAL).
                tv_sec: unix100.div_euclid(10_000_000) as _,
                tv_nsec: (unix100.rem_euclid(10_000_000) * 100) as _,
            }
        }
    }
    let times = [ts(at), ts(mt)];
    // SAFETY: times is a live [timespec; 2], exactly what futimens reads; of.fd is held
    // under the session lock.
    if unsafe { libc::futimens(of.fd, times.as_ptr()) } < 0 {
        // Attribute-only updates (archive bit etc.) succeed as a no-op.
        let e = vfs::errno();
        if e != libc::EACCES && e != libc::EPERM {
            return status::from_errno(e);
        }
    }
    status::SUCCESS
}

fn set_disposition(of: &mut vfs::OpenFile, data: &[u8]) -> u32 {
    let Some(&flag) = data.first() else {
        return status::INVALID_PARAMETER;
    };
    if flag != 0 && of.rel.is_empty() {
        return status::ACCESS_DENIED; // never the share root (#39 R21)
    }
    if flag != 0 && of.is_dir {
        // Windows semantics: refuse marking a non-empty directory.
        match std::fs::read_dir(&of.path) {
            Ok(mut it) => {
                if it.next().is_some() {
                    return status::DIRECTORY_NOT_EMPTY;
                }
            }
            Err(e) => return status::from_errno(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }
    of.delete_on_close = flag != 0;
    status::SUCCESS
}

/// Rename the open file. Returns the status and, when an existing file was
/// replaced, that file's inode (its holders' leases must break).
fn set_rename(of: &mut vfs::OpenFile, data: &[u8], share_root: &Path) -> (u32, Option<u64>) {
    let mut r = Rdr::new(data);
    let parsed = (|| {
        let replace = r.u8()? != 0;
        r.skip(7 + 8)?; // reserved, RootDirectory
        let name_len = r.u32()? as usize;
        let name = from_utf16le(r.take(name_len)?);
        Some((replace, name))
    })();
    let Some((replace, name)) = parsed else {
        return (status::INVALID_PARAMETER, None);
    };
    let (new_path, new_rel) = match vfs::resolve(share_root, &name) {
        Ok(v) => v,
        Err(st) => return (st, None),
    };
    // Neither the share root nor anything onto it (#39 R21).
    if of.rel.is_empty() || new_rel.is_empty() {
        return (status::ACCESS_DENIED, None);
    }
    if !replace && new_path.exists() {
        return (status::OBJECT_NAME_COLLISION, None);
    }
    let replaced = vfs::stat_meta(&new_path)
        .ok()
        .filter(|m| !m.is_dir)
        .map(|m| m.ino)
        .filter(|&ino| vfs::fstat_meta(of.fd).map(|m| m.ino != ino).unwrap_or(true));
    let res = if replace {
        std::fs::rename(&of.path, &new_path).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
    } else {
        // RENAME_NOREPLACE closes the window between the exists() check above
        // and the rename, where a file created meanwhile would be replaced.
        vfs::rename_noreplace(&of.path, &new_path)
    };
    if let Err(e) = res {
        let st = if e == libc::EEXIST { status::OBJECT_NAME_COLLISION } else { status::from_errno(e) };
        return (st, None);
    }
    of.leaf = new_rel.rsplit('\\').next().unwrap_or("").to_string();
    of.path = new_path;
    of.rel = new_rel;
    (status::SUCCESS, replaced)
}

// --------------------------------------------------------------------- LOCK

const LOCKFLAG_SHARED: u32 = 0x1;
const LOCKFLAG_EXCLUSIVE: u32 = 0x2;
const LOCKFLAG_UNLOCK: u32 = 0x4;

fn lock(sess: &mut SessionInner, h: &ReqHdr, body: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 48 {
            return None;
        }
        let count = r.u16()? as usize;
        r.skip(4)?; // lock sequence
        let fid = parse_fid(&mut r, chain)?;
        if count == 0 || count > 64 {
            return None;
        }
        let mut elems = Vec::with_capacity(count);
        for _ in 0..count {
            let off = r.u64()?;
            let len = r.u64()?;
            let flags = r.u32()?;
            r.skip(4)?;
            elems.push((off, len, flags));
        }
        Some((fid, elems))
    })();
    let Some((fid, elems)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let Some(of) = sess.handles.get(fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    if of.is_dir {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    }

    // Batch semantics: all-or-nothing. Locks taken earlier in this request
    // are unwound if a later element conflicts. Blocking waits degrade to
    // immediate failure in v0.2 (clients retry).
    let mut applied: Vec<(u64, u64)> = Vec::new();
    let mut fail = status::SUCCESS;
    for &(off, len, flags) in &elems {
        let res = if flags & LOCKFLAG_UNLOCK != 0 {
            vfs::range_lock(of.fd, off, len, vfs::LockKind::Unlock)
        } else if flags & LOCKFLAG_EXCLUSIVE != 0 {
            vfs::range_lock(of.fd, off, len, vfs::LockKind::Exclusive)
        } else if flags & LOCKFLAG_SHARED != 0 {
            vfs::range_lock(of.fd, off, len, vfs::LockKind::Shared)
        } else {
            fail = status::INVALID_PARAMETER;
            break;
        };
        match res {
            Ok(()) => {
                if flags & LOCKFLAG_UNLOCK == 0 {
                    applied.push((off, len));
                }
            }
            Err(e) if e == libc::EAGAIN || e == libc::EACCES => {
                fail = status::LOCK_NOT_GRANTED;
                break;
            }
            Err(e) => {
                fail = status::from_errno(e);
                break;
            }
        }
    }
    if fail != status::SUCCESS {
        for &(off, len) in applied.iter().rev() {
            let _ = vfs::range_lock(of.fd, off, len, vfs::LockKind::Unlock);
        }
        err_resp(tx, h, fail, chain);
        return;
    }
    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(4);
    tx.p16(0);
}

// ------------------------------------------------------------ CHANGE_NOTIFY

fn change_notify(pc: &mut ProtoConn, sess: &mut SessionInner, h: &ReqHdr, body: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let mut r = Rdr::new(body);
        if r.u16()? != 32 {
            return None;
        }
        let flags = r.u16()?;
        let out_len = r.u32()?;
        let fid = parse_fid(&mut r, chain)?;
        let filter = r.u32()?;
        Some((flags, out_len, fid, filter))
    })();
    let Some((flags, out_len, fid, filter)) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let want_sign = pc
        .channels
        .get(&chain.session_id)
        .map(|c| c.sign.is_some() && (c.signing_required || h.flags & crate::smb2::FLAG_SIGNED != 0))
        .unwrap_or(false);
    let Some(of) = sess.handles.get(fid, chain.tree_id) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    if !of.is_dir {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    }
    let path = of.path.clone();

    let async_id = pc.next_async_id;
    pc.next_async_id += 1;
    let meta = crate::smb2::AsyncMeta {
        msg_id: h.msg_id,
        credit_charge: h.credit_charge,
        session_id: chain.session_id,
        async_id,
        want_sign,
    };
    pc.notify_new.push(crate::smb2::NotifyPend {
        async_id,
        fid,
        path,
        recursive: flags & 0x1 != 0,
        filter,
        out_len: out_len.min(MAX_TRANSACT),
        meta: meta.clone(),
    });
    pc.notify_active.push((fid, async_id));

    // Interim response: STATUS_PENDING with the async id; the final
    // completion is sent out-of-band by the reactor.
    crate::smb2::begin_resp_async(tx, &meta, status::PENDING, h.credits, CMD_CHANGE_NOTIFY);
    crate::smb2::err_body(tx);
}

// -------------------------------------------------------------------- IOCTL

fn ioctl(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
    let parsed = (|| {
        let body = &msg[64..];
        let mut r = Rdr::new(body);
        if r.u16()? != 57 {
            return None;
        }
        r.skip(2)?;
        let ctl = r.u32()?;
        r.skip(16)?; // FileId
        Some(ctl)
    })();
    let Some(ctl) = parsed else {
        err_resp(tx, h, status::INVALID_PARAMETER, chain);
        return;
    };
    let out: Vec<u8> = match ctl {
        FSCTL_VALIDATE_NEGOTIATE_INFO => {
            // The client repeats what it sent in NEGOTIATE; anything changed
            // means an on-path attacker rewrote the (unsigned) NEGOTIATE, e.g.
            // to strip SMB 3.1.1 and with it encryption. MS-SMB2 3.3.5.15.12:
            // terminate the connection (#39 R8).
            let input = (|| {
                let mut r = Rdr::new(msg.get(64 + 24..)?);
                let in_off = r.u32()? as usize;
                let in_len = r.u32()? as usize;
                let mut r = Rdr::new(msg.get(in_off..in_off.checked_add(in_len)?)?);
                let caps = r.u32()?;
                let guid: [u8; 16] = r.take(16)?.try_into().ok()?;
                let secmode = r.u16()?;
                let n = r.u16()? as usize;
                let mut dialects = Vec::with_capacity(n.min(16));
                for _ in 0..n.min(16) {
                    dialects.push(r.u16()?);
                }
                Some((crate::smb2::ClientNeg { secmode, caps, guid }, dialects))
            })();
            let valid = match (&input, &pc.client_neg) {
                (Some((cn, dialects)), Some(orig)) => {
                    cn == orig
                        && SUPPORTED_DIALECTS.iter().find(|d| dialects.contains(d)) == Some(&pc.dialect)
                }
                _ => false,
            };
            if !valid {
                crate::logw!("VALIDATE_NEGOTIATE_INFO mismatch (NEGOTIATE tampered?): disconnecting");
                pc.close = true;
                return;
            }
            // Echo our negotiated parameters so the client can verify them.
            // They MUST match what NEGOTIATE advertised, or the client aborts
            // with "security settings mismatch".
            let mut secmode = SECURITY_MODE_SIGNING_ENABLED;
            if srv.cfg.require_signing {
                secmode |= SECURITY_MODE_SIGNING_REQUIRED;
            }
            let mut o: Vec<u8> = Vec::with_capacity(24);
            o.p32(pc.server_caps);
            o.pbytes(&srv.guid);
            o.p16(secmode);
            o.p16(pc.dialect);
            o
        }
        FSCTL_QUERY_NETWORK_INTERFACE_INFO => {
            // Report our interfaces so the client knows how many channels to
            // open. Returning RSS-capable, high-speed links invites the
            // client to stripe across multiple connections. Loopback is never
            // advertised — a remote client would try to connect to its OWN
            // loopback; same-IP multichannel still works via the RSS flag.
            let ifaces: Vec<_> =
                srv.interfaces.iter().filter(|i| !i.loopback).cloned().collect();
            crate::net::encode_interface_info(&ifaces)
        }
        _ => {
            err_resp(tx, h, status::NOT_SUPPORTED, chain);
            return;
        }
    };

    begin_resp(tx, h, status::SUCCESS, chain.related, chain.tree_id, chain.session_id);
    tx.p16(49);
    tx.p16(0);
    tx.p32(ctl);
    tx.p64(u64::MAX); // FileId
    tx.p64(u64::MAX);
    tx.p32(112); // InputOffset
    tx.p32(0); // InputCount
    tx.p32(112); // OutputOffset
    tx.p32(out.len() as u32);
    tx.p32(0); // Flags
    tx.p32(0);
    tx.pbytes(&out);
}

#[cfg(test)]
mod oplock_tests {
    use super::*;

    /// Build one SMB2_CREATE_CONTEXT carrying an RqLs lease request.
    fn rqls_ctx(data: &[u8]) -> Vec<u8> {
        // header is 16 bytes; name "RqLs" at off 16 (len 4), pad to 8-align,
        // data at off 24.
        let name_off = 16u16;
        let data_off = 24u16;
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes()); // Next = 0 (last)
        v.extend_from_slice(&name_off.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes()); // NameLength
        v.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        v.extend_from_slice(&data_off.to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(CTX_NAME_RQLS); // off 16
        v.extend_from_slice(&[0, 0, 0, 0]); // pad to off 24
        v.extend_from_slice(data); // off 24
        v
    }

    #[test]
    fn lease_ctx_v1() {
        let mut data = Vec::new();
        let key = [0xABu8; 16];
        data.extend_from_slice(&key);
        data.extend_from_slice(&(LEASE_READ_CACHING | LEASE_HANDLE_CACHING).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&0u64.to_le_bytes()); // duration
        assert_eq!(data.len(), 32);
        let l = parse_lease_ctx(&rqls_ctx(&data)).expect("v1 lease");
        assert_eq!(l.key, key);
        assert_eq!(l.state, LEASE_READ_CACHING | LEASE_HANDLE_CACHING);
        assert!(!l.v2);
    }

    #[test]
    fn lease_ctx_v2() {
        let mut data = Vec::new();
        let key = [0x11u8; 16];
        let parent = [0x22u8; 16];
        data.extend_from_slice(&key);
        data.extend_from_slice(
            &(LEASE_READ_CACHING | LEASE_WRITE_CACHING | LEASE_HANDLE_CACHING).to_le_bytes(),
        );
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&0u64.to_le_bytes()); // duration
        data.extend_from_slice(&parent);
        data.extend_from_slice(&7u16.to_le_bytes()); // epoch
        data.extend_from_slice(&0u16.to_le_bytes()); // reserved
        assert_eq!(data.len(), 52);
        let l = parse_lease_ctx(&rqls_ctx(&data)).expect("v2 lease");
        assert_eq!(l.key, key);
        assert!(l.v2);
        assert_eq!(l.parent, parent);
        assert_eq!(l.epoch, 7);
    }

    #[test]
    fn no_lease_ctx() {
        // A non-RqLs context (name "MxAc") must yield None.
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&16u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // data off
        v.extend_from_slice(&0u32.to_le_bytes()); // data len
        v.extend_from_slice(b"MxAc");
        assert!(parse_lease_ctx(&v).is_none());
    }
}
