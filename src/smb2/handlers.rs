//! SMB2 command handlers.

use std::path::Path;

use super::*;
use crate::config::{ShareCfg, Srv};
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
const SESSION_FLAG_IS_GUEST: u16 = 0x1;
const SESSION_FLAG_ENCRYPT_DATA: u16 = 0x4;
const MAXIMAL_ACCESS_ALL: u32 = 0x001F_01FF;
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

    // Verify signatures on signed requests; reject unsigned requests on
    // signing-required channels. Signing state is connection-local. Skipped
    // entirely for encrypted sessions — an SMB3-encrypted message is not
    // separately signed; the AEAD tag provides integrity (and it already
    // verified during decryption).
    if let Some(ch) = pc.channels.get(&chain.session_id) {
        if !ch.encrypt {
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
                    create(srv, &mut sess, h, msg, chain, tx, share, tree.share_idx, cid, allow_oplock)
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
                CMD_WRITE => write(srv, &mut sess, h, msg, chain, tx, share, tree.share_idx),
                CMD_QUERY_DIRECTORY => query_directory(&mut sess, h, msg, chain, tx),
                CMD_QUERY_INFO => query_info(srv, &mut sess, h, body, chain, tx),
                CMD_SET_INFO => set_info(&mut sess, h, msg, chain, tx, share),
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

/// LOGOFF: drop this connection's channel; tear down the shared session when
/// its last channel goes away.
fn logoff(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, chain: &Chain, tx: &mut Vec<u8>) {
    if pc.channels.remove(&chain.session_id).is_none() {
        err_resp(tx, h, status::USER_SESSION_DELETED, chain);
        return;
    }
    if let Some(sref) = srv.sessions.get(chain.session_id) {
        let drop_session = {
            let mut s = sref.lock().unwrap();
            s.channels = s.channels.saturating_sub(1);
            s.channels == 0
        };
        if drop_session {
            srv.sessions.remove(chain.session_id);
        }
    }
    simple_resp(tx, h, chain);
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
        r.skip(2 + 2 + 4 + 16)?; // secmode, reserved, caps, guid
        let ctx_off = r.u32()? as usize;
        let ctx_count = r.u16()? as usize;
        r.skip(2)?;
        let mut dialects = Vec::with_capacity(count.min(16));
        for _ in 0..count.min(16) {
            dialects.push(r.u16()?);
        }
        Some((dialects, ctx_off, ctx_count))
    })();
    let Some((dialects, ctx_off, ctx_count)) = parsed else {
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
                        for _ in 0..n.min(8) {
                            let c = r.u16()?;
                            if cipher == 0
                                && matches!(
                                    c,
                                    CIPHER_AES128_GCM
                                        | CIPHER_AES256_GCM
                                        | CIPHER_AES128_CCM
                                        | CIPHER_AES256_CCM
                                )
                            {
                                cipher = c;
                            }
                        }
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
    let hint = crate::ntlm::spnego_hint();
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

fn ss_resp(tx: &mut Vec<u8>, h: &ReqHdr, st: u32, related: bool, sid: u64, flags: u16, blob: &[u8]) {
    begin_resp(tx, h, st, related, 0, sid);
    tx.p16(9);
    tx.p16(flags);
    tx.p16(72); // SecurityBufferOffset
    tx.p16(blob.len() as u16);
    tx.pbytes(blob);
}

const SESSION_FLAG_BINDING: u8 = 0x01;

fn session_setup(srv: &Srv, pc: &mut ProtoConn, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>) {
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
                // Bind to an existing session — it must already exist.
                if h.session_id == 0 || srv.sessions.get(h.session_id).is_none() {
                    err_resp(tx, h, status::USER_SESSION_DELETED, chain);
                    return;
                }
                h.session_id
            } else {
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
                let ok = if !s.established {
                    false
                } else if s.guest {
                    // Guest sessions carry no key; binding is signing-free
                    // regardless of what the client presents.
                    true
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
    sess.next_tree_id += 1;
    let tree_id = sess.next_tree_id;
    sess.trees.insert(tree_id, crate::smb2::Tree { share_idx, ipc });
    chain.tree_id = tree_id;

    begin_resp(tx, h, status::SUCCESS, chain.related, tree_id, chain.session_id);
    tx.p16(16);
    tx.p8(if ipc { 2 } else { 1 }); // ShareType: pipe / disk
    tx.p8(0);
    tx.p32(0); // ShareFlags
    tx.p32(0); // Capabilities
    tx.p32(if ipc { 0x001F_00A9 } else { MAXIMAL_ACCESS_ALL });
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
    share_idx: u32,
    cid: (usize, usize, u16),
    allow_oplock: bool,
) {
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
    if share.read_only && (wants_write || creates || delete_on_close) {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }

    let existing = vfs::stat_meta(&path).ok();
    let exists = existing.is_some();
    let existing_dir = existing.map(|m| m.is_dir).unwrap_or(false);

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
            wants_write || (req.desired & MAXIMUM_ALLOWED != 0 && !share.read_only) || creates;
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
            unsafe { libc::close(fd) };
            err_resp(tx, h, status::from_errno(e), chain);
            return;
        }
    };
    // Prefetch hint for streamed file reads (helps cold-storage throughput).
    if !is_dir {
        vfs::advise_sequential(fd);
    }
    let leaf = rel.rsplit('\\').next().unwrap_or("").to_string();
    let attrs = vfs::finalize_attrs(meta.attrs, &leaf);
    // Grant a read-caching lease when the client requests one (RqLs) on a file.
    // Read-caching is the safe subset: distinct lease keys coexist, there's no
    // dirty client data, and a conflicting write breaks it to none. Gated off
    // by default (Config::oplocks). The client's lease key is recorded on the
    // handle regardless (so a WRITE can exempt the client's own lease).
    let lease_req = req.lease.clone();
    let grant_lease = srv.cfg.oplocks
        && allow_oplock
        && !is_dir
        && lease_req.as_ref().is_some_and(|l| l.state & LEASE_READ_CACHING != 0);
    let fid = sess.handles.insert(OpenFile {
        fd,
        path,
        rel,
        leaf,
        share_idx,
        is_dir,
        writable,
        delete_on_close,
        dir: None,
        oplock_ino: if grant_lease { Some(meta.ino) } else { None },
        lease_key: lease_req.as_ref().map(|l| l.key),
    });
    chain.last_fid = Some(fid);
    if grant_lease {
        let l = lease_req.as_ref().unwrap();
        srv.leases.grant(
            (share_idx, meta.ino),
            crate::lease::LeaseGrant {
                lease_key: l.key,
                state: LEASE_READ_CACHING,
                epoch: l.epoch,
                session_id: chain.session_id,
                wid: cid.0,
                conn_idx: cid.1,
                conn_gen: cid.2,
            },
        );
        crate::logd!("lease: granted READ (share {share_idx}, ino {})", meta.ino);
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
        tx.p32(LEASE_READ_CACHING); // LeaseState (granted)
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
    let Some(of) = sess.handles.remove(fid) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };
    // Release any lease this handle held.
    if let (Some(ino), Some(lk)) = (of.oplock_ino, of.lease_key) {
        srv.leases.release((of.share_idx, ino), lk);
    }
    // Complete any CHANGE_NOTIFY pended on this handle.
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

    let post_attrib = flags & 0x1 != 0;
    let meta = if post_attrib { vfs::fstat_meta(of.fd).ok() } else { None };

    let mut st = status::SUCCESS;
    if of.delete_on_close {
        let res = if of.is_dir {
            std::fs::remove_dir(&of.path)
        } else {
            std::fs::remove_file(&of.path)
        };
        if let Err(e) = res {
            st = status::from_errno(e.raw_os_error().unwrap_or(libc::EIO));
        }
    }
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
    let Some(of) = sess.handles.get(fid) else {
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
        let Some(of) = sess.handles.get(fid) else {
            err_resp(tx, h, status::FILE_CLOSED, chain);
            return None;
        };
        if of.is_dir {
            err_resp(tx, h, status::INVALID_DEVICE_REQUEST, chain);
            return None;
        }
        unsafe { libc::dup(of.fd) }
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
    share: &ShareCfg,
    share_idx: u32,
) {
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
    if share.read_only {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }
    let Some(of) = sess.handles.get(fid) else {
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
                for b in srv.leases.break_conflicts((share_idx, ino), writer_key) {
                    srv.mailboxes[b.wid].post(b);
                }
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
    let Some(of) = sess.handles.get(fid) else {
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
    let Some(of) = sess.handles.get(fid) else {
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

fn set_info(sess: &mut SessionInner, h: &ReqHdr, msg: &[u8], chain: &mut Chain, tx: &mut Vec<u8>, share: &ShareCfg) {
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
    if share.read_only {
        err_resp(tx, h, status::ACCESS_DENIED, chain);
        return;
    }
    let share_root = share.path.clone();
    let Some(of) = sess.handles.get(fid) else {
        err_resp(tx, h, status::FILE_CLOSED, chain);
        return;
    };

    let st = match class {
        4 => set_basic_info(of, data),
        13 => set_disposition(of, data),
        10 => set_rename(of, data, &share_root),
        19 => status::SUCCESS, // FileAllocationInformation: best-effort no-op
        20 => {
            // FileEndOfFileInformation
            let mut r = Rdr::new(data);
            match r.u64() {
                Some(len) => match vfs::ftruncate(of.fd, len) {
                    Ok(()) => status::SUCCESS,
                    Err(e) => status::from_errno(e),
                },
                None => status::INVALID_PARAMETER,
            }
        }
        _ => status::NOT_SUPPORTED,
    };
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
                tv_sec: (unix100 / 10_000_000) as _,
                tv_nsec: ((unix100 % 10_000_000) * 100) as _,
            }
        }
    }
    let times = [ts(at), ts(mt)];
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

fn set_rename(of: &mut vfs::OpenFile, data: &[u8], share_root: &Path) -> u32 {
    let mut r = Rdr::new(data);
    let parsed = (|| {
        let replace = r.u8()? != 0;
        r.skip(7 + 8)?; // reserved, RootDirectory
        let name_len = r.u32()? as usize;
        let name = from_utf16le(r.take(name_len)?);
        Some((replace, name))
    })();
    let Some((replace, name)) = parsed else {
        return status::INVALID_PARAMETER;
    };
    let (new_path, new_rel) = match vfs::resolve(share_root, &name) {
        Ok(v) => v,
        Err(st) => return st,
    };
    if !replace && new_path.exists() {
        return status::OBJECT_NAME_COLLISION;
    }
    if let Err(e) = std::fs::rename(&of.path, &new_path) {
        return status::from_errno(e.raw_os_error().unwrap_or(libc::EIO));
    }
    of.leaf = new_rel.rsplit('\\').next().unwrap_or("").to_string();
    of.path = new_path;
    of.rel = new_rel;
    status::SUCCESS
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
    let Some(of) = sess.handles.get(fid) else {
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
    let Some(of) = sess.handles.get(fid) else {
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
            // Echo our negotiated parameters so the client can verify them.
            // The security mode MUST match what we advertised in NEGOTIATE
            // or the client aborts with "security settings mismatch".
            let mut secmode = SECURITY_MODE_SIGNING_ENABLED;
            if srv.cfg.require_signing {
                secmode |= SECURITY_MODE_SIGNING_REQUIRED;
            }
            let mut o: Vec<u8> = Vec::with_capacity(24);
            o.p32(CAP_LARGE_MTU);
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
