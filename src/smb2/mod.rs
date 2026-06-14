//! SMB2 core: header codec, compound dispatch, connection protocol state.
//!
//! The reactor feeds complete NetBIOS-framed messages to [`process_frame`]
//! and sends back whatever lands in `tx`. A standalone READ becomes a
//! [`FrameAction::ZcRead`] plan that the reactor serves zero-copy via
//! splice; everything else is answered from the tx buffer.

pub mod handlers;

use std::collections::HashMap;
use std::os::fd::RawFd;
use std::path::PathBuf;

use crate::config::Srv;
use crate::crypto::{self, SignAlg};
use crate::session::SessionInner;
use crate::status;
use crate::wire::{Put, Rdr};

pub const CMD_NEGOTIATE: u16 = 0;
pub const CMD_SESSION_SETUP: u16 = 1;
pub const CMD_LOGOFF: u16 = 2;
pub const CMD_TREE_CONNECT: u16 = 3;
pub const CMD_TREE_DISCONNECT: u16 = 4;
pub const CMD_CREATE: u16 = 5;
pub const CMD_CLOSE: u16 = 6;
pub const CMD_FLUSH: u16 = 7;
pub const CMD_READ: u16 = 8;
pub const CMD_WRITE: u16 = 9;
pub const CMD_LOCK: u16 = 10;
pub const CMD_IOCTL: u16 = 11;
pub const CMD_CANCEL: u16 = 12;
pub const CMD_ECHO: u16 = 13;
pub const CMD_QUERY_DIRECTORY: u16 = 14;
pub const CMD_CHANGE_NOTIFY: u16 = 15;
pub const CMD_QUERY_INFO: u16 = 16;
pub const CMD_SET_INFO: u16 = 17;
#[allow(dead_code)]
pub const CMD_OPLOCK_BREAK: u16 = 18;

// SMB2 oplock levels (RequestedOplockLevel / granted OplockLevel byte).
pub const OPLOCK_NONE: u8 = 0x00;
pub const OPLOCK_LEVEL_II: u8 = 0x01;
pub const OPLOCK_EXCLUSIVE: u8 = 0x08;
pub const OPLOCK_BATCH: u8 = 0x09;
/// RequestedOplockLevel sentinel meaning "a lease is requested via the RqLs
/// create context" rather than a legacy oplock.
pub const OPLOCK_LEASE: u8 = 0xFF;

// SMB2 lease state caching bits (LeaseState in the RqLs create context).
pub const LEASE_READ_CACHING: u32 = 0x01;
pub const LEASE_HANDLE_CACHING: u32 = 0x02;
pub const LEASE_WRITE_CACHING: u32 = 0x04;

/// Create-context name "RqLs" (lease request/response).
pub const CTX_NAME_RQLS: &[u8; 4] = b"RqLs";

pub const FLAG_RESPONSE: u32 = 0x1;
pub const FLAG_ASYNC: u32 = 0x2;
pub const FLAG_RELATED: u32 = 0x4;
#[allow(dead_code)]
pub const FLAG_SIGNED: u32 = 0x8;

pub const MAX_TRANSACT: u32 = 4 << 20;
pub const MAX_WRITE: u32 = 4 << 20;
/// Advertised MaxReadSize target (further bounded by pipe capacity).
/// Deliberately smaller than MaxWriteSize: a modest rsize keeps the client
/// issuing many parallel READs (readahead), which pipelines far better
/// through the splice path than few huge serialized ones — measured 5.8 GB/s
/// at 1 MiB vs 0.67 GB/s at 4 MiB on loopback.
pub const MAX_READ_TARGET: u32 = 1 << 20;
/// Reads at or above this size take the zero-copy splice path.
pub const ZC_MIN_READ: u32 = 8 * 1024;

const HDR_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct ReqHdr {
    pub credit_charge: u16,
    pub command: u16,
    pub credits: u16,
    pub flags: u32,
    pub next: u32,
    pub msg_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    /// Present when the ASYNC flag is set (e.g. CANCEL of a pended op).
    pub async_id: Option<u64>,
}

pub fn parse_hdr(b: &[u8]) -> Option<ReqHdr> {
    let mut r = Rdr::new(b);
    if r.take(4)? != [0xFE, b'S', b'M', b'B'] {
        return None;
    }
    if r.u16()? != 64 {
        return None;
    }
    let credit_charge = r.u16()?;
    let _status = r.u32()?;
    let command = r.u16()?;
    let credits = r.u16()?;
    let flags = r.u32()?;
    let next = r.u32()?;
    let msg_id = r.u64()?;
    let (tree_id, session_id, async_id);
    if flags & FLAG_ASYNC != 0 {
        async_id = Some(r.u64()?);
        tree_id = 0;
        session_id = r.u64()?;
    } else {
        let _process_id = r.u32()?;
        tree_id = r.u32()?;
        session_id = r.u64()?;
        async_id = None;
    }
    r.skip(16)?; // signature
    Some(ReqHdr {
        credit_charge,
        command,
        credits,
        flags,
        next,
        msg_id,
        tree_id,
        session_id,
        async_id,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct Tree {
    pub share_idx: u32,
    pub ipc: bool,
}

#[derive(Debug, Clone)]
pub struct SignCtx {
    pub alg: SignAlg,
    pub key: [u8; 16],
}

/// SMB3 encryption keys for one channel. `c2s` decrypts inbound transform
/// frames; `s2c` encrypts outbound; `nonce_ctr` is the per-connection GCM
/// nonce counter (never reused for a given key).
#[derive(Debug, Clone)]
pub struct EncCtx {
    pub cipher: u16,
    /// Cipher keys in 32-byte buffers; only the first `cipher_key_len(cipher)`
    /// bytes are used (16 for AES-128, 32 for AES-256).
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
    pub nonce_ctr: u64,
}

/// Auth state stashed between the NTLM challenge and the AUTHENTICATE.
#[derive(Debug)]
pub struct PendingAuth {
    pub challenge: [u8; 8],
    pub spnego: bool,
    /// Set when this is a multichannel session-binding handshake.
    pub binding: bool,
}

/// Per-connection, per-session channel state. One `ProtoConn` holds a
/// `ChannelState` for every session it is a channel of. Signing and preauth
/// are connection-local (no registry lock on the sign/verify hot path); the
/// shared session state (trees, handles, key) lives in the registry.
#[derive(Debug)]
pub struct ChannelState {
    pub established: bool,
    pub signing_required: bool,
    pub sign: Option<SignCtx>,
    pub pending: Option<PendingAuth>,
    /// This connection's running preauth hash for this session's setup.
    pub preauth: [u8; 64],
    /// SMB3 encryption keys, set once the session negotiates encryption.
    pub enc: Option<EncCtx>,
    /// Encrypt responses on this session (client requested or server/share
    /// requires). When set, signing is implied by the AEAD tag.
    pub encrypt: bool,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            established: false,
            signing_required: false,
            sign: None,
            pending: None,
            preauth: [0; 64],
            enc: None,
            encrypt: false,
        }
    }
}

/// A pended CHANGE_NOTIFY the reactor must watch via inotify.
/// `recursive` (WATCH_TREE) and `filter` are accepted but not narrowed:
/// inotify is non-recursive and we over-deliver rather than filter —
/// clients treat extra notifications as a hint to re-check.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NotifyPend {
    pub async_id: u64,
    pub fid: u64,
    pub path: PathBuf,
    pub recursive: bool,
    pub filter: u32,
    pub out_len: u32,
    pub meta: AsyncMeta,
}

#[derive(Debug, Clone)]
pub struct NotifyDone {
    pub async_id: u64,
    pub status: u32,
}

#[derive(Debug, Clone)]
pub struct AsyncMeta {
    pub msg_id: u64,
    pub credit_charge: u16,
    pub session_id: u64,
    pub async_id: u64,
    pub want_sign: bool,
}

/// Per-connection protocol state. Sessions and their handles live in the
/// shared `Srv::sessions` registry (so channels on other cores share them);
/// `channels` holds this connection's per-session signing/preauth state.
pub struct ProtoConn {
    pub dialect: u16,
    /// Negotiated SMB3 cipher (0 = none). Currently AES-128-GCM only.
    pub cipher: u16,
    pub channels: HashMap<u64, ChannelState>,
    pub max_read: u32,
    /// SMB 3.1.1 connection preauth hash (negotiate exchange).
    pub preauth_neg: [u8; 64],
    /// Credits currently granted to the client (window accounting).
    pub credits_out: i64,
    pub next_async_id: u64,
    /// CHANGE_NOTIFY pends for the reactor to register (drained each frame).
    pub notify_new: Vec<NotifyPend>,
    /// Completions (cancel / handle close) for the reactor to emit.
    pub notify_done: Vec<NotifyDone>,
    /// Live pends: (fid, async_id) — owned here so CLOSE/CANCEL can find them.
    pub notify_active: Vec<(u64, u64)>,
    /// This connection's location in the reactor, so a lease/oplock break
    /// raised on another worker can be routed back here (worker id + the
    /// connection's slot index + generation guard). See `crate::lease`.
    pub wid: usize,
    pub conn_idx: usize,
    pub conn_gen: u16,
}

impl ProtoConn {
    pub fn new(srv: &Srv, wid: usize, conn_idx: usize, conn_gen: u16) -> Self {
        Self {
            dialect: 0,
            cipher: 0,
            channels: HashMap::new(),
            max_read: srv.max_read,
            preauth_neg: [0; 64],
            credits_out: 0,
            next_async_id: 1,
            notify_new: Vec::new(),
            notify_done: Vec::new(),
            notify_active: Vec::new(),
            wid,
            conn_idx,
            conn_gen,
        }
    }
}

/// Everything the reactor needs to finish a zero-copy READ after the
/// dispatcher has validated the request.
#[derive(Debug, Clone)]
pub struct ZcReadPlan {
    pub fd: RawFd,
    pub offset: u64,
    pub length: u32,
    pub min_count: u32,
    pub msg_id: u64,
    pub credit_charge: u16,
    pub credits: u16,
    pub tree_id: u32,
    pub session_id: u64,
    /// True when offset+length ≤ file size (a full read, no EOF possible),
    /// so the reactor can submit splice-in → send → splice-out as one linked
    /// io_uring chain instead of three round-trips.
    pub linked: bool,
}

pub enum FrameAction {
    Respond,
    ZcRead(ZcReadPlan),
    /// Tear down the connection. Used when an encrypted (TRANSFORM) frame
    /// cannot be decrypted — per MS-SMB2 the server disconnects rather than
    /// leaving the client waiting for a response it will never get.
    Close,
}

/// State threaded through a compound chain.
pub struct Chain {
    pub related: bool,
    pub session_id: u64,
    pub tree_id: u32,
    pub last_fid: Option<u64>,
    pub single: bool,
}

/// Write a response header. Returns the offset of the header start in `tx`.
#[allow(clippy::too_many_arguments)]
pub fn begin_resp(
    tx: &mut Vec<u8>,
    h: &ReqHdr,
    st: u32,
    related: bool,
    tree_id: u32,
    session_id: u64,
) -> usize {
    let start = tx.len();
    tx.pbytes(&[0xFE, b'S', b'M', b'B']);
    tx.p16(64);
    tx.p16(h.credit_charge);
    tx.p32(st);
    tx.p16(h.command);
    tx.p16(h.credits); // credits granted (accounted by the dispatcher)
    tx.p32(FLAG_RESPONSE | if related { FLAG_RELATED } else { 0 });
    tx.p32(0); // NextCommand, patched by the chain loop
    tx.p64(h.msg_id);
    tx.p32(0); // process id
    tx.p32(tree_id);
    tx.p64(session_id);
    tx.zeros(16); // signature
    start
}

/// Async response header (interim STATUS_PENDING and final completions).
pub fn begin_resp_async(tx: &mut Vec<u8>, meta: &AsyncMeta, st: u32, credits: u16, cmd: u16) -> usize {
    let start = tx.len();
    tx.pbytes(&[0xFE, b'S', b'M', b'B']);
    tx.p16(64);
    tx.p16(meta.credit_charge);
    tx.p32(st);
    tx.p16(cmd);
    tx.p16(credits);
    tx.p32(FLAG_RESPONSE | FLAG_ASYNC);
    tx.p32(0); // NextCommand
    tx.p64(meta.msg_id);
    tx.p64(meta.async_id);
    tx.p64(meta.session_id);
    tx.zeros(16);
    start
}

/// Sign the message at tx[start..end] in place (signature field is zeroed
/// by construction) and set the SIGNED flag.
pub fn sign_in_place(tx: &mut [u8], start: usize, end: usize, sc: &SignCtx) {
    let flags_off = start + 16;
    let cur = u32::from_le_bytes(tx[flags_off..flags_off + 4].try_into().unwrap());
    tx[flags_off..flags_off + 4].copy_from_slice(&(cur | FLAG_SIGNED).to_le_bytes());
    let sig = crypto::smb2_signature(sc.alg, &sc.key, &[&tx[start..end]]);
    tx[start + 48..start + 64].copy_from_slice(&sig);
}

/// Verify a signed request message (signature field substituted with zeros).
pub fn verify_signature(msg: &[u8], sc: &SignCtx) -> bool {
    if msg.len() < 64 {
        return false;
    }
    let zeros = [0u8; 16];
    let sig = crypto::smb2_signature(sc.alg, &sc.key, &[&msg[..48], &zeros, &msg[64..]]);
    // Not secret-dependent timing-wise in any exploitable way (MAC compare),
    // but compare without early exit anyway.
    sig.iter().zip(&msg[48..64]).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
}

/// Derive the SMB2/3 signing context for `dialect` from a 16-byte session key.
pub fn derive_sign_ctx(dialect: u16, session_key: &[u8; 16], preauth: &[u8; 64]) -> SignCtx {
    match dialect {
        0x0202 | 0x0210 => SignCtx { alg: SignAlg::HmacSha256, key: *session_key },
        0x0311 => SignCtx {
            alg: SignAlg::AesCmac,
            key: crypto::kdf128(session_key, b"SMBSigningKey\0", preauth),
        },
        _ => SignCtx {
            alg: SignAlg::AesCmac,
            key: crypto::kdf128(session_key, b"SMB2AESCMAC\0", b"SmbSign\0"),
        },
    }
}

/// 9-byte SMB2 ERROR response body.
pub fn err_body(tx: &mut Vec<u8>) {
    tx.p16(9);
    tx.p8(0); // ErrorContextCount
    tx.p8(0);
    tx.p32(0); // ByteCount
    tx.p8(0); // ErrorData placeholder
}

pub fn err_resp(tx: &mut Vec<u8>, h: &ReqHdr, st: u32, chain: &Chain) {
    begin_resp(tx, h, st, chain.related, chain.tree_id, chain.session_id);
    err_body(tx);
}

/// NBT prefix + success header + READ response fixed part for `n` bytes of
/// spliced payload that the reactor will append from the pipe.
pub fn build_read_resp_prefix(plan: &ZcReadPlan, n: u32, tx: &mut Vec<u8>) {
    tx.clear();
    let h = read_plan_hdr(plan);
    tx.zeros(4);
    begin_resp(tx, &h, status::SUCCESS, false, plan.tree_id, plan.session_id);
    tx.p16(17); // StructureSize
    tx.p8(80); // DataOffset
    tx.p8(0);
    tx.p32(n);
    tx.p32(0); // DataRemaining
    tx.p32(0);
    let total = (tx.len() - 4) as u32 + n;
    finish_nbt_with(tx, total);
}

pub fn build_read_err(plan: &ZcReadPlan, st: u32, tx: &mut Vec<u8>) {
    tx.clear();
    let h = read_plan_hdr(plan);
    tx.zeros(4);
    begin_resp(tx, &h, st, false, plan.tree_id, plan.session_id);
    err_body(tx);
    let total = (tx.len() - 4) as u32;
    finish_nbt_with(tx, total);
}

fn read_plan_hdr(plan: &ZcReadPlan) -> ReqHdr {
    ReqHdr {
        credit_charge: plan.credit_charge,
        command: CMD_READ,
        credits: plan.credits,
        flags: 0,
        next: 0,
        msg_id: plan.msg_id,
        tree_id: plan.tree_id,
        session_id: plan.session_id,
        async_id: None,
    }
}

/// Build a complete (NBT-framed, optionally signed) final response for a
/// pended CHANGE_NOTIFY. `events` are (action, name) pairs; an empty list —
/// or an encoding that exceeds the client's buffer — degrades to
/// STATUS_NOTIFY_ENUM_DIR ("re-enumerate") for success completions.
pub fn build_notify_final(
    pc: &ProtoConn,
    meta: &AsyncMeta,
    st: u32,
    events: &[(u32, String)],
    out_len: u32,
) -> Vec<u8> {
    let mut tx = Vec::with_capacity(256);
    tx.zeros(4);
    let mut data: Vec<u8> = Vec::new();
    if st == status::SUCCESS && !events.is_empty() {
        let mut entry_starts: Vec<usize> = Vec::new();
        for (action, name) in events {
            // 4-align between entries.
            while !data.len().is_multiple_of(4) {
                data.push(0);
            }
            entry_starts.push(data.len());
            let n16 = crate::wire::utf16le(name);
            data.p32(0); // NextEntryOffset patched below
            data.p32(*action);
            data.p32(n16.len() as u32);
            data.pbytes(&n16);
        }
        for w in entry_starts.windows(2) {
            let next = (w[1] - w[0]) as u32;
            data[w[0]..w[0] + 4].copy_from_slice(&next.to_le_bytes());
        }
    }
    if st == status::SUCCESS && !events.is_empty() && data.len() <= out_len as usize {
        let start = begin_resp_async(&mut tx, meta, st, 0, CMD_CHANGE_NOTIFY);
        tx.p16(9);
        tx.p16(72);
        tx.p32(data.len() as u32);
        tx.pbytes(&data);
        finalize_async(pc, meta, &mut tx, start);
    } else {
        let final_st = if st == status::SUCCESS { status::NOTIFY_ENUM_DIR } else { st };
        let start = begin_resp_async(&mut tx, meta, final_st, 0, CMD_CHANGE_NOTIFY);
        err_body(&mut tx);
        finalize_async(pc, meta, &mut tx, start);
    }
    tx
}

fn finalize_async(pc: &ProtoConn, meta: &AsyncMeta, tx: &mut [u8], start: usize) {
    if meta.want_sign {
        if let Some(sc) = pc.channels.get(&meta.session_id).and_then(|c| c.sign.clone()) {
            let end = tx.len();
            sign_in_place(tx, start, end, &sc);
        }
    }
    let total = (tx.len() - 4) as u32;
    finish_nbt_with(tx, total);
}

fn finish_nbt_with(tx: &mut [u8], len: u32) {
    tx[0] = 0;
    tx[1] = ((len >> 16) & 0xFF) as u8;
    tx[2] = ((len >> 8) & 0xFF) as u8;
    tx[3] = (len & 0xFF) as u8;
}

/// Build a complete NBT-framed SMB2 **Lease Break** notification (server→client,
/// MS-SMB2 2.2.23.2): a synchronous response with MessageId = -1, keyed by the
/// client's 16-byte LeaseKey, telling it to drop from `cur_state` to
/// `new_state`. Read-caching → none carries no dirty data, so Flags = 0 (no
/// acknowledgement required). Signed if the channel has a signing context.
#[allow(clippy::too_many_arguments)]
pub fn build_lease_break(
    lease_key: &[u8; 16],
    cur_state: u32,
    new_state: u32,
    epoch: u16,
    session_id: u64,
    sign: Option<&SignCtx>,
) -> Vec<u8> {
    let mut tx = Vec::with_capacity(4 + 64 + 44);
    tx.zeros(4); // NBT length placeholder
    let start = tx.len();
    tx.pbytes(&[0xFE, b'S', b'M', b'B']);
    tx.p16(64); // header StructureSize
    tx.p16(0); // CreditCharge
    tx.p32(0); // Status
    tx.p16(CMD_OPLOCK_BREAK);
    tx.p16(0); // CreditResponse
    tx.p32(FLAG_RESPONSE);
    tx.p32(0); // NextCommand
    tx.p64(0xFFFF_FFFF_FFFF_FFFF); // MessageId (notification sentinel)
    tx.p32(0); // ProcessId
    tx.p32(0); // TreeId
    tx.p64(session_id);
    tx.zeros(16); // signature
    // Lease Break Notification body (StructureSize 44).
    tx.p16(44);
    tx.p16(epoch); // NewEpoch (v2 leases; 0 for v1)
    tx.p32(0); // Flags: 0 = acknowledgement not required (read-cache drop)
    tx.pbytes(lease_key); // LeaseKey (16)
    tx.p32(cur_state); // CurrentLeaseState
    tx.p32(new_state); // NewLeaseState
    tx.p32(0); // BreakReason
    tx.p32(0); // AccessMaskHint
    tx.p32(0); // ShareMaskHint
    if let Some(sc) = sign {
        let end = tx.len();
        sign_in_place(&mut tx, start, end, sc);
    }
    let total = (tx.len() - 4) as u32;
    finish_nbt_with(&mut tx, total);
    tx
}

// ----------------------------------------------------- SMB3 TRANSFORM_HEADER

/// SMB2_TRANSFORM_HEADER ProtocolId: 0xFD 'S' 'M' 'B'.
pub const TRANSFORM_PROTO: [u8; 4] = [0xFD, b'S', b'M', b'B'];
const TRANSFORM_HDR_LEN: usize = 52;

/// True if a (de-NBT'd) frame is an SMB3 encrypted transform message.
pub fn is_transform(frame: &[u8]) -> bool {
    frame.len() >= 4 && frame[..4] == TRANSFORM_PROTO
}

/// Decrypt a transform-wrapped frame into the inner plaintext SMB2 message(s).
/// Returns None on malformed input or AEAD authentication failure.
pub fn decrypt_transform(frame: &[u8], enc: &EncCtx) -> Option<Vec<u8>> {
    if frame.len() < TRANSFORM_HDR_LEN || frame[..4] != TRANSFORM_PROTO {
        return None;
    }
    let tag: [u8; 16] = frame[4..20].try_into().ok()?;
    let orig_size = u32::from_le_bytes(frame[36..40].try_into().ok()?) as usize;
    // AAD is the header from the Nonce field to the end (Signature excluded).
    let aad = frame[20..TRANSFORM_HDR_LEN].to_vec();
    let klen = crypto::cipher_key_len(enc.cipher);
    let nlen = crypto::cipher_nonce_len(enc.cipher);
    let nonce = &frame[20..20 + nlen];
    let ct = &frame[TRANSFORM_HDR_LEN..];
    if ct.len() != orig_size {
        return None;
    }
    let mut buf = ct.to_vec();
    if !crypto::aead_open(enc.cipher, &enc.c2s[..klen], nonce, &aad, &mut buf, &tag) {
        return None;
    }
    Some(buf)
}

/// Wrap a plaintext SMB2 message/compound in a transform header, encrypting
/// with the s2c key. Writes NBT prefix + transform header + ciphertext to tx
/// (which is cleared first).
pub fn wrap_transform(plain: &[u8], enc: &mut EncCtx, session_id: u64, tx: &mut Vec<u8>) {
    tx.clear();
    tx.zeros(4); // NBT placeholder
    let hdr = tx.len();
    tx.pbytes(&TRANSFORM_PROTO);
    let sig_off = tx.len();
    tx.zeros(16); // Signature (AEAD tag) — filled after encryption
    enc.nonce_ctr += 1;
    let mut nonce16 = [0u8; 16];
    nonce16[..8].copy_from_slice(&enc.nonce_ctr.to_le_bytes());
    tx.pbytes(&nonce16); // Nonce (12 used for GCM)
    tx.p32(plain.len() as u32); // OriginalMessageSize
    tx.p16(0); // Reserved
    tx.p16(1); // Flags: SMB2_ENCRYPTION (3.1.1)
    tx.p64(session_id);
    debug_assert_eq!(tx.len() - hdr, TRANSFORM_HDR_LEN);
    let aad_start = hdr + 20;
    let ct_off = tx.len();
    tx.pbytes(plain);
    let klen = crypto::cipher_key_len(enc.cipher);
    let nlen = crypto::cipher_nonce_len(enc.cipher);
    let nonce = nonce16[..nlen].to_vec();
    let (head, tail) = tx.split_at_mut(ct_off);
    let tag = crypto::aead_seal(enc.cipher, &enc.s2c[..klen], &nonce, &head[aad_start..ct_off], tail);
    tx[sig_off..sig_off + 16].copy_from_slice(&tag);
    let total = (tx.len() - 4) as u32;
    finish_nbt_with(tx, total);
}

/// Process one NetBIOS-framed message (without the 4-byte NBT prefix).
/// Transparently handles SMB3 encryption: a transform-wrapped frame is
/// decrypted, the inner message processed, and the response re-encrypted.
/// The response (with NBT prefix) is appended to `tx`.
pub fn process_frame(srv: &Srv, pc: &mut ProtoConn, frame: &[u8], tx: &mut Vec<u8>) -> FrameAction {
    if is_transform(frame) {
        // Session id lives at bytes 44..52 of the transform header.
        let sid = if frame.len() >= TRANSFORM_HDR_LEN {
            u64::from_le_bytes(frame[44..52].try_into().unwrap())
        } else {
            return FrameAction::Close; // malformed transform → disconnect
        };
        let Some(enc) = pc.channels.get(&sid).and_then(|c| c.enc.clone()) else {
            // No decryption key for this session (e.g. a guest/anonymous
            // session, which cannot be encrypted). The client sealed traffic we
            // can't decrypt — disconnect instead of silently dropping, which
            // would hang the client forever (#26).
            return FrameAction::Close;
        };
        let Some(plain) = decrypt_transform(frame, &enc) else {
            return FrameAction::Close; // auth/decrypt failure → disconnect
        };
        // This session is actively encrypting — make reads take the buffered
        // path (responses are wrapped, so they can't be spliced).
        if let Some(c) = pc.channels.get_mut(&sid) {
            c.encrypt = true;
        }
        // Process the decrypted message(s); encrypted sessions never splice
        // (read() forces the buffered path), so this won't be a ZcRead.
        let mut inner = Vec::new();
        let _ = process_plain(srv, pc, &plain, &mut inner, true);
        if inner.len() <= 4 {
            tx.clear();
            return FrameAction::Respond; // no response (e.g. CANCEL)
        }
        // Re-encrypt the plaintext response (strip its NBT prefix first).
        let mut enc2 = pc.channels.get(&sid).and_then(|c| c.enc.clone()).unwrap();
        wrap_transform(&inner[4..], &mut enc2, sid, tx);
        if let Some(c) = pc.channels.get_mut(&sid) {
            c.enc = Some(enc2); // persist the bumped nonce counter
        }
        return FrameAction::Respond;
    }
    process_plain(srv, pc, frame, tx, false)
}

/// `encrypted` is true when these messages arrived inside a transform (so the
/// response will be wrapped, not signed).
fn process_plain(
    srv: &Srv,
    pc: &mut ProtoConn,
    frame: &[u8],
    tx: &mut Vec<u8>,
    encrypted: bool,
) -> FrameAction {
    let base = tx.len();
    tx.zeros(4); // NBT placeholder

    // Legacy SMB1 negotiate → wildcard SMB2 response (dialect 0x02FF).
    if frame.len() >= 4 && frame[0] == 0xFF && &frame[1..4] == b"SMB" {
        handlers::negotiate_resp_smb1_wildcard(srv, pc, tx);
        let total = (tx.len() - base - 4) as u32;
        finish_nbt_with(&mut tx[base..], total);
        return FrameAction::Respond;
    }

    let mut chain = Chain {
        related: false,
        session_id: 0,
        tree_id: 0,
        last_fid: None,
        single: true,
    };
    let mut plan: Option<ZcReadPlan> = None;
    let mut prev_start: Option<usize> = None;
    let mut off = 0usize;
    // Per-response bookkeeping for the post-pass (signing + preauth).
    struct RespRec {
        cmd: u16,
        start: usize,
        req_off: usize,
        req_end: usize,
        sess_id: u64,
    }
    let mut recs: Vec<RespRec> = Vec::new();

    while let Some(h) = parse_hdr(&frame[off..]) {
        let msg_end = if h.next > 0 {
            (off + h.next as usize).min(frame.len())
        } else {
            frame.len()
        };
        if msg_end < off + HDR_LEN {
            break;
        }
        let msg = &frame[off..msg_end];
        chain.single = off == 0 && h.next == 0;

        // Align this response and patch the previous header's NextCommand.
        if let Some(p) = prev_start {
            tx.pad8(base + 4);
            let here = tx.len();
            tx.patch32(p + 20, (here - p) as u32);
        }
        let resp_start = tx.len();
        if let Some(z) = handlers::dispatch(srv, pc, &h, msg, &mut chain, tx) {
            plan = Some(z);
        }
        if tx.len() > resp_start {
            prev_start = Some(resp_start);
            recs.push(RespRec {
                cmd: h.command,
                start: resp_start,
                req_off: off,
                req_end: msg_end,
                sess_id: chain.session_id,
            });
        }

        if h.next == 0 {
            break;
        }
        off += h.next as usize;
        if off + HDR_LEN > frame.len() {
            break;
        }
    }

    if let Some(p) = plan {
        // A zero-copy plan writes nothing buffered; drop the placeholder.
        tx.truncate(base);
        return FrameAction::ZcRead(p);
    }

    // Post-pass 1: sign every response on an authenticated session. A
    // session only holds signing material (`sess.sign`) once a non-guest
    // user has authenticated, and MS-SMB2 requires such sessions to sign
    // all responses — including the final SESSION_SETUP — regardless of
    // whether the client set the SIGNING_REQUIRED flag. (Responses end
    // where the next one starts; the last ends at tx end.)
    for i in 0..recs.len() {
        let end = recs.get(i + 1).map(|r| r.start).unwrap_or(tx.len());
        let rec = &recs[i];
        let Some(ch) = pc.channels.get(&rec.sess_id) else {
            continue;
        };
        // Responses to encrypted requests are wrapped (AEAD tag = integrity),
        // so they're not separately signed. Plaintext-path responses — incl.
        // the session-setup response that *enables* encryption — are signed.
        if encrypted {
            continue;
        }
        if let Some(sc) = ch.sign.clone() {
            sign_in_place(tx, rec.start, end, &sc);
        }
    }

    // Post-pass 2 (SMB 3.1.1): preauth integrity hash chaining over the
    // exact transmitted bytes. The NEGOTIATE exchange updates the
    // connection hash; interim SESSION_SETUP responses update the pending
    // session hash (requests are hashed in the handler, where ordering
    // against key derivation matters).
    if pc.dialect == 0x0311 {
        for i in 0..recs.len() {
            let end = recs.get(i + 1).map(|r| r.start).unwrap_or(tx.len());
            let rec = &recs[i];
            match rec.cmd {
                CMD_NEGOTIATE => {
                    let h0 = crypto::sha512(&[&[0u8; 64], &frame[rec.req_off..rec.req_end]]);
                    pc.preauth_neg = crypto::sha512(&[&h0, &tx[rec.start..end]]);
                }
                CMD_SESSION_SETUP => {
                    let st = u32::from_le_bytes(tx[rec.start + 8..rec.start + 12].try_into().unwrap());
                    if st == status::MORE_PROCESSING_REQUIRED {
                        if let Some(ch) = pc.channels.get_mut(&rec.sess_id) {
                            ch.preauth = crypto::sha512(&[&ch.preauth, &tx[rec.start..end]]);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let total = (tx.len() - base - 4) as u32;
    if total == 0 {
        tx.truncate(base); // nothing to send for this frame
    } else {
        finish_nbt_with(&mut tx[base..], total);
    }
    FrameAction::Respond
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ShareCfg};
    use crate::wire::utf16le;

    fn test_srv(dir: &std::path::Path) -> Srv {
        let cfg = Config {
            listen: "127.0.0.1:445".into(),
            workers: 1,
            server_name: "TESTSRV".into(),
            log_level: 0,
            allow_guest: None,
            require_signing: false,
            multichannel: false,
            encrypt: false,
            advertise_only: vec![],
            core_pinning: false,
            sqpoll: false,
            prefer_aes256: false,
            oplocks: false,
            shares: vec![ShareCfg { name: "t".into(), path: dir.into(), read_only: false }],
            users: vec![],
        };
        let users = cfg.user_db();
        let allow_guest = cfg.guest_allowed();
        Srv {
            cfg,
            guid: [9; 16],
            max_read: 1 << 20,
            start_ft: 0,
            users,
            allow_guest,
            interfaces: vec![],
            sessions: crate::session::Registry::default(),
            mailboxes: vec![],
            leases: crate::lease::LeaseTable::default(),
        }
    }

    fn req_hdr(cmd: u16, msg_id: u64, tree: u32, sess: u64) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(64);
        v.pbytes(&[0xFE, b'S', b'M', b'B']);
        v.p16(64);
        v.p16(1); // credit charge
        v.p32(0);
        v.p16(cmd);
        v.p16(64); // credits requested
        v.p32(0); // flags
        v.p32(0); // next
        v.p64(msg_id);
        v.p32(0); // pid
        v.p32(tree);
        v.p64(sess);
        v.zeros(16);
        v
    }

    struct Resp {
        status: u32,
        tree_id: u32,
        session_id: u64,
        body: Vec<u8>,
    }

    fn roundtrip(srv: &Srv, pc: &mut ProtoConn, frame: Vec<u8>) -> Resp {
        let mut tx = Vec::new();
        match process_frame(srv, pc, &frame, &mut tx) {
            FrameAction::Respond => {}
            FrameAction::ZcRead(_) => panic!("unexpected zc plan"),
            FrameAction::Close => panic!("unexpected close"),
        }
        assert!(tx.len() > 68, "no response produced");
        let nbt = ((tx[1] as usize) << 16) | ((tx[2] as usize) << 8) | tx[3] as usize;
        assert_eq!(nbt, tx.len() - 4, "NBT length mismatch");
        let h = &tx[4..68];
        Resp {
            status: u32::from_le_bytes(h[8..12].try_into().unwrap()),
            tree_id: u32::from_le_bytes(h[36..40].try_into().unwrap()),
            session_id: u64::from_le_bytes(h[40..48].try_into().unwrap()),
            body: tx[68..].to_vec(),
        }
    }

    fn establish(srv: &Srv, pc: &mut ProtoConn) -> (u64, u32) {
        // NEGOTIATE offering 2.1 / 3.0 / 3.0.2
        let mut f = req_hdr(CMD_NEGOTIATE, 0, 0, 0);
        f.p16(36);
        f.p16(3);
        f.p16(1);
        f.p16(0);
        f.p32(0);
        f.zeros(16 + 8);
        f.p16(0x0210);
        f.p16(0x0300);
        f.p16(0x0302);
        let r = roundtrip(srv, pc, f);
        assert_eq!(r.status, status::SUCCESS);
        let dialect = u16::from_le_bytes(r.body[4..6].try_into().unwrap());
        assert_eq!(dialect, 0x0302);

        // SESSION_SETUP: NTLMSSP NEGOTIATE → challenge
        let mut blob = crate::ntlm::SIG.to_vec();
        blob.extend_from_slice(&1u32.to_le_bytes());
        let mut f = req_hdr(CMD_SESSION_SETUP, 1, 0, 0);
        f.p16(25);
        f.p8(0);
        f.p8(1);
        f.p32(0);
        f.p32(0);
        f.p16(88);
        f.p16(blob.len() as u16);
        f.p64(0);
        f.pbytes(&blob);
        let r = roundtrip(srv, pc, f);
        assert_eq!(r.status, status::MORE_PROCESSING_REQUIRED);
        let sess = r.session_id;
        assert_ne!(sess, 0);

        // SESSION_SETUP: NTLMSSP AUTHENTICATE → guest session
        let mut blob = crate::ntlm::SIG.to_vec();
        blob.extend_from_slice(&3u32.to_le_bytes());
        let mut f = req_hdr(CMD_SESSION_SETUP, 2, 0, sess);
        f.p16(25);
        f.p8(0);
        f.p8(1);
        f.p32(0);
        f.p32(0);
        f.p16(88);
        f.p16(blob.len() as u16);
        f.p64(0);
        f.pbytes(&blob);
        let r = roundtrip(srv, pc, f);
        assert_eq!(r.status, status::SUCCESS);

        // TREE_CONNECT \\srv\t
        let path = utf16le("\\\\srv\\t");
        let mut f = req_hdr(CMD_TREE_CONNECT, 3, 0, sess);
        f.p16(9);
        f.p16(0);
        f.p16(72);
        f.p16(path.len() as u16);
        f.pbytes(&path);
        let r = roundtrip(srv, pc, f);
        assert_eq!(r.status, status::SUCCESS);
        (sess, r.tree_id)
    }

    fn create_file(srv: &Srv, pc: &mut ProtoConn, sess: u64, tree: u32, name: &str, disp: u32, opts: u32, desired: u32) -> (u32, u64) {
        let n = utf16le(name);
        let mut f = req_hdr(CMD_CREATE, 10, tree, sess);
        f.p16(57);
        f.p8(0);
        f.p8(0);
        f.p32(2);
        f.p64(0);
        f.p64(0);
        f.p32(desired);
        f.p32(0);
        f.p32(7);
        f.p32(disp);
        f.p32(opts);
        f.p16(120);
        f.p16(n.len() as u16);
        f.p32(0);
        f.p32(0);
        f.pbytes(&n);
        let r = roundtrip(srv, pc, f);
        let fid = if r.status == status::SUCCESS {
            u64::from_le_bytes(r.body[72..80].try_into().unwrap())
        } else {
            0
        };
        (r.status, fid)
    }

    #[test]
    fn full_session_create_write_read_dir() {
        let dir = std::env::temp_dir().join(format!("rsmbd-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let srv = test_srv(&dir);
        let mut pc = ProtoConn::new(&srv, 0, 0, 1);
        let (sess, tree) = establish(&srv, &mut pc);

        // CREATE hello.txt (overwrite-if, generic all)
        let (st, fid) = create_file(&srv, &mut pc, sess, tree, "hello.txt", 5, 0x40, 0x1000_0000);
        assert_eq!(st, status::SUCCESS);

        // WRITE "rocket data"
        let data = b"rocket data";
        let mut f = req_hdr(CMD_WRITE, 11, tree, sess);
        f.p16(49);
        f.p16(112);
        f.p32(data.len() as u32);
        f.p64(0);
        f.p64(fid);
        f.p64(fid);
        f.p32(0);
        f.p32(0);
        f.p16(0);
        f.p16(0);
        f.p32(0);
        f.pbytes(data);
        let r = roundtrip(&srv, &mut pc, f);
        assert_eq!(r.status, status::SUCCESS);
        let count = u32::from_le_bytes(r.body[4..8].try_into().unwrap());
        assert_eq!(count as usize, data.len());

        // READ it back (small read → buffered path)
        let mut f = req_hdr(CMD_READ, 12, tree, sess);
        f.p16(49);
        f.p8(0);
        f.p8(0);
        f.p32(1024);
        f.p64(0);
        f.p64(fid);
        f.p64(fid);
        f.p32(0);
        f.p32(0);
        f.p32(0);
        f.p16(0);
        f.p16(0);
        f.p8(0);
        let r = roundtrip(&srv, &mut pc, f);
        assert_eq!(r.status, status::SUCCESS);
        let dlen = u32::from_le_bytes(r.body[4..8].try_into().unwrap()) as usize;
        assert_eq!(&r.body[16..16 + dlen], data);

        // CLOSE
        let mut f = req_hdr(CMD_CLOSE, 13, tree, sess);
        f.p16(24);
        f.p16(1);
        f.p32(0);
        f.p64(fid);
        f.p64(fid);
        let r = roundtrip(&srv, &mut pc, f);
        assert_eq!(r.status, status::SUCCESS);

        // Open share root and enumerate: must contain hello.txt
        let (st, dfid) = create_file(&srv, &mut pc, sess, tree, "", 1, 0x1, 0x8000_0000);
        assert_eq!(st, status::SUCCESS);
        let pat = utf16le("*");
        let mut f = req_hdr(CMD_QUERY_DIRECTORY, 14, tree, sess);
        f.p16(33);
        f.p8(37); // FileIdBothDirectoryInformation
        f.p8(0);
        f.p32(0);
        f.p64(dfid);
        f.p64(dfid);
        f.p16(96);
        f.p16(pat.len() as u16);
        f.p32(65536);
        f.pbytes(&pat);
        let r = roundtrip(&srv, &mut pc, f);
        assert_eq!(r.status, status::SUCCESS);
        let needle = utf16le("hello.txt");
        assert!(
            r.body.windows(needle.len()).any(|w| w == &needle[..]),
            "directory listing must contain hello.txt"
        );

        // Traversal must be rejected
        let (st, _) = create_file(&srv, &mut pc, sess, tree, "..\\evil", 1, 0x40, 0x8000_0000);
        assert_eq!(st, status::OBJECT_NAME_INVALID);

        // Large standalone READ must produce a zero-copy plan
        let (st, fid2) = create_file(&srv, &mut pc, sess, tree, "hello.txt", 1, 0x40, 0x8000_0000);
        assert_eq!(st, status::SUCCESS);
        let mut f = req_hdr(CMD_READ, 15, tree, sess);
        f.p16(49);
        f.p8(0);
        f.p8(0);
        f.p32(64 * 1024);
        f.p64(0);
        f.p64(fid2);
        f.p64(fid2);
        f.p32(0);
        f.p32(0);
        f.p32(0);
        f.p16(0);
        f.p16(0);
        f.p8(0);
        let mut tx = Vec::new();
        match process_frame(&srv, &mut pc, &f, &mut tx) {
            FrameAction::ZcRead(p) => {
                assert_eq!(p.length, 64 * 1024);
                assert_eq!(p.offset, 0);
                // Reactor-side header builder sanity
                let mut hdr = Vec::new();
                build_read_resp_prefix(&p, 11, &mut hdr);
                assert_eq!(hdr.len(), 4 + 64 + 16);
                let nbt = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
                assert_eq!(nbt, 80 + 11);
            }
            FrameAction::Respond => panic!("expected zero-copy plan for 64K read"),
            FrameAction::Close => panic!("unexpected close"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Full authenticated session over the wire: NTLMv2 challenge/response
    /// with a real user db, then a signed TREE_CONNECT whose response must
    /// carry a valid signature, and rejection of a wrong password.
    #[test]
    fn ntlmv2_auth_and_signing() {
        use crate::crypto;
        use crate::ntlm;

        let dir = std::env::temp_dir().join(format!("rsmbd-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut srv = test_srv(&dir);
        srv.cfg.users.push(crate::config::UserCfg {
            name: "glenn".into(),
            password: Some("s3cret".into()),
            nt_hash: None,
        });
        srv.users = srv.cfg.user_db();
        srv.allow_guest = srv.cfg.guest_allowed();
        assert!(!srv.allow_guest, "users defined → guest off by default");

        let mut pc = ProtoConn::new(&srv, 0, 0, 1);
        // NEGOTIATE 3.0.2
        let mut f = req_hdr(CMD_NEGOTIATE, 0, 0, 0);
        f.p16(36);
        f.p16(1);
        f.p16(1);
        f.p16(0);
        f.p32(0);
        f.zeros(16 + 8);
        f.p16(0x0302);
        let r = roundtrip(&srv, &mut pc, f);
        assert_eq!(r.status, status::SUCCESS);

        // Type 1 → challenge
        let mut blob = ntlm::SIG.to_vec();
        blob.extend_from_slice(&1u32.to_le_bytes());
        let mut f = req_hdr(CMD_SESSION_SETUP, 1, 0, 0);
        f.p16(25);
        f.p8(0);
        f.p8(1);
        f.p32(0);
        f.p32(0);
        f.p16(88);
        f.p16(blob.len() as u16);
        f.p64(0);
        f.pbytes(&blob);
        let r = roundtrip(&srv, &mut pc, f);
        assert_eq!(r.status, status::MORE_PROCESSING_REQUIRED);
        let sess = r.session_id;
        // Pull the server challenge out of the CHALLENGE token.
        let tok_off = r.body.len() - r.body
            .windows(8)
            .rev()
            .position(|w| w == ntlm::SIG)
            .map(|p| p + 8)
            .unwrap();
        let chal: [u8; 8] = r.body[tok_off + 24..tok_off + 32].try_into().unwrap();

        // Build a genuine NTLMv2 type 3 like a client would.
        let build_t3 = |password: &str| -> Vec<u8> {
            let nt = crypto::nt_hash(password);
            let mut id = crate::wire::utf16le("GLENN");
            id.extend_from_slice(&crate::wire::utf16le("WG"));
            let v2 = crypto::hmac_md5(&nt, &id);
            let mut temp = vec![1, 1, 0, 0, 0, 0, 0, 0];
            temp.extend_from_slice(&[0; 8]);
            temp.extend_from_slice(&[0x42; 8]);
            temp.extend_from_slice(&[0; 8]);
            let mut buf = chal.to_vec();
            buf.extend_from_slice(&temp);
            let proof = crypto::hmac_md5(&v2, &buf);
            let mut nt_resp = proof.to_vec();
            nt_resp.extend_from_slice(&temp);
            let user16 = crate::wire::utf16le("glenn");
            let dom16 = crate::wire::utf16le("WG");
            let mut m: Vec<u8> = Vec::new();
            m.pbytes(ntlm::SIG);
            m.p32(3);
            let mut off = 64usize;
            for len in [0usize, nt_resp.len(), dom16.len(), user16.len(), 0, 0] {
                m.p16(len as u16);
                m.p16(len as u16);
                m.p32(off as u32);
                off += len;
            }
            m.p32(0); // flags: no KEY_EXCH → session key = session base key
            m.pbytes(&nt_resp);
            m.pbytes(&dom16);
            m.pbytes(&user16);
            m
        };

        // Wrong password → LOGON_FAILURE
        let t3 = build_t3("wrong");
        let mut f = req_hdr(CMD_SESSION_SETUP, 2, 0, sess);
        f.p16(25);
        f.p8(0);
        f.p8(2); // client requires signing
        f.p32(0);
        f.p32(0);
        f.p16(88);
        f.p16(t3.len() as u16);
        f.p64(0);
        f.pbytes(&t3);
        let r = roundtrip(&srv, &mut pc, f);
        assert_eq!(r.status, status::LOGON_FAILURE);

        // Redo the handshake with the right password.
        let mut blob = ntlm::SIG.to_vec();
        blob.extend_from_slice(&1u32.to_le_bytes());
        let mut f = req_hdr(CMD_SESSION_SETUP, 3, 0, 0);
        f.p16(25);
        f.p8(0);
        f.p8(1);
        f.p32(0);
        f.p32(0);
        f.p16(88);
        f.p16(blob.len() as u16);
        f.p64(0);
        f.pbytes(&blob);
        let r = roundtrip(&srv, &mut pc, f);
        let sess = r.session_id;
        let tok_off = r.body.len() - r.body
            .windows(8)
            .rev()
            .position(|w| w == ntlm::SIG)
            .map(|p| p + 8)
            .unwrap();
        let chal2: [u8; 8] = r.body[tok_off + 24..tok_off + 32].try_into().unwrap();
        // Rebind the closure's challenge by shadowing.
        let chal = chal2;
        let t3 = {
            let nt = crypto::nt_hash("s3cret");
            let mut id = crate::wire::utf16le("GLENN");
            id.extend_from_slice(&crate::wire::utf16le("WG"));
            let v2 = crypto::hmac_md5(&nt, &id);
            let mut temp = vec![1, 1, 0, 0, 0, 0, 0, 0];
            temp.extend_from_slice(&[0; 8]);
            temp.extend_from_slice(&[0x42; 8]);
            temp.extend_from_slice(&[0; 8]);
            let mut buf = chal.to_vec();
            buf.extend_from_slice(&temp);
            let proof = crypto::hmac_md5(&v2, &buf);
            let mut nt_resp = proof.to_vec();
            nt_resp.extend_from_slice(&temp);
            // Session base key the server will derive too.
            let _sbk = crypto::hmac_md5(&v2, &proof);
            let user16 = crate::wire::utf16le("glenn");
            let dom16 = crate::wire::utf16le("WG");
            let mut m: Vec<u8> = Vec::new();
            m.pbytes(ntlm::SIG);
            m.p32(3);
            let mut off = 64usize;
            for len in [0usize, nt_resp.len(), dom16.len(), user16.len(), 0, 0] {
                m.p16(len as u16);
                m.p16(len as u16);
                m.p32(off as u32);
                off += len;
            }
            m.p32(0);
            m.pbytes(&nt_resp);
            m.pbytes(&dom16);
            m.pbytes(&user16);
            m
        };
        let mut f = req_hdr(CMD_SESSION_SETUP, 4, 0, sess);
        f.p16(25);
        f.p8(0);
        f.p8(2);
        f.p32(0);
        f.p32(0);
        f.p16(88);
        f.p16(t3.len() as u16);
        f.p64(0);
        f.pbytes(&t3);
        let r = roundtrip(&srv, &mut pc, f);
        assert_eq!(r.status, status::SUCCESS);
        // Final session setup response on a signing-required session must
        // itself be signed. Signing is per-channel; guest is session-wide.
        let ch = pc.channels.get(&sess).unwrap();
        assert!(ch.sign.is_some());
        assert!(ch.signing_required);
        assert!(!srv.sessions.get(sess).unwrap().lock().unwrap().guest);

        // Unsigned TREE_CONNECT on a signing-required session → rejected.
        let path16 = utf16le("\\\\srv\\t");
        let mut f = req_hdr(CMD_TREE_CONNECT, 5, 0, sess);
        f.p16(9);
        f.p16(0);
        f.p16(72);
        f.p16(path16.len() as u16);
        f.pbytes(&path16);
        let r = roundtrip(&srv, &mut pc, f);
        assert_eq!(r.status, status::ACCESS_DENIED);

        // Properly signed TREE_CONNECT must succeed, and the response must
        // verify under the same key.
        let sc = pc.channels.get(&sess).unwrap().sign.clone().unwrap();
        let mut f = req_hdr(CMD_TREE_CONNECT, 6, 0, sess);
        f.p16(9);
        f.p16(0);
        f.p16(72);
        f.p16(path16.len() as u16);
        f.pbytes(&path16);
        // Set SIGNED flag and compute the signature.
        let flags = u32::from_le_bytes(f[16..20].try_into().unwrap()) | FLAG_SIGNED;
        f[16..20].copy_from_slice(&flags.to_le_bytes());
        let sig = crate::crypto::smb2_signature(sc.alg, &sc.key, &[&f[..48], &[0; 16], &f[64..]]);
        f[48..64].copy_from_slice(&sig);
        let mut tx = Vec::new();
        match process_frame(&srv, &mut pc, &f, &mut tx) {
            FrameAction::Respond => {}
            _ => panic!(),
        }
        let st = u32::from_le_bytes(tx[12..16].try_into().unwrap());
        assert_eq!(st, status::SUCCESS);
        let rflags = u32::from_le_bytes(tx[20..24].try_into().unwrap());
        assert_ne!(rflags & FLAG_SIGNED, 0, "response must be signed");
        assert!(verify_signature(&tx[4..], &sc), "response signature must verify");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Drive a real SMB 3.1.1 handshake and independently recompute the
    /// preauth integrity chain + signing key from the exact transmitted
    /// bytes, then verify the final SESSION_SETUP response signature. This
    /// catches preauth/key-derivation divergence that real clients reject.
    #[test]
    fn smb311_preauth_signing() {
        use crate::crypto;
        use crate::ntlm;

        let dir = std::env::temp_dir().join(format!("rsmbd-311-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut srv = test_srv(&dir);
        srv.cfg.users.push(crate::config::UserCfg {
            name: "u".into(),
            password: Some("pw".into()),
            nt_hash: None,
        });
        srv.users = srv.cfg.user_db();
        srv.allow_guest = srv.cfg.guest_allowed();
        let mut pc = ProtoConn::new(&srv, 0, 0, 1);

        // --- NEGOTIATE with a 3.1.1 preauth-integrity context (SHA-512) ---
        let mut neg = req_hdr(CMD_NEGOTIATE, 0, 0, 0);
        let neg_body = neg.len();
        neg.p16(36);
        neg.p16(1); // dialect count
        neg.p16(1); // signing enabled
        neg.p16(0);
        neg.p32(0);
        neg.zeros(16); // client guid
        // NegotiateContextOffset/Count/Reserved filled after we know layout.
        let ncoff_pos = neg.len();
        neg.p32(0); // ctx offset
        neg.p16(1); // ctx count
        neg.p16(0);
        neg.p16(0x0311); // dialect
                         // pad to 8 from header start
        while (neg.len() - neg_body) % 8 != 0 {
            neg.p16(0);
        }
        let ctx_off = neg.len() - 0; // offset from SMB2 header start (frame base)
        // PREAUTH_INTEGRITY_CAPABILITIES context
        neg.p16(1); // type
        neg.p16(38); // data length
        neg.p32(0);
        neg.p16(1); // 1 hash algo
        neg.p16(32); // salt len
        neg.p16(1); // SHA-512
        neg.zeros(32); // salt
        neg[ncoff_pos..ncoff_pos + 4].copy_from_slice(&(ctx_off as u32).to_le_bytes());

        // Capture transmitted bytes to recompute preauth independently.
        let mut tx = Vec::new();
        assert!(matches!(
            process_frame(&srv, &mut pc, &neg, &mut tx),
            FrameAction::Respond
        ));
        let neg_resp = tx[4..].to_vec(); // strip NBT
        // dialect = body offset 4 → message offset 64 + 4
        let dialect = u16::from_le_bytes(neg_resp[68..70].try_into().unwrap());
        assert_eq!(dialect, 0x0311);

        let h1 = crypto::sha512(&[&[0u8; 64], &neg[..]]);
        let mut preauth = crypto::sha512(&[&h1, &neg_resp]);

        // --- SESSION_SETUP type 1 ---
        let mut blob = ntlm::SIG.to_vec();
        blob.extend_from_slice(&1u32.to_le_bytes());
        let mut ss1 = req_hdr(CMD_SESSION_SETUP, 1, 0, 0);
        ss1.p16(25);
        ss1.p8(0);
        ss1.p8(1);
        ss1.p32(0);
        ss1.p32(0);
        ss1.p16(88);
        ss1.p16(blob.len() as u16);
        ss1.p64(0);
        ss1.pbytes(&blob);
        let mut tx = Vec::new();
        process_frame(&srv, &mut pc, &ss1, &mut tx);
        let ss1_resp = tx[4..].to_vec();
        let sess = u64::from_le_bytes(ss1_resp[40..48].try_into().unwrap());
        preauth = crypto::sha512(&[&preauth, &ss1[..]]);
        preauth = crypto::sha512(&[&preauth, &ss1_resp]);
        // server challenge
        let toff = ss1_resp.len()
            - ss1_resp.windows(8).rev().position(|w| w == ntlm::SIG).map(|p| p + 8).unwrap();
        let chal: [u8; 8] = ss1_resp[toff + 24..toff + 32].try_into().unwrap();

        // --- SESSION_SETUP type 3 (NTLMv2) ---
        let nt = crypto::nt_hash("pw");
        let mut id = crate::wire::utf16le("U");
        id.extend_from_slice(&crate::wire::utf16le(""));
        let v2 = crypto::hmac_md5(&nt, &id);
        let mut temp = vec![1u8, 1, 0, 0, 0, 0, 0, 0];
        temp.extend_from_slice(&[0; 8]);
        temp.extend_from_slice(&[0x33; 8]);
        temp.extend_from_slice(&[0; 8]);
        let mut pb = chal.to_vec();
        pb.extend_from_slice(&temp);
        let proof = crypto::hmac_md5(&v2, &pb);
        let mut nt_resp = proof.to_vec();
        nt_resp.extend_from_slice(&temp);
        let session_base = crypto::hmac_md5(&v2, &proof);

        let user16 = crate::wire::utf16le("u");
        let mut t3 = ntlm::SIG.to_vec();
        t3.p32(3);
        let mut off = 64usize;
        for len in [0usize, nt_resp.len(), 0, user16.len(), 0, 0] {
            t3.p16(len as u16);
            t3.p16(len as u16);
            t3.p32(off as u32);
            off += len;
        }
        t3.p32(0); // flags: no KEY_EXCH → session key = session base key
        t3.pbytes(&nt_resp);
        t3.pbytes(&user16);

        let mut ss3 = req_hdr(CMD_SESSION_SETUP, 2, 0, sess);
        ss3.p16(25);
        ss3.p8(0);
        ss3.p8(1);
        ss3.p32(0);
        ss3.p32(0);
        ss3.p16(88);
        ss3.p16(t3.len() as u16);
        ss3.p64(0);
        ss3.pbytes(&t3);

        // Preauth for the signing key includes ss_req2 (but NOT ss_resp2).
        preauth = crypto::sha512(&[&preauth, &ss3[..]]);
        let expect_key = crypto::kdf128(&session_base, b"SMBSigningKey\0", &preauth);
        let expect_sc = SignCtx { alg: SignAlg::AesCmac, key: expect_key };

        let mut tx = Vec::new();
        process_frame(&srv, &mut pc, &ss3, &mut tx);
        let st = u32::from_le_bytes(tx[12..16].try_into().unwrap());
        assert_eq!(st, status::SUCCESS, "auth should succeed");

        // The server's stored signing key must match the independent one.
        let server_sc = pc.channels.get(&sess).unwrap().sign.clone().unwrap();
        assert_eq!(server_sc.key, expect_sc.key, "3.1.1 signing key mismatch");

        // And the final SS response must verify under the independent key.
        let rflags = u32::from_le_bytes(tx[20..24].try_into().unwrap());
        assert_ne!(rflags & FLAG_SIGNED, 0, "final SS response must be signed");
        assert!(
            verify_signature(&tx[4..], &expect_sc),
            "final SS response signature must verify under spec-derived key"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transform_roundtrip_and_tamper() {
        use crate::crypto::{
            CIPHER_AES128_CCM, CIPHER_AES128_GCM, CIPHER_AES256_CCM, CIPHER_AES256_GCM,
        };
        for cipher in [CIPHER_AES128_GCM, CIPHER_AES256_GCM, CIPHER_AES128_CCM, CIPHER_AES256_CCM] {
            // Same key for c2s/s2c so wrap (s2c) round-trips through
            // decrypt_transform (c2s) in one process. 32-byte buffers; the
            // codec uses the first cipher_key_len bytes.
            let mut enc =
                EncCtx { cipher, c2s: [3u8; 32], s2c: [3u8; 32], nonce_ctr: 0 };
            let plain = b"\xfeSMBplaintext-inner-smb2-message-bytes-0123456789".to_vec();
            let mut tx = Vec::new();
            wrap_transform(&plain, &mut enc, 0xABCD, &mut tx);
            let frame = &tx[4..]; // strip NBT prefix
            assert!(is_transform(frame));
            assert_eq!(u64::from_le_bytes(frame[44..52].try_into().unwrap()), 0xABCD);
            assert_eq!(enc.nonce_ctr, 1, "nonce counter advances ({cipher:#x})");

            let dec = decrypt_transform(frame, &enc).expect("decrypt ok");
            assert_eq!(dec, plain, "decrypt recovers inner ({cipher:#x})");

            let mut bad = frame.to_vec();
            let n = bad.len();
            bad[n - 1] ^= 1;
            assert!(decrypt_transform(&bad, &enc).is_none(), "tamper detected ({cipher:#x})");
        }
    }

    #[test]
    fn process_frame_appends_for_batching() {
        let dir = std::env::temp_dir().join(format!("rsmbd-batch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let srv = test_srv(&dir);
        let mut pc = ProtoConn::new(&srv, 0, 0, 1);

        // Two ECHO frames processed into the same tx buffer must yield two
        // complete, independently-framed responses.
        let mut echo = req_hdr(CMD_ECHO, 7, 0, 0);
        echo.p16(4);
        echo.p16(0);
        let mut tx = Vec::new();
        for _ in 0..2 {
            match process_frame(&srv, &mut pc, &echo, &mut tx) {
                FrameAction::Respond => {}
                _ => panic!("echo must respond"),
            }
        }
        // Walk both NBT frames.
        let mut off = 0;
        for _ in 0..2 {
            let nbt = ((tx[off + 1] as usize) << 16) | ((tx[off + 2] as usize) << 8)
                | tx[off + 3] as usize;
            let status =
                u32::from_le_bytes(tx[off + 4 + 8..off + 4 + 12].try_into().unwrap());
            assert_eq!(status, status::SUCCESS);
            off += 4 + nbt;
        }
        assert_eq!(off, tx.len(), "exactly two framed responses");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
