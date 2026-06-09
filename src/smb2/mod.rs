//! SMB2 core: header codec, compound dispatch, connection protocol state.
//!
//! The reactor feeds complete NetBIOS-framed messages to [`process_frame`]
//! and sends back whatever lands in `tx`. A standalone READ becomes a
//! [`FrameAction::ZcRead`] plan that the reactor serves zero-copy via
//! splice; everything else is answered from the tx buffer.

pub mod handlers;

use std::collections::HashMap;
use std::os::fd::RawFd;

use crate::config::Srv;
use crate::status;
use crate::vfs::HandleTable;
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
pub const CMD_OPLOCK_BREAK: u16 = 18;

pub const FLAG_RESPONSE: u32 = 0x1;
pub const FLAG_ASYNC: u32 = 0x2;
pub const FLAG_RELATED: u32 = 0x4;
#[allow(dead_code)]
pub const FLAG_SIGNED: u32 = 0x8;

pub const MAX_TRANSACT: u32 = 1 << 20;
pub const MAX_WRITE: u32 = 1 << 20;
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
    let (tree_id, session_id);
    if flags & FLAG_ASYNC != 0 {
        let _async_id = r.u64()?;
        tree_id = 0;
        session_id = r.u64()?;
    } else {
        let _process_id = r.u32()?;
        tree_id = r.u32()?;
        session_id = r.u64()?;
    }
    r.skip(16)?; // signature
    Some(ReqHdr { credit_charge, command, credits, flags, next, msg_id, tree_id, session_id })
}

#[derive(Debug, Default)]
pub struct Session {
    pub trees: HashMap<u32, u32>, // tree_id -> share index
    pub next_tree_id: u32,
}

/// Per-connection protocol state. OS-independent and unit-testable; all
/// io_uring specifics live in the reactor.
pub struct ProtoConn {
    pub dialect: u16,
    pub sessions: HashMap<u64, Session>,
    pub handles: HandleTable,
    pub next_session_id: u64,
    pub max_read: u32,
}

impl ProtoConn {
    pub fn new(srv: &Srv, conn_seed: u64) -> Self {
        Self {
            dialect: 0,
            sessions: HashMap::new(),
            handles: HandleTable::default(),
            next_session_id: (conn_seed << 32) | 1,
            max_read: srv.max_read,
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
}

pub enum FrameAction {
    Respond,
    ZcRead(ZcReadPlan),
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
    tx.p16(h.credits.clamp(1, 512)); // credits granted
    tx.p32(FLAG_RESPONSE | if related { FLAG_RELATED } else { 0 });
    tx.p32(0); // NextCommand, patched by the chain loop
    tx.p64(h.msg_id);
    tx.p32(0); // process id
    tx.p32(tree_id);
    tx.p64(session_id);
    tx.zeros(16); // signature
    start
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
    }
}

fn finish_nbt_with(tx: &mut [u8], len: u32) {
    tx[0] = 0;
    tx[1] = ((len >> 16) & 0xFF) as u8;
    tx[2] = ((len >> 8) & 0xFF) as u8;
    tx[3] = (len & 0xFF) as u8;
}

/// Process one NetBIOS-framed message (without the 4-byte NBT prefix).
/// Responses are appended to `tx` including the NBT prefix; an empty `tx`
/// on return means "no response" (e.g. CANCEL).
pub fn process_frame(srv: &Srv, pc: &mut ProtoConn, frame: &[u8], tx: &mut Vec<u8>) -> FrameAction {
    tx.clear();
    tx.zeros(4); // NBT placeholder

    // Legacy SMB1 negotiate → wildcard SMB2 response (dialect 0x02FF).
    if frame.len() >= 4 && frame[0] == 0xFF && &frame[1..4] == b"SMB" {
        handlers::negotiate_resp_smb1_wildcard(srv, pc, tx);
        let total = (tx.len() - 4) as u32;
        finish_nbt_with(tx, total);
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

    loop {
        let Some(h) = parse_hdr(&frame[off..]) else {
            break;
        };
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
            tx.pad8(4);
            let here = tx.len();
            tx.patch32(p + 20, (here - p) as u32);
        }
        let resp_start = tx.len();
        if let Some(z) = handlers::dispatch(srv, pc, &h, msg, &mut chain, tx) {
            plan = Some(z);
        }
        if tx.len() > resp_start {
            prev_start = Some(resp_start);
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
        return FrameAction::ZcRead(p);
    }
    let total = (tx.len() - 4) as u32;
    if total == 0 {
        tx.clear(); // nothing to send
    } else {
        finish_nbt_with(tx, total);
    }
    FrameAction::Respond
}
