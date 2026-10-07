//! Live Kerberos SESSION_SETUP against a real KDC (#38), in process: a GSS
//! initiator (the system library, as a client would use it) talks to
//! rocketsmbd's `process_frame`. Covers the single-leg exchange cifs.ko and
//! Windows use, and a DCE-style exchange, where MIT krb5 needs a third leg
//! (AP-REQ → AP-REP → AP-REP), so the acceptor context must survive across
//! SESSION_SETUP requests. The client side derives the SMB 3.1.1 signing key
//! independently and checks the server's final reply against it.
//!
//! Needs a KDC, a service keytab and a ticket cache, so it runs only when
//! `RSMBD_KRB5_TEST=1`; `deploy/krb5-local-test.sh` sets up a private MIT KDC
//! and runs it. Without that it passes as a no-op (and says so).
#![cfg(feature = "kerberos")]

use gssapi_sys as gss;
use rocketsmbd::config::Srv;
use rocketsmbd::crypto;
use rocketsmbd::smb2::{self, FrameAction, ProtoConn};
use rocketsmbd::status;
use rocketsmbd::wire::Put;
use std::ptr;

const GSS_C_MUTUAL_FLAG: u32 = 2;
const GSS_C_SEQUENCE_FLAG: u32 = 8;
const GSS_C_INTEG_FLAG: u32 = 32;
const GSS_C_DCE_STYLE: u32 = 4096;
/// GSS_C_INQ_SSPI_SESSION_KEY, as in src/krb5.rs.
const SESSION_KEY_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02, 0x05, 0x05];

#[repr(C)]
struct BufferSet {
    count: usize,
    elements: *mut gss::gss_buffer_desc,
}
extern "C" {
    fn gss_inquire_sec_context_by_oid(
        minor: *mut gss::OM_uint32,
        ctx: gss::gss_ctx_id_t,
        oid: gss::gss_OID,
        set: *mut *mut BufferSet,
    ) -> gss::OM_uint32;
}

fn enabled() -> bool {
    if std::env::var("RSMBD_KRB5_TEST").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("krb5_live: skipped (set RSMBD_KRB5_TEST=1; deploy/krb5-local-test.sh runs it)");
    false
}

fn spn_host() -> String {
    std::env::var("RSMBD_KRB5_HOST").unwrap_or_else(|_| "rsmbd.test".into())
}

fn server() -> Srv {
    rocketsmbd::log::set_level(2);
    let dir = std::env::temp_dir().join(format!("rsmbd-krb5-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    rocketsmbd::fuzzing::srv_from_toml(&format!(
        "server_name = \"KRBTEST\"\nworkers = 1\nauth = \"kerberos\"\nallow_guest = false\n\
         require_signing = true\ncore_pinning = false\n\
         [kerberos]\nspn = \"cifs/{}\"\n[[share]]\nname = \"t\"\npath = '{}'\n",
        spn_host(),
        dir.display()
    ))
}

/// The GSS initiator (client side).
struct Initiator {
    ctx: gss::gss_ctx_id_t,
    target: gss::gss_name_t,
    flags: u32,
}

impl Initiator {
    fn new(dce: bool) -> Initiator {
        let name = format!("cifs@{}", spn_host());
        let mut minor = 0;
        let mut bytes = name.into_bytes();
        let mut nb = gss::gss_buffer_desc { length: bytes.len(), value: bytes.as_mut_ptr() as *mut _ };
        let mut target: gss::gss_name_t = ptr::null_mut();
        // SAFETY: nb borrows `bytes` for the call; target is released in Drop.
        let major = unsafe { gss::gss_import_name(&mut minor, &mut nb, gss::GSS_C_NT_HOSTBASED_SERVICE, &mut target) };
        assert_eq!(major, gss::GSS_S_COMPLETE, "gss_import_name");
        let mut flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG;
        if dce {
            flags |= GSS_C_DCE_STYLE;
        }
        Initiator { ctx: ptr::null_mut(), target, flags }
    }

    /// One init step: (output token, complete?).
    fn step(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        let mut minor = 0;
        let mut inb = gss::gss_buffer_desc { length: input.len(), value: input.as_ptr() as *mut _ };
        let mut out = gss::gss_buffer_desc { length: 0, value: ptr::null_mut() };
        // SAFETY: inb borrows `input` (read-only to GSS); out is copied and
        // released; ctx and target are owned by self.
        let major = unsafe {
            gss::gss_init_sec_context(
                &mut minor,
                ptr::null_mut(), // default credential: the ticket cache
                &mut self.ctx,
                self.target,
                ptr::null_mut(), // default mech (krb5)
                self.flags,
                0,
                ptr::null_mut(),
                if input.is_empty() { ptr::null_mut() } else { &mut inb },
                ptr::null_mut(),
                &mut out,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        let tok = if out.value.is_null() {
            Vec::new()
        } else {
            // SAFETY: GSS returned `length` bytes at `value`; released below.
            unsafe { std::slice::from_raw_parts(out.value as *const u8, out.length).to_vec() }
        };
        // SAFETY: out was filled by GSS (or is empty) and is released once.
        unsafe { gss::gss_release_buffer(&mut minor, &mut out) };
        assert!(
            major == gss::GSS_S_COMPLETE || major == gss::GSS_S_CONTINUE_NEEDED,
            "gss_init_sec_context failed: major {major:#x} minor {minor}"
        );
        (tok, major == gss::GSS_S_COMPLETE)
    }

    fn session_key(&self) -> [u8; 16] {
        let mut minor = 0;
        let mut oid_val = SESSION_KEY_OID.to_vec();
        let mut oid = gss::gss_OID_desc { length: oid_val.len() as _, elements: oid_val.as_mut_ptr() as *mut _ };
        let mut set: *mut BufferSet = ptr::null_mut();
        // SAFETY: oid outlives the call; set is read, copied and not used after.
        unsafe {
            let major = gss_inquire_sec_context_by_oid(&mut minor, self.ctx, &mut oid, &mut set);
            assert_eq!(major, gss::GSS_S_COMPLETE, "initiator session key");
            let b = &*(*set).elements;
            let k = std::slice::from_raw_parts(b.value as *const u8, b.length);
            let mut key = [0u8; 16];
            key.copy_from_slice(&k[..16]);
            key
        }
    }
}

impl Drop for Initiator {
    fn drop(&mut self) {
        let mut minor = 0;
        // SAFETY: both handles are owned here and released once.
        unsafe {
            if !self.ctx.is_null() {
                gss::gss_delete_sec_context(&mut minor, &mut self.ctx, ptr::null_mut());
            }
            gss::gss_release_name(&mut minor, &mut self.target);
        }
    }
}

struct Conn {
    pc: ProtoConn,
    next_id: u64,
    preauth: [u8; 64],
}

fn hdr(cmd: u16, id: u64, sess: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.pbytes(&[0xFE, b'S', b'M', b'B']);
    v.p16(64);
    v.p16(1);
    v.p32(0);
    v.p16(cmd);
    v.p16(64);
    v.p32(0);
    v.p32(0);
    v.p64(id);
    v.p32(0);
    v.p32(0);
    v.p64(sess);
    v.zeros(16);
    v
}

impl Conn {
    fn send(&mut self, srv: &Srv, frame: &[u8]) -> Vec<u8> {
        let mut tx = Vec::new();
        assert!(matches!(smb2::process_frame(srv, &mut self.pc, frame, &mut tx), FrameAction::Respond));
        tx[4..].to_vec()
    }

    /// NEGOTIATE SMB 3.1.1 (SHA-512 preauth), signing required.
    fn negotiate(srv: &Srv) -> Conn {
        let mut c = Conn { pc: ProtoConn::new(srv, 0, 0, 1), next_id: 0, preauth: [0; 64] };
        let mut m = hdr(smb2::CMD_NEGOTIATE, 0, 0);
        c.next_id = 1;
        m.p16(36);
        m.p16(1);
        m.p16(3);
        m.p16(0);
        m.p32(0);
        m.zeros(16);
        let off_pos = m.len();
        m.p32(0);
        m.p16(1);
        m.p16(0);
        m.p16(0x0311);
        while m.len() % 8 != 0 {
            m.p8(0);
        }
        let off = m.len() as u32;
        m[off_pos..off_pos + 4].copy_from_slice(&off.to_le_bytes());
        m.p16(1);
        m.p16(38);
        m.p32(0);
        m.p16(1);
        m.p16(32);
        m.p16(1);
        m.zeros(32);
        let r = c.send(srv, &m);
        assert_eq!(u32::from_le_bytes(r[8..12].try_into().unwrap()), status::SUCCESS);
        let h0 = crypto::sha512(&[&[0u8; 64], &m]);
        c.preauth = crypto::sha512(&[&h0, &r]);
        c
    }

    /// One SESSION_SETUP leg with a raw GSS token. Returns (status, session
    /// id, security token, raw reply); the request (and an interim reply)
    /// go into the preauth hash the way the spec chains them.
    fn setup_leg(&mut self, srv: &Srv, sess: u64, token: &[u8]) -> (u32, u64, Vec<u8>, Vec<u8>) {
        let mut m = hdr(smb2::CMD_SESSION_SETUP, self.next_id, sess);
        self.next_id += 1;
        m.p16(25);
        m.p8(0);
        m.p8(2); // signing required
        m.p32(0);
        m.p32(0);
        m.p16(88);
        m.p16(token.len() as u16);
        m.p64(0);
        m.pbytes(token);
        self.preauth = crypto::sha512(&[&self.preauth, &m]);
        let r = self.send(srv, &m);
        let st = u32::from_le_bytes(r[8..12].try_into().unwrap());
        let sid = u64::from_le_bytes(r[40..48].try_into().unwrap());
        if st == status::MORE_PROCESSING_REQUIRED {
            self.preauth = crypto::sha512(&[&self.preauth, &r]);
        }
        let body = &r[64..];
        let (off, len) = (u16::from_le_bytes([body[4], body[5]]) as usize, u16::from_le_bytes([body[6], body[7]]) as usize);
        let tok = if len == 0 { Vec::new() } else { r[off..off + len].to_vec() };
        (st, sid, tok, r)
    }
}

/// Run a whole exchange; returns the number of SESSION_SETUP legs it took.
fn exchange(dce: bool) -> usize {
    let srv = server();
    let mut c = Conn::negotiate(&srv);
    let mut init = Initiator::new(dce);
    let (mut tok, mut client_done) = init.step(&[]);
    let mut sess = 0u64;
    for leg in 1..=4 {
        let (st, sid, reply_tok, raw) = c.setup_leg(&srv, sess, &tok);
        sess = sid;
        if !client_done && !reply_tok.is_empty() {
            let (t, done) = init.step(&reply_tok);
            tok = t;
            client_done = done;
        }
        match st {
            status::MORE_PROCESSING_REQUIRED => {
                assert!(!tok.is_empty(), "server wants more but the client has nothing to send");
                assert!(
                    c.pc.channels.get(&sess).is_some_and(|ch| ch.krb_pending.is_some()),
                    "partial GSS context kept on the channel"
                );
            }
            status::SUCCESS => {
                assert!(client_done, "server finished before the client");
                // Independent 3.1.1 signing key from the client's own GSS
                // session key and preauth hash: the final reply must verify.
                let sc = smb2::derive_sign_ctx(0x0311, &init.session_key(), &c.preauth);
                let flags = u32::from_le_bytes(raw[16..20].try_into().unwrap());
                assert_ne!(flags & smb2::FLAG_SIGNED, 0, "final SESSION_SETUP reply signed");
                assert!(smb2::verify_signature(&raw, &sc), "final reply verifies under the client-derived key");
                let s = srv.sessions.get(sess).expect("session registered");
                let s = s.lock().unwrap();
                assert!(s.established && s.kerberos && !s.guest);
                assert!(s.user.starts_with("alice@"), "principal {:?}", s.user);
                assert!(c.pc.channels.get(&sess).is_some_and(|ch| ch.krb_pending.is_none() && ch.established));
                assert_eq!(srv.sessions.len(), 1, "no stray sessions");
                return leg;
            }
            st => panic!("leg {leg}: SESSION_SETUP status {st:#x}"),
        }
    }
    panic!("exchange did not finish in 4 legs");
}

#[test]
fn single_leg_ap_req() {
    if !enabled() {
        return;
    }
    assert_eq!(exchange(false), 1, "a plain AP-REQ completes in one SESSION_SETUP");
}

#[test]
fn multi_leg_dce_style() {
    if !enabled() {
        return;
    }
    let legs = exchange(true);
    assert!(legs >= 2, "DCE style needs another leg (took {legs})");
}

/// A broken second leg fails the logon and drops the half-made session.
#[test]
fn multi_leg_bad_second_token() {
    if !enabled() {
        return;
    }
    let srv = server();
    let mut c = Conn::negotiate(&srv);
    let mut init = Initiator::new(true);
    let (tok, _) = init.step(&[]);
    let (st, sid, _, _) = c.setup_leg(&srv, 0, &tok);
    assert_eq!(st, status::MORE_PROCESSING_REQUIRED);
    assert_eq!(srv.sessions.len(), 1);
    let (st, _, _, _) = c.setup_leg(&srv, sid, b"\x60\x03garbage");
    assert_ne!(st, status::SUCCESS);
    assert_ne!(st, status::MORE_PROCESSING_REQUIRED);
    assert!(srv.sessions.get(sid).is_none(), "failed exchange drops its session");
    assert!(c.pc.channels.get(&sid).is_none());
}
