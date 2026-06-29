//! Kerberos GSS-API acceptor (#33, #34) — gated by the `kerberos` feature.
//!
//! Raw RFC 2744 C GSS-API via `gssapi-sys` (MIT krb5 / Heimdal at link time).
//! We bind the C API directly rather than a safe wrapper so the same
//! `gss_ctx_id_t` drives both `gss_accept_sec_context` and the
//! `gss_inquire_sec_context_by_oid` that extracts the SMB session key (the
//! Kerberos sub-session key).
//!
//! ## Build/validation status
//! This module compiles only with `--features kerberos`, which links the system
//! GSS library and therefore builds on a **Linux host** (krb5-devel /
//! libkrb5-dev), not the macOS cross-check host. The control flow and the GSS
//! call sequence follow RFC 2744 and the MS-SMB2 session-key derivation, but
//! the exact `gssapi-sys` symbol/const spellings and the session-key inquire
//! must be confirmed against the installed library on the Linux host (see
//! docs/KERBEROS.md §5–6). Threading: a `gss_cred_id_t` is not `Send`, so each
//! worker builds its own `Acceptor`; never share one across the reactor's
//! worker threads.

use std::ptr;

use gssapi_sys as gss;

// `gssapi-sys` binds only the base RFC 2744 `gssapi.h`. The session-key
// extraction needs three symbols from the MIT/Heimdal extension header
// (`gssapi_ext.h`) plus the `GSS_C_INDEFINITE` lifetime constant; declare them
// here. They are exported by `libgssapi_krb5` (linked via `gssapi-sys`).
const GSS_C_INDEFINITE: gss::OM_uint32 = 0xffff_ffff;

#[repr(C)]
struct GssBufferSetDesc {
    count: usize, // size_t
    elements: *mut gss::gss_buffer_desc,
}
type GssBufferSetT = *mut GssBufferSetDesc;

extern "C" {
    fn gss_inquire_sec_context_by_oid(
        minor_status: *mut gss::OM_uint32,
        context_handle: gss::gss_ctx_id_t,
        desired_object: gss::gss_OID,
        data_set: *mut GssBufferSetT,
    ) -> gss::OM_uint32;
    fn gss_release_buffer_set(
        minor_status: *mut gss::OM_uint32,
        buffer_set: *mut GssBufferSetT,
    ) -> gss::OM_uint32;
}

/// `GSS_C_INQ_SSPI_SESSION_KEY` — the inquire OID whose first buffer is the
/// established context's session key (the Kerberos sub-session key SMB signs
/// and seals with). OID 1.2.840.113554.1.2.2.5.5.
const SESSION_KEY_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02, 0x05, 0x05];

/// Result of feeding one client token to the acceptor.
pub enum Step {
    /// More legs needed; send this token back with MORE_PROCESSING_REQUIRED.
    Continue(Vec<u8>),
    /// Context established.
    Done(Established),
    /// Authentication failed; the string is a log-worthy reason.
    Failed(String),
}

/// A completed Kerberos authentication.
pub struct Established {
    /// Authenticated client principal, e.g. `alice@EXAMPLE.COM`.
    pub client: String,
    /// SMB session key (Kerberos sub-session key). Fed to the existing
    /// SP800-108 KDF for signing/encryption keys, exactly like the NTLM key.
    pub session_key: Vec<u8>,
    /// Final output token (AP-REP) to return, if any.
    pub out: Vec<u8>,
}

/// Per-worker acceptor holding the service credential acquired from the keytab.
pub struct Acceptor {
    cred: gss::gss_cred_id_t,
}

// The credential handle is owned by this worker's Acceptor and only touched on
// that worker's thread; we never move it across threads.
unsafe impl Send for Acceptor {}

impl Acceptor {
    /// Acquire the acceptor credential for `spn` (e.g. `cifs/host.example.com`)
    /// from `keytab` (or the default keytab / `$KRB5_KTNAME` when `None`).
    pub fn new(spn: &str, keytab: Option<&std::path::Path>) -> Result<Acceptor, String> {
        // The keytab is selected per-process via the krb5 env var; set it
        // before acquiring the credential so the GSS layer reads from it.
        if let Some(kt) = keytab {
            std::env::set_var("KRB5_KTNAME", kt);
        }
        unsafe {
            // Import the SPN. SMB SPNs are `service/host`; the GSS hostbased
            // form is `service@host`, so translate the first `/`.
            let hostbased = spn.replacen('/', "@", 1);
            let name = import_name(&hostbased)?;
            let mut cred: gss::gss_cred_id_t = ptr::null_mut();
            let mut minor: gss::OM_uint32 = 0;
            let major = gss::gss_acquire_cred(
                &mut minor,
                name,
                GSS_C_INDEFINITE,
                ptr::null_mut(),               // desired mechs: default set
                gss::GSS_C_ACCEPT as i32,
                &mut cred,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            release_name(name);
            if major != gss::GSS_S_COMPLETE {
                return Err(format!("gss_acquire_cred({hostbased}) failed: {}", status_str(major, minor)));
            }
            Ok(Acceptor { cred })
        }
    }

    /// Begin a new per-session context.
    pub fn begin(&self) -> AcceptCtx<'_> {
        AcceptCtx { acc: self, ctx: ptr::null_mut() }
    }
}

impl Drop for Acceptor {
    fn drop(&mut self) {
        unsafe {
            let mut minor: gss::OM_uint32 = 0;
            gss::gss_release_cred(&mut minor, &mut self.cred);
        }
    }
}

/// An in-progress acceptor context for one SMB session/channel.
pub struct AcceptCtx<'a> {
    acc: &'a Acceptor,
    ctx: gss::gss_ctx_id_t,
}

impl AcceptCtx<'_> {
    /// Feed one client token (the GSS AP-REQ, unwrapped from SPNEGO by
    /// `spnego::classify`). On completion, extracts the session key.
    pub fn step(&mut self, token: &[u8]) -> Step {
        unsafe {
            let mut minor: gss::OM_uint32 = 0;
            let mut input = buf_from(token);
            let mut output = empty_buf();
            let mut src_name: gss::gss_name_t = ptr::null_mut();
            let mut ret_flags: gss::OM_uint32 = 0;
            let major = gss::gss_accept_sec_context(
                &mut minor,
                &mut self.ctx,
                self.acc.cred,
                &mut input,
                ptr::null_mut(),               // no channel bindings
                &mut src_name,
                ptr::null_mut(),               // mech type: don't care
                &mut output,
                &mut ret_flags,
                ptr::null_mut(),               // time_rec
                ptr::null_mut(),               // delegated cred
            );
            let out = take_buf(&mut output);

            if major == gss::GSS_S_COMPLETE {
                let client = display_name(src_name);
                release_name(src_name);
                match self.session_key() {
                    Ok(session_key) => Step::Done(Established { client, session_key, out }),
                    Err(e) => Step::Failed(format!("session-key inquire failed: {e}")),
                }
            } else if major & gss::GSS_S_CONTINUE_NEEDED != 0 {
                release_name(src_name);
                Step::Continue(out)
            } else {
                release_name(src_name);
                Step::Failed(format!("gss_accept_sec_context failed: {}", status_str(major, minor)))
            }
        }
    }

    /// Extract the session key via `gss_inquire_sec_context_by_oid`.
    fn session_key(&self) -> Result<Vec<u8>, String> {
        unsafe {
            let mut minor: gss::OM_uint32 = 0;
            let mut oid_val = SESSION_KEY_OID.to_vec();
            let oid = gss::gss_OID_desc {
                length: oid_val.len() as gss::OM_uint32,
                elements: oid_val.as_mut_ptr() as *mut _,
            };
            let mut set: GssBufferSetT = ptr::null_mut();
            let major = gss_inquire_sec_context_by_oid(
                &mut minor,
                self.ctx,
                &oid as *const _ as gss::gss_OID,
                &mut set,
            );
            if major != gss::GSS_S_COMPLETE || set.is_null() || (*set).count == 0 {
                return Err(status_str(major, minor));
            }
            let b = &*(*set).elements;
            let key = std::slice::from_raw_parts(b.value as *const u8, b.length as usize).to_vec();
            gss_release_buffer_set(&mut minor, &mut set);
            if key.is_empty() {
                return Err("empty session key".into());
            }
            Ok(key)
        }
    }
}

impl Drop for AcceptCtx<'_> {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                let mut minor: gss::OM_uint32 = 0;
                gss::gss_delete_sec_context(&mut minor, &mut self.ctx, ptr::null_mut());
            }
        }
    }
}

// ----------------------------------------------------------- FFI helper glue

unsafe fn import_name(s: &str) -> Result<gss::gss_name_t, String> {
    let mut minor: gss::OM_uint32 = 0;
    let mut bytes = s.as_bytes().to_vec();
    let mut nb = gss::gss_buffer_desc {
        length: bytes.len() as usize,
        value: bytes.as_mut_ptr() as *mut _,
    };
    let mut name: gss::gss_name_t = ptr::null_mut();
    // GSS_C_NT_HOSTBASED_SERVICE — `service@host`.
    let major = gss::gss_import_name(
        &mut minor,
        &mut nb,
        gss::GSS_C_NT_HOSTBASED_SERVICE,
        &mut name,
    );
    if major != gss::GSS_S_COMPLETE {
        return Err(format!("gss_import_name({s}) failed: {}", status_str(major, minor)));
    }
    Ok(name)
}

unsafe fn release_name(mut name: gss::gss_name_t) {
    if !name.is_null() {
        let mut minor: gss::OM_uint32 = 0;
        gss::gss_release_name(&mut minor, &mut name);
    }
}

unsafe fn display_name(name: gss::gss_name_t) -> String {
    if name.is_null() {
        return String::new();
    }
    let mut minor: gss::OM_uint32 = 0;
    let mut out = empty_buf();
    let mut oid: gss::gss_OID = ptr::null_mut();
    if gss::gss_display_name(&mut minor, name, &mut out, &mut oid) != gss::GSS_S_COMPLETE {
        return String::new();
    }
    let s = String::from_utf8_lossy(std::slice::from_raw_parts(
        out.value as *const u8,
        out.length as usize,
    ))
    .into_owned();
    gss::gss_release_buffer(&mut minor, &mut out);
    s
}

unsafe fn buf_from(b: &[u8]) -> gss::gss_buffer_desc {
    gss::gss_buffer_desc {
        length: b.len() as usize,
        value: b.as_ptr() as *mut _,
    }
}

unsafe fn empty_buf() -> gss::gss_buffer_desc {
    gss::gss_buffer_desc { length: 0, value: ptr::null_mut() }
}

/// Copy an output buffer to a Vec and release the GSS-allocated storage.
unsafe fn take_buf(b: &mut gss::gss_buffer_desc) -> Vec<u8> {
    if b.value.is_null() || b.length == 0 {
        return Vec::new();
    }
    let v = std::slice::from_raw_parts(b.value as *const u8, b.length as usize).to_vec();
    let mut minor: gss::OM_uint32 = 0;
    gss::gss_release_buffer(&mut minor, b);
    v
}

/// Format a GSS major/minor status pair for logs.
fn status_str(major: gss::OM_uint32, minor: gss::OM_uint32) -> String {
    format!("major=0x{major:08x} minor=0x{minor:08x}")
}
