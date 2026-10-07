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

use crate::config::AcceptorName;

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

// SAFETY (FFI declarations): these prototypes match MIT krb5 `gssapi_ext.h`
// (and Heimdal) in types, argument order and return type; `GssBufferSetDesc`
// mirrors `gss_buffer_set_desc { size_t count; gss_buffer_desc *elements; }`.
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
    // RFC 6680 naming extensions (MIT `gssapi_ext.h`): read the `urn:mspac:`
    // attributes the krb5 mech exposes from the ticket's PAC (#40).
    fn gss_get_name_attribute(
        minor_status: *mut gss::OM_uint32,
        name: gss::gss_name_t,
        attr: *mut gss::gss_buffer_desc,
        authenticated: *mut i32,
        complete: *mut i32,
        value: *mut gss::gss_buffer_desc,
        display_value: *mut gss::gss_buffer_desc,
        more: *mut i32,
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
    /// The ticket's PAC LOGON_INFO (user + group SIDs) when the KDC is AD and
    /// the GSS library verified the PAC signature; `None` otherwise (an MIT
    /// KDC issues no LOGON_INFO). Feeds per-share `@group` checks (#40).
    pub pac: Option<crate::pac::LogonInfo>,
    /// Final output token (AP-REP) to return, if any.
    pub out: Vec<u8>,
}

/// Per-worker acceptor holding the service credential acquired from the keytab.
pub struct Acceptor {
    cred: gss::gss_cred_id_t,
}

// SAFETY: a gss_cred_id_t has no thread affinity in MIT/Heimdal, so moving the
// owning Acceptor to another thread is fine; Acceptor is !Sync, so the handle is
// never used from two threads at once (in practice it stays on one worker).
unsafe impl Send for Acceptor {}

/// Point the GSS library at the configured keytab (`KRB5_KTNAME`). Must be
/// called once at startup, before any worker or health thread exists:
/// `setenv` while another thread calls C `getenv` (GSS does, per accept) is a
/// use-after-free in glibc.
pub fn set_keytab_env(keytab: Option<&std::path::Path>) {
    if let Some(kt) = keytab {
        std::env::set_var("KRB5_KTNAME", kt);
    }
}

/// GSS_KRB5_NT_PRINCIPAL_NAME (1.2.840.113554.1.2.2.1): a Kerberos principal
/// name, `service/host@REALM`. Spelled out here rather than linked because
/// MIT exports it as a variable and Heimdal as a macro over a private symbol.
const NT_KRB5_PRINCIPAL_OID: [u8; 10] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02, 0x01];

impl Acceptor {
    /// Acquire the acceptor credential for `name` (see
    /// `Config::krb_acceptor_name`) from the keytab `$KRB5_KTNAME` names (set
    /// once at startup by [`set_keytab_env`]) or the system default keytab.
    /// A `Principal` name must be in the keytab exactly, realm included.
    pub fn new(name: &AcceptorName) -> Result<Acceptor, String> {
        // SAFETY: name is released on every path; cred is only wrapped in an
        // Acceptor on GSS_S_COMPLETE. Optional out-params are NULL.
        unsafe {
            let (shown, name) = match name {
                AcceptorName::HostBased(n) => (n, import_name(n, gss::GSS_C_NT_HOSTBASED_SERVICE)?),
                AcceptorName::Principal(n) => {
                    let mut oid_val = NT_KRB5_PRINCIPAL_OID;
                    let mut oid = gss::gss_OID_desc {
                        length: oid_val.len() as _,
                        elements: oid_val.as_mut_ptr() as *mut _,
                    };
                    (n, import_name(n, &mut oid)?)
                }
            };
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
                return Err(format!("gss_acquire_cred({shown}) failed: {}", status_str(major, minor)));
            }
            Ok(Acceptor { cred })
        }
    }

    /// Begin a new per-session context.
    pub fn begin(&self) -> GssAcceptCtx {
        GssAcceptCtx::new()
    }
}

impl Drop for Acceptor {
    fn drop(&mut self) {
        // SAFETY: cred came from a successful gss_acquire_cred and is released exactly once
        // (gss_release_cred nulls it).
        unsafe {
            let mut minor: gss::OM_uint32 = 0;
            gss::gss_release_cred(&mut minor, &mut self.cred);
        }
    }
}

/// An acceptor context for one SMB session/channel. It holds no borrow of the
/// `Acceptor` (the credential is passed to each `step`), so a partial context
/// can be kept in the channel's state between SESSION_SETUP legs of a
/// multi-leg exchange (#38).
pub struct GssAcceptCtx {
    ctx: gss::gss_ctx_id_t,
}

// SAFETY: like the credential, a gss_ctx_id_t has no thread affinity in
// MIT/Heimdal; the context is owned by one channel and only used by the worker
// that owns that connection, never from two threads at once (it is !Sync).
unsafe impl Send for GssAcceptCtx {}

impl std::fmt::Debug for GssAcceptCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssAcceptCtx").field("started", &!self.ctx.is_null()).finish()
    }
}

impl Default for GssAcceptCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl GssAcceptCtx {
    /// A fresh context (GSS_C_NO_CONTEXT until the first `step`).
    pub fn new() -> Self {
        GssAcceptCtx { ctx: ptr::null_mut() }
    }

    /// Feed one client token (the GSS AP-REQ, or a later leg's token,
    /// unwrapped from SPNEGO by `spnego::classify`) with `acc`'s credential.
    /// On completion, extracts the session key.
    pub fn step(&mut self, acc: &Acceptor, token: &[u8]) -> Step {
        // SAFETY: input borrows `token` for the call only (GSS treats it as const); output
        // and src_name are GSS-allocated and released on every path (take_buf /
        // release_name); ctx is owned by self and freed in Drop.
        unsafe {
            let mut minor: gss::OM_uint32 = 0;
            let mut input = buf_from(token);
            let mut output = empty_buf();
            let mut src_name: gss::gss_name_t = ptr::null_mut();
            let mut ret_flags: gss::OM_uint32 = 0;
            let major = gss::gss_accept_sec_context(
                &mut minor,
                &mut self.ctx,
                acc.cred,
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
                let pac = name_pac(src_name, &client);
                release_name(src_name);
                match self.session_key() {
                    Ok(session_key) => Step::Done(Established { client, session_key, pac, out }),
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
        // SAFETY: oid_val outlives the call; set is null-checked, element 0 and its value
        // are null-checked before from_raw_parts, and set is released on every path after
        // the copy.
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
            if major != gss::GSS_S_COMPLETE || set.is_null() {
                return Err(status_str(major, minor));
            }
            let key = if (*set).count == 0 || (*set).elements.is_null() {
                Vec::new()
            } else {
                let b = &*(*set).elements;
                if b.value.is_null() {
                    Vec::new()
                } else {
                    std::slice::from_raw_parts(b.value as *const u8, b.length).to_vec()
                }
            };
            gss_release_buffer_set(&mut minor, &mut set);
            if key.is_empty() {
                return Err("empty session key".into());
            }
            Ok(key)
        }
    }
}

impl Drop for GssAcceptCtx {
    fn drop(&mut self) {
        // SAFETY: ctx is NO_CONTEXT or a live context owned solely by this GssAcceptCtx;
        // deleted once, and GSS resets the handle.
        unsafe {
            if !self.ctx.is_null() {
                let mut minor: gss::OM_uint32 = 0;
                gss::gss_delete_sec_context(&mut minor, &mut self.ctx, ptr::null_mut());
            }
        }
    }
}

// ----------------------------------------------------------- FFI helper glue

// SAFETY: (# Safety) returns an owned gss_name_t the caller must release_name exactly once;
// `bytes` and `name_type` outlive gss_import_name, which copies both.
unsafe fn import_name(s: &str, name_type: gss::gss_OID) -> Result<gss::gss_name_t, String> {
    let mut minor: gss::OM_uint32 = 0;
    let mut bytes = s.as_bytes().to_vec();
    let mut nb = gss::gss_buffer_desc {
        length: bytes.len(),
        value: bytes.as_mut_ptr() as *mut _,
    };
    let mut name: gss::gss_name_t = ptr::null_mut();
    let major = gss::gss_import_name(&mut minor, &mut nb, name_type, &mut name);
    if major != gss::GSS_S_COMPLETE {
        return Err(format!("gss_import_name({s}) failed: {}", status_str(major, minor)));
    }
    Ok(name)
}

// SAFETY: (# Safety) name must be NULL or a live GSS-owned name not released elsewhere;
// consumed here.
unsafe fn release_name(mut name: gss::gss_name_t) {
    if !name.is_null() {
        let mut minor: gss::OM_uint32 = 0;
        gss::gss_release_name(&mut minor, &mut name);
    }
}

// SAFETY: (# Safety) name must be NULL or live; the display buffer is copied and released
// by take_buf; the returned name-type OID is static and not freed.
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
    String::from_utf8_lossy(&take_buf(&mut out)).into_owned()
}

/// Read the PAC off an accepted client name and decode its LOGON_INFO. Tries
/// the LOGON_INFO buffer (`urn:mspac:logon-info`) then the whole PAC
/// (`urn:mspac:`); a PAC without LOGON_INFO (MIT KDC) is "no groups". Only an *authenticated* attribute is used: the
/// GSS library sets that once it has verified the PAC's server signature with
/// our service key, so a client can't forge group membership.
// SAFETY: (# Safety) name must be NULL or a live mechanism name from accept; attr borrows a
// 'static str (read-only to GSS); value/display are GSS-allocated and released via take_buf
// on every path; more = -1 per RFC 6680.
unsafe fn name_pac(name: gss::gss_name_t, client: &str) -> Option<crate::pac::LogonInfo> {
    if name.is_null() {
        return None;
    }
    type Parse = fn(&[u8]) -> Result<crate::pac::LogonInfo, String>;
    let attrs: [(&str, Parse); 2] = [
        ("urn:mspac:logon-info", crate::pac::parse_logon_info),
        ("urn:mspac:", crate::pac::parse_pac),
    ];
    for (attr, parse) in attrs {
        let mut minor: gss::OM_uint32 = 0;
        let mut a = buf_from(attr.as_bytes());
        let (mut authenticated, mut complete, mut more) = (0i32, 0i32, -1i32);
        let mut value = empty_buf();
        let mut display = empty_buf();
        let major = gss_get_name_attribute(
            &mut minor,
            name,
            &mut a,
            &mut authenticated,
            &mut complete,
            &mut value,
            &mut display,
            &mut more,
        );
        let v = take_buf(&mut value);
        take_buf(&mut display);
        if major != gss::GSS_S_COMPLETE {
            continue;
        }
        if authenticated == 0 {
            crate::logw!("kerberos: {client}: PAC present but not verified; ignoring it");
            return None;
        }
        match parse(&v) {
            Ok(li) => return Some(li),
            Err(e) if e == crate::pac::NO_LOGON_INFO => {
                crate::logd!("kerberos: {client}: PAC has no LOGON_INFO (non-AD KDC)");
                return None;
            }
            Err(e) => {
                crate::logw!("kerberos: {client}: PAC ({attr}) unreadable: {e}");
                return None;
            }
        }
    }
    None
}

// SAFETY: the returned descriptor borrows `b`; use it only as a GSS *input* buffer (never
// written or released) while `b` is alive.
unsafe fn buf_from(b: &[u8]) -> gss::gss_buffer_desc {
    gss::gss_buffer_desc {
        length: b.len(),
        value: b.as_ptr() as *mut _,
    }
}

// SAFETY: an empty output descriptor for GSS to fill; whatever GSS stores must be released
// with take_buf.
unsafe fn empty_buf() -> gss::gss_buffer_desc {
    gss::gss_buffer_desc { length: 0, value: ptr::null_mut() }
}

/// Copy an output buffer to a Vec and release the GSS-allocated storage.
// SAFETY: (# Safety) b must be a GSS-allocated output buffer or empty; copied when value is
// non-null, then released exactly once.
unsafe fn take_buf(b: &mut gss::gss_buffer_desc) -> Vec<u8> {
    if b.value.is_null() {
        return Vec::new();
    }
    let v = std::slice::from_raw_parts(b.value as *const u8, b.length).to_vec();
    let mut minor: gss::OM_uint32 = 0;
    gss::gss_release_buffer(&mut minor, b);
    v
}

/// Format a GSS major/minor status pair for logs, decoding both into the
/// human-readable messages from the GSS library (so the common Kerberos
/// failures — clock skew, no key in keytab, expired ticket, unreachable KDC —
/// are obvious in the log instead of a bare hex code).
fn status_str(major: gss::OM_uint32, minor: gss::OM_uint32) -> String {
    let maj = display_status(major, gss::GSS_C_GSS_CODE as i32);
    let min = display_status(minor, gss::GSS_C_MECH_CODE as i32);
    let mut s = format!("major=0x{major:08x}");
    if !maj.is_empty() {
        s.push_str(&format!(" ({maj})"));
    }
    s.push_str(&format!(" minor=0x{minor:08x}"));
    if !min.is_empty() {
        s.push_str(&format!(" ({min})"));
    }
    s
}

/// Decode one GSS status value (major or minor) into its message text(s),
/// walking the multi-message context.
fn display_status(value: gss::OM_uint32, status_type: i32) -> String {
    if value == 0 {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut msg_ctx: gss::OM_uint32 = 0;
    // Bound the loop defensively; GSS sets msg_ctx back to 0 when done.
    for _ in 0..8 {
        // SAFETY: buf is a fresh output descriptor, copied only when non-null and released
        // each iteration; msg_ctx is a live local.
        unsafe {
            let mut minor: gss::OM_uint32 = 0;
            let mut buf = empty_buf();
            let major = gss::gss_display_status(
                &mut minor,
                value,
                status_type,
                ptr::null_mut(), // default mechanism
                &mut msg_ctx,
                &mut buf,
            );
            if major != gss::GSS_S_COMPLETE {
                break;
            }
            if !buf.value.is_null() && buf.length != 0 {
                parts.push(
                    String::from_utf8_lossy(std::slice::from_raw_parts(
                        buf.value as *const u8,
                        buf.length,
                    ))
                    .into_owned(),
                );
            }
            gss::gss_release_buffer(&mut minor, &mut buf);
        }
        if msg_ctx == 0 {
            break;
        }
    }
    parts.join("; ")
}

/// Map a failed GSS accept to the most informative SMB status. Clock skew is
/// the single most common Kerberos misconfiguration, so surface it distinctly;
/// everything else is a logon failure.
pub fn status_for_failure(reason: &str) -> u32 {
    let r = reason.to_ascii_lowercase();
    if r.contains("clock skew") || r.contains("time") && r.contains("skew") {
        crate::status::TIME_DIFFERENCE_AT_DC
    } else {
        crate::status::LOGON_FAILURE
    }
}
