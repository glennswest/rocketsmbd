//! Microsoft PAC (MS-PAC) parsing (#40): the user and group SIDs AD puts in
//! a Kerberos service ticket.
//!
//! The GSS acceptor (`krb5.rs`, `kerberos` feature) hands us the PAC that the
//! GSS library has already verified with the service key (`urn:mspac:`
//! name attribute, `authenticated` = true). This module only decodes it, so
//! it is plain safe Rust with no feature gate: it is unit-tested in every
//! build against recorded Windows PACs (`testdata/`).
//!
//! Only the `KERB_VALIDATION_INFO` (LOGON_INFO, buffer type 1) is decoded. It
//! is an NDR type serialization (MS-RPCE 2.2.6, 32-bit NDR20 pointers): a
//! fixed-size struct whose strings, SIDs and arrays follow as deferred
//! referents in field order. Group *names* are not in the PAC: matching a
//! group by name goes through `authz` (SID literal, well-known RID or the
//! `[[group]]` table).

use std::fmt;

/// `parse_pac` error for a PAC that has no LOGON_INFO buffer — what an MIT
/// KDC issues (it has no AD account data). Not a fault; callers treat it as
/// "no groups".
pub const NO_LOGON_INFO: &str = "PAC: no LOGON_INFO buffer";

/// PAC buffer type of the `KERB_VALIDATION_INFO`.
const PAC_LOGON_INFO: u32 = 1;

/// Upper bounds on attacker-influenced counts (the PAC is signed by the KDC,
/// but the parser is still fed bytes, and fuzzed). AD caps a token at ~1015
/// groups; these are generous.
const MAX_SUBAUTH: usize = 15;
const MAX_GROUPS: usize = 8192;

/// A Windows security identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    pub revision: u8,
    /// 48-bit identifier authority (5 = NT AUTHORITY).
    pub authority: u64,
    pub sub: Vec<u32>,
}

impl Sid {
    /// Parse the `S-1-5-21-…` string form.
    pub fn parse(s: &str) -> Option<Sid> {
        let mut it = s.split('-');
        if !it.next()?.eq_ignore_ascii_case("S") {
            return None;
        }
        let revision: u8 = it.next()?.parse().ok()?;
        let authority: u64 = it.next()?.parse().ok()?;
        if revision != 1 || authority >= 1 << 48 {
            return None;
        }
        let sub = it.map(|p| p.parse::<u32>().ok()).collect::<Option<Vec<u32>>>()?;
        if sub.is_empty() || sub.len() > MAX_SUBAUTH {
            return None;
        }
        Some(Sid { revision, authority, sub })
    }

    /// This (domain) SID with `rid` appended.
    pub fn with_rid(&self, rid: u32) -> Sid {
        let mut s = self.clone();
        s.sub.push(rid);
        s
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-{}-{}", self.revision, self.authority)?;
        for s in &self.sub {
            write!(f, "-{s}")?;
        }
        Ok(())
    }
}

/// What rocketsmbd uses from a PAC's `KERB_VALIDATION_INFO`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogonInfo {
    /// sAMAccountName, e.g. `alice`.
    pub user: String,
    /// NetBIOS domain name, e.g. `AD`.
    pub domain: String,
    /// Domain SID (`LogonDomainId`); `None` only in a malformed PAC.
    pub domain_sid: Option<Sid>,
    /// User SID (domain SID + `UserId`).
    pub user_sid: Option<Sid>,
    /// Every group SID the token carries: the primary group, `GroupIds`
    /// (domain-relative), `ExtraSids` and the resource groups.
    pub groups: Vec<Sid>,
}

impl LogonInfo {
    /// True when `sid` is the user's SID or one of its group SIDs.
    pub fn has_sid(&self, sid: &Sid) -> bool {
        self.user_sid.as_ref() == Some(sid) || self.groups.iter().any(|g| g == sid)
    }
}

/// Decode a whole PAC (`PACTYPE`, what `urn:mspac:` returns) and return its
/// LOGON_INFO.
pub fn parse_pac(pac: &[u8]) -> Result<LogonInfo, String> {
    let mut r = Rd::new(pac);
    let count = r.u32()? as usize;
    let _version = r.u32()?;
    if count == 0 || count > 64 {
        return Err(format!("PAC: implausible buffer count {count}"));
    }
    for _ in 0..count {
        let ty = r.u32()?;
        let size = r.u32()? as usize;
        let off = r.u64()?;
        if ty == PAC_LOGON_INFO {
            let off = usize::try_from(off).map_err(|_| "PAC: offset overflow")?;
            let end = off.checked_add(size).ok_or("PAC: length overflow")?;
            let buf = pac.get(off..end).ok_or("PAC: LOGON_INFO out of bounds")?;
            return parse_logon_info(buf);
        }
    }
    Err(NO_LOGON_INFO.into())
}

/// Decode a LOGON_INFO buffer (what `urn:mspac:logon-info` returns): the NDR
/// type serialization of a `KERB_VALIDATION_INFO`.
pub fn parse_logon_info(buf: &[u8]) -> Result<LogonInfo, String> {
    let mut r = Rd::new(buf);
    // Common type header: version 1, little-endian (0x10), length 8.
    let (ver, endian, hlen) = (r.u8()?, r.u8()?, r.u16()?);
    if ver != 1 || endian != 0x10 || hlen != 8 {
        return Err(format!("LOGON_INFO: unsupported NDR header {ver}/{endian:#x}/{hlen}"));
    }
    r.u32()?; // filler
    r.u32()?; // private header: object buffer length
    r.u32()?; // filler
    if r.u32()? == 0 {
        return Err("LOGON_INFO: null KERB_VALIDATION_INFO".into());
    }

    // --- fixed part of KERB_VALIDATION_INFO
    r.skip(6 * 8)?; // LogonTime … PasswordMustChange
    // EffectiveName, FullName, LogonScript, ProfilePath, HomeDirectory,
    // HomeDirectoryDrive
    let mut strs = [UStr { len: 0, present: false }; 6];
    for s in strs.iter_mut() {
        *s = r.ustr_hdr()?;
    }
    r.u16()?; // LogonCount
    r.u16()?; // BadPasswordCount
    let user_id = r.u32()?;
    let primary_group = r.u32()?;
    r.u32()?; // GroupCount (the array carries its own count)
    let group_ids = r.u32()? != 0;
    r.u32()?; // UserFlags
    r.skip(16)?; // UserSessionKey
    let logon_server = r.ustr_hdr()?;
    let domain_name = r.ustr_hdr()?;
    let domain_sid = r.u32()? != 0;
    r.skip(2 * 4)?; // Reserved1
    r.u32()?; // UserAccountControl
    r.u32()?; // SubAuthStatus
    r.skip(2 * 8)?; // LastSuccessfulILogon, LastFailedILogon
    r.u32()?; // FailedILogonCount
    r.u32()?; // Reserved3
    r.u32()?; // SidCount
    let extra_sids = r.u32()? != 0;
    let res_domain = r.u32()? != 0;
    r.u32()?; // ResourceGroupCount
    let res_ids = r.u32()? != 0;

    // --- deferred referents, in field order
    let user = r.ustr_body(strs[0])?.unwrap_or_default();
    for s in &strs[1..] {
        r.ustr_body(*s)?;
    }
    let rids = if group_ids { r.rids()? } else { Vec::new() };
    r.ustr_body(logon_server)?;
    let domain = r.ustr_body(domain_name)?.unwrap_or_default();
    let domain_sid = if domain_sid { Some(r.sid()?) } else { None };
    let mut extra = Vec::new();
    if extra_sids {
        // KERB_SID_AND_ATTRIBUTES[]: (SID pointer, Attributes) pairs, then
        // the non-null SIDs in order.
        let n = r.u32()? as usize;
        if n > MAX_GROUPS {
            return Err("PAC: too many extra SIDs".into());
        }
        let mut present = Vec::with_capacity(n);
        for _ in 0..n {
            present.push(r.u32()? != 0);
            r.u32()?; // Attributes
        }
        for p in present {
            if p {
                extra.push(r.sid()?);
            }
        }
    }
    let res_domain = if res_domain { Some(r.sid()?) } else { None };
    let res_rids = if res_ids { r.rids()? } else { Vec::new() };

    let mut groups: Vec<Sid> = Vec::new();
    let mut add = |s: Sid| {
        if !groups.contains(&s) {
            groups.push(s);
        }
    };
    if let Some(d) = &domain_sid {
        add(d.with_rid(primary_group));
        for rid in &rids {
            add(d.with_rid(*rid));
        }
    }
    for s in extra {
        add(s);
    }
    if let Some(d) = &res_domain {
        for rid in &res_rids {
            add(d.with_rid(*rid));
        }
    }
    let user_sid = domain_sid.as_ref().map(|d| d.with_rid(user_id));
    Ok(LogonInfo { user, domain, domain_sid, user_sid, groups })
}

/// The `RPC_UNICODE_STRING` header: byte length and whether the buffer
/// pointer is non-null.
#[derive(Clone, Copy)]
struct UStr {
    len: u16,
    present: bool,
}

/// Little-endian NDR reader; `u32` reads align to 4 from the buffer start
/// (the NDR stream starts at offset 16 of the buffer, itself 4-aligned).
struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rd { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("PAC: overflow")?;
        let s = self.b.get(self.pos..end).ok_or("PAC: truncated")?;
        self.pos = end;
        Ok(s)
    }
    fn skip(&mut self, n: usize) -> Result<(), String> {
        self.take(n).map(|_| ())
    }
    fn align(&mut self, a: usize) -> Result<(), String> {
        let pad = (a - self.pos % a) % a;
        self.skip(pad)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        self.align(2)?;
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, String> {
        self.align(4)?;
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, String> {
        let lo = self.u32()? as u64;
        let hi = self.u32()? as u64;
        Ok(lo | hi << 32)
    }
    fn ustr_hdr(&mut self) -> Result<UStr, String> {
        let len = self.u16()?;
        let _max = self.u16()?;
        let present = self.u32()? != 0;
        Ok(UStr { len, present })
    }
    /// The deferred body of a string whose header was `h`.
    fn ustr_body(&mut self, h: UStr) -> Result<Option<String>, String> {
        if !h.present {
            return Ok(None);
        }
        let _max = self.u32()?;
        let _off = self.u32()?;
        let actual = self.u32()? as usize;
        if actual * 2 < h.len as usize || actual > 0x8000 {
            return Err("PAC: bad string length".into());
        }
        let raw = self.take(actual * 2)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .take(h.len as usize / 2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(Some(String::from_utf16_lossy(&units)))
    }
    /// A deferred `RPC_SID` (conformant: MaxCount, then the SID).
    fn sid(&mut self) -> Result<Sid, String> {
        let max = self.u32()? as usize;
        let revision = self.u8()?;
        let n = self.u8()? as usize;
        if n != max || n == 0 || n > MAX_SUBAUTH {
            return Err("PAC: bad SID".into());
        }
        let a = self.take(6)?;
        let authority = a.iter().fold(0u64, |acc, &b| acc << 8 | b as u64);
        let mut sub = Vec::with_capacity(n);
        for _ in 0..n {
            sub.push(self.u32()?);
        }
        Ok(Sid { revision, authority, sub })
    }
    /// A deferred `GROUP_MEMBERSHIP` array: the RIDs.
    fn rids(&mut self) -> Result<Vec<u32>, String> {
        let n = self.u32()? as usize;
        if n > MAX_GROUPS {
            return Err("PAC: too many groups".into());
        }
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.u32()?);
            self.u32()?; // Attributes
        }
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(s: &str) -> Sid {
        Sid::parse(s).unwrap()
    }

    /// Windows Server 2003 PAC for a domain controller's machine account,
    /// from Samba's torture suite via MIT krb5 `t_pac.c` (see testdata/README).
    #[test]
    fn windows_2003_pac() {
        let li = parse_pac(include_bytes!("../testdata/pac-w2003.bin")).unwrap();
        let dom = "S-1-5-21-3048156945-3961193616-3706469200";
        assert_eq!(li.user, "W2003FINAL$");
        assert_eq!(li.domain, "WIN2K3THINK");
        assert_eq!(li.domain_sid, Some(sid(dom)));
        assert_eq!(li.user_sid, Some(sid(&format!("{dom}-1005"))));
        // Primary group + GroupIds = Domain Controllers (516); ExtraSids =
        // Enterprise Domain Controllers (S-1-5-9).
        assert_eq!(li.groups, vec![sid(&format!("{dom}-516")), sid("S-1-5-9")]);
        assert!(li.has_sid(&sid("S-1-5-9")));
        assert!(!li.has_sid(&sid(&format!("{dom}-512"))));
    }

    /// Windows Server 2008 S4U2Self PAC for a regular user (MIT `t_pac.c`).
    #[test]
    fn windows_2008_user_pac() {
        let li = parse_pac(include_bytes!("../testdata/pac-w2008-s4u.bin")).unwrap();
        let dom = "S-1-5-21-9281652-3921847615-585208160";
        assert_eq!(li.user, "w2k8u");
        assert_eq!(li.domain, "ACME");
        assert_eq!(li.user_sid, Some(sid(&format!("{dom}-1142"))));
        assert_eq!(li.groups, vec![sid(&format!("{dom}-513"))]); // Domain Users
    }

    /// The LOGON_INFO buffer on its own (`urn:mspac:logon-info`) parses the
    /// same as via the PACTYPE.
    #[test]
    fn logon_info_buffer_alone() {
        let pac = include_bytes!("../testdata/pac-w2003.bin");
        // Buffer 0 is LOGON_INFO: size 0x1d8 at offset 0x48.
        let li = parse_logon_info(&pac[0x48..0x48 + 0x1d8]).unwrap();
        assert_eq!(li.user, "W2003FINAL$");
    }

    /// Every truncation of a real PAC is an error, never a panic.
    #[test]
    fn truncated_pac_errors() {
        let pac = include_bytes!("../testdata/pac-w2003.bin");
        for n in 0..0x48 + 0x1d8 {
            assert!(parse_pac(&pac[..n]).is_err(), "prefix {n} parsed");
        }
        assert!(parse_pac(&[0u8; 8]).is_err());
    }

    /// A PAC with no LOGON_INFO (what an MIT KDC issues) reports the
    /// distinguishable NO_LOGON_INFO error.
    #[test]
    fn pac_without_logon_info() {
        let mut pac = Vec::new();
        pac.extend_from_slice(&1u32.to_le_bytes()); // cBuffers
        pac.extend_from_slice(&0u32.to_le_bytes()); // Version
        pac.extend_from_slice(&10u32.to_le_bytes()); // CLIENT_INFO
        pac.extend_from_slice(&0u32.to_le_bytes());
        pac.extend_from_slice(&24u64.to_le_bytes());
        assert_eq!(parse_pac(&pac), Err(NO_LOGON_INFO.to_string()));
    }

    #[test]
    fn sid_string_roundtrip() {
        let s = "S-1-5-21-3048156945-3961193616-3706469200-512";
        assert_eq!(sid(s).to_string(), s);
        assert_eq!(sid("s-1-5-32-544").to_string(), "S-1-5-32-544");
        for bad in ["", "S-1", "S-1-5", "S-2-5-21", "X-1-5-21", "S-1-5-x", "S-1-281474976710656-1"] {
            assert!(Sid::parse(bad).is_none(), "{bad:?}");
        }
    }
}
