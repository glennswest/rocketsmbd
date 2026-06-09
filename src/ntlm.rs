//! NTLMSSP: challenge generation, NTLMv2 verification, session key
//! derivation, and just enough SPNEGO (DER) to keep Windows clients happy.
//!
//! MIC verification is not implemented (we omit the MsvAvTimestamp AV pair,
//! so well-behaved clients don't send one).

use crate::crypto;
use crate::wire::{utf16le, Put, Rdr};

pub const SIG: &[u8; 8] = b"NTLMSSP\0";

const FLAG_ANONYMOUS: u32 = 0x0000_0800;
const FLAG_KEY_EXCH: u32 = 0x4000_0000;

#[derive(Debug, PartialEq, Eq)]
pub enum Token {
    Negotiate,
    Authenticate,
    Other,
}

/// Locate an NTLMSSP token inside a raw or SPNEGO-wrapped blob.
pub fn find_token(blob: &[u8]) -> Option<&[u8]> {
    let p = blob.windows(SIG.len()).position(|w| w == SIG)?;
    Some(&blob[p..])
}

pub fn classify(blob: &[u8]) -> Token {
    let Some(tok) = find_token(blob) else {
        return Token::Other;
    };
    if tok.len() < 12 {
        return Token::Other;
    }
    match u32::from_le_bytes(tok[8..12].try_into().unwrap()) {
        1 => Token::Negotiate,
        3 => Token::Authenticate,
        _ => Token::Other,
    }
}

const FLAGS: u32 = 0x0000_0001  // UNICODE
    | 0x0000_0010               // SIGN (cifs requires this for sec=ntlmsspi)
    | 0x0000_0200               // NTLM
    | 0x0000_8000               // ALWAYS_SIGN
    | 0x0002_0000               // TARGET_TYPE_SERVER
    | 0x0008_0000               // EXTENDED_SESSIONSECURITY
    | 0x0080_0000               // TARGET_INFO
    | 0x0200_0000               // VERSION
    | 0x2000_0000               // 128-bit
    | 0x4000_0000               // KEY_EXCH
    | 0x8000_0000; // 56-bit

/// Build a CHALLENGE_MESSAGE (type 2).
pub fn challenge(server_name: &str, chal: [u8; 8]) -> Vec<u8> {
    let target = utf16le(server_name);
    let mut info: Vec<u8> = Vec::new();
    // AV pairs: NetBIOS domain (2), NetBIOS computer (1), EOL (0).
    for (id, val) in [(2u16, &target), (1u16, &target)] {
        info.p16(id);
        info.p16(val.len() as u16);
        info.pbytes(val);
    }
    info.p16(0);
    info.p16(0);

    const HDR: usize = 56;
    let mut m: Vec<u8> = Vec::with_capacity(HDR + target.len() + info.len());
    m.pbytes(SIG);
    m.p32(2); // MessageType
    m.p16(target.len() as u16);
    m.p16(target.len() as u16);
    m.p32(HDR as u32);
    m.p32(FLAGS);
    m.pbytes(&chal);
    m.p64(0); // Reserved
    m.p16(info.len() as u16);
    m.p16(info.len() as u16);
    m.p32((HDR + target.len()) as u32);
    // Version: 6.1 build 7601, NTLMSSP revision 15.
    m.pbytes(&[0x06, 0x01, 0xB1, 0x1D, 0x00, 0x00, 0x00, 0x0F]);
    debug_assert_eq!(m.len(), HDR);
    m.pbytes(&target);
    m.pbytes(&info);
    m
}

#[derive(Debug)]
pub struct Authenticate<'a> {
    pub user: String,
    pub domain: String,
    pub nt_response: &'a [u8],
    pub enc_session_key: &'a [u8],
    pub flags: u32,
}

impl Authenticate<'_> {
    pub fn is_anonymous(&self) -> bool {
        self.flags & FLAG_ANONYMOUS != 0 || (self.user.is_empty() && self.nt_response.len() < 16)
    }
}

fn field<'a>(tok: &'a [u8], r: &mut Rdr) -> Option<&'a [u8]> {
    let len = r.u16()? as usize;
    let _max = r.u16()?;
    let off = r.u32()? as usize;
    if len == 0 {
        return Some(&[]);
    }
    tok.get(off..off + len)
}

/// Parse an AUTHENTICATE_MESSAGE (type 3) from a raw or wrapped blob.
pub fn parse_authenticate(blob: &[u8]) -> Option<Authenticate<'_>> {
    let tok = find_token(blob)?;
    let mut r = Rdr::new(tok);
    r.skip(8)?;
    if r.u32()? != 3 {
        return None;
    }
    let _lm = field(tok, &mut r)?;
    let nt_response = field(tok, &mut r)?;
    let domain = field(tok, &mut r)?;
    let user = field(tok, &mut r)?;
    let _workstation = field(tok, &mut r)?;
    let enc_session_key = field(tok, &mut r)?;
    let flags = r.u32()?;
    Some(Authenticate {
        user: crate::wire::from_utf16le(user),
        domain: crate::wire::from_utf16le(domain),
        nt_response,
        enc_session_key,
        flags,
    })
}

/// Verify an NTLMv2 response and return the 16-byte ExportedSessionKey on
/// success (used as the SMB session key).
pub fn verify_ntlmv2(
    nt_hash: &[u8; 16],
    auth: &Authenticate,
    server_challenge: &[u8; 8],
) -> Option<[u8; 16]> {
    if auth.nt_response.len() < 16 + 28 {
        return None;
    }
    // NTLMv2 hash = HMAC-MD5(NT hash, UPPER(user) + domain) in UTF-16LE,
    // domain exactly as the client sent it.
    let mut id = utf16le(&auth.user.to_uppercase());
    id.extend_from_slice(&utf16le(&auth.domain));
    let v2_hash = crypto::hmac_md5(nt_hash, &id);

    let (proof, temp) = auth.nt_response.split_at(16);
    let mut buf = Vec::with_capacity(8 + temp.len());
    buf.extend_from_slice(server_challenge);
    buf.extend_from_slice(temp);
    let expect = crypto::hmac_md5(&v2_hash, &buf);
    if expect != proof {
        return None;
    }

    let session_base = crypto::hmac_md5(&v2_hash, proof);
    let key = if auth.flags & FLAG_KEY_EXCH != 0 && auth.enc_session_key.len() == 16 {
        crypto::rc4(&session_base, auth.enc_session_key).try_into().unwrap()
    } else {
        session_base
    };
    Some(key)
}

// --------------------------------------------------------------- SPNEGO/DER

pub fn is_spnego(blob: &[u8]) -> bool {
    matches!(blob.first(), Some(0x60) | Some(0xA1))
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len() + 4);
    v.push(tag);
    let n = content.len();
    if n < 128 {
        v.push(n as u8);
    } else if n < 256 {
        v.push(0x81);
        v.push(n as u8);
    } else {
        v.push(0x82);
        v.push((n >> 8) as u8);
        v.push((n & 0xFF) as u8);
    }
    v.extend_from_slice(content);
    v
}

const OID_SPNEGO: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
const OID_NTLMSSP: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];

/// NegTokenInit2 hint placed in the NEGOTIATE response security buffer so
/// Windows clients pick NTLMSSP.
pub fn spnego_hint() -> Vec<u8> {
    let mech_list = der(0xA0, &der(0x30, &der(0x06, OID_NTLMSSP)));
    let hint_str = der(0x1B, b"not_defined_in_RFC4178@please_ignore");
    let hints = der(0xA3, &der(0x30, &der(0xA0, &hint_str)));
    let mut init = mech_list;
    init.extend_from_slice(&hints);
    let token = der(0xA0, &der(0x30, &init));
    let mut body = der(0x06, OID_SPNEGO);
    body.extend_from_slice(&token);
    der(0x60, &body)
}

/// NegTokenResp carrying our CHALLENGE, negState = accept-incomplete.
pub fn spnego_wrap_challenge(token: &[u8]) -> Vec<u8> {
    let mut inner = der(0xA0, &[0x0A, 0x01, 0x01]);
    inner.extend_from_slice(&der(0xA1, &der(0x06, OID_NTLMSSP)));
    inner.extend_from_slice(&der(0xA2, &der(0x04, token)));
    der(0xA1, &der(0x30, &inner))
}

/// NegTokenResp, negState = accept-completed.
pub fn spnego_accept_completed() -> Vec<u8> {
    der(0xA1, &der(0x30, &der(0xA0, &[0x0A, 0x01, 0x00])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_raw_and_wrapped() {
        let mut t1 = SIG.to_vec();
        t1.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(classify(&t1), Token::Negotiate);
        let mut t3 = vec![0xA1, 0x82, 0x01, 0x00];
        t3.extend_from_slice(SIG);
        t3.extend_from_slice(&3u32.to_le_bytes());
        assert_eq!(classify(&t3), Token::Authenticate);
        assert_eq!(classify(b"garbage"), Token::Other);
    }

    #[test]
    fn challenge_shape() {
        let c = challenge("SRV", [7; 8]);
        assert_eq!(&c[..8], SIG);
        assert_eq!(u32::from_le_bytes(c[8..12].try_into().unwrap()), 2);
        assert_eq!(&c[24..32], &[7; 8]);
        let off = u32::from_le_bytes(c[16..20].try_into().unwrap()) as usize;
        assert_eq!(&c[off..off + 6], &utf16le("SRV")[..]);
    }

    /// Build a synthetic type-3 the way a real client would, then verify it.
    fn make_type3(user: &str, domain: &str, password: &str, chal: &[u8; 8]) -> Vec<u8> {
        let nt = crypto::nt_hash(password);
        let mut id = utf16le(&user.to_uppercase());
        id.extend_from_slice(&utf16le(domain));
        let v2 = crypto::hmac_md5(&nt, &id);
        // temp blob: resptype(2) reserved(6) time(8) client-chal(8) res(4) eol(4)
        let mut temp = vec![1, 1, 0, 0, 0, 0, 0, 0];
        temp.extend_from_slice(&[0; 8]);
        temp.extend_from_slice(&[0xAA; 8]);
        temp.extend_from_slice(&[0; 8]);
        let mut buf = chal.to_vec();
        buf.extend_from_slice(&temp);
        let proof = crypto::hmac_md5(&v2, &buf);
        let mut nt_resp = proof.to_vec();
        nt_resp.extend_from_slice(&temp);

        let u16user = utf16le(user);
        let u16dom = utf16le(domain);
        let mut m: Vec<u8> = Vec::new();
        m.pbytes(SIG);
        m.p32(3);
        let base = 64usize; // header size up to flags
        let mut off = base;
        let mut fields: Vec<(usize, usize)> = Vec::new();
        for len in [0, nt_resp.len(), u16dom.len(), u16user.len(), 0, 0] {
            fields.push((len, off));
            off += len;
        }
        for (len, off) in &fields {
            m.p16(*len as u16);
            m.p16(*len as u16);
            m.p32(*off as u32);
        }
        m.p32(0); // flags: no KEY_EXCH
        debug_assert_eq!(m.len(), base);
        m.pbytes(&nt_resp);
        m.pbytes(&u16dom);
        m.pbytes(&u16user);
        m
    }

    #[test]
    fn ntlmv2_roundtrip() {
        let chal = [9u8; 8];
        let blob = make_type3("glenn", "WORKGROUP", "secretpw", &chal);
        let auth = parse_authenticate(&blob).unwrap();
        assert_eq!(auth.user, "glenn");
        assert_eq!(auth.domain, "WORKGROUP");
        let nt = crypto::nt_hash("secretpw");
        assert!(verify_ntlmv2(&nt, &auth, &chal).is_some());
        // Wrong password must fail.
        let bad = crypto::nt_hash("wrongpw");
        assert!(verify_ntlmv2(&bad, &auth, &chal).is_none());
        // Tampered challenge must fail.
        assert!(verify_ntlmv2(&nt, &auth, &[0; 8]).is_none());
    }

    #[test]
    fn spnego_der_shapes() {
        let hint = spnego_hint();
        assert_eq!(hint[0], 0x60);
        let chal = spnego_wrap_challenge(b"NTLMSSP\0fake");
        assert_eq!(chal[0], 0xA1);
        assert!(find_token(&chal).is_some());
        let done = spnego_accept_completed();
        assert_eq!(done[0], 0xA1);
        assert!(is_spnego(&done));
    }
}
