//! SPNEGO (RFC 4178) DER glue and mechanism negotiation.
//!
//! This module owns the GSS/SPNEGO wire encoding shared by every auth
//! mechanism — the minimal DER writer/reader, the mechanism OIDs, the
//! `NegTokenInit2` hint placed in the NEGOTIATE response, and classification of
//! an inbound SESSION_SETUP security blob into the mechanism + the GSS token to
//! hand the acceptor.
//!
//! It is always compiled (Kerberos needs it even in an NTLM-free build, #30);
//! the NTLM-specific message bodies live in `ntlm.rs`. SPNEGO negotiation logic
//! here is pure ASN.1 with no external dependency, so it is fully unit-tested on
//! any host — the GSS acceptor that consumes the classified token is the only
//! Linux/`kerberos`-gated part (#33).

// ----------------------------------------------------------------- mech OIDs

/// SPNEGO: 1.3.6.1.5.5.2
pub const OID_SPNEGO: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
/// NTLMSSP: 1.3.6.1.4.1.311.2.2.10
pub const OID_NTLMSSP: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];
/// Kerberos 5: 1.2.840.113554.1.2.2
pub const OID_KRB5: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];
/// MS Kerberos (legacy alias Windows still sends): 1.2.840.48018.1.2.2
pub const OID_MS_KRB5: &[u8] = &[0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02];

/// Negotiated security mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mech {
    /// Kerberos 5 (either the canonical or the MS OID).
    Krb5,
    /// NTLMSSP.
    Ntlmssp,
    /// Unrecognized / unsupported.
    Unknown,
}

impl Mech {
    fn from_oid(oid: &[u8]) -> Mech {
        match oid {
            OID_KRB5 | OID_MS_KRB5 => Mech::Krb5,
            OID_NTLMSSP => Mech::Ntlmssp,
            _ => Mech::Unknown,
        }
    }
}

// -------------------------------------------------------------- DER encoding

/// Write a DER TLV with a definite length (supports the short and 1/2-byte
/// long forms — enough for SPNEGO tokens, which never exceed 64 KiB).
pub fn der(tag: u8, content: &[u8]) -> Vec<u8> {
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

/// DER OBJECT IDENTIFIER from its body bytes.
fn der_oid(body: &[u8]) -> Vec<u8> {
    der(0x06, body)
}

// -------------------------------------------------------------- DER decoding

/// One DER element: tag, and the slice of its content (value).
struct Tlv<'a> {
    tag: u8,
    val: &'a [u8],
    /// total bytes consumed (header + value), for sequential walking.
    len: usize,
}

/// Parse one TLV at the front of `buf`. Returns None on a malformed/short
/// length. Only the definite short and 1/2-byte long forms are accepted.
fn tlv(buf: &[u8]) -> Option<Tlv<'_>> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let b1 = buf[1] as usize;
    let (hdr, len): (usize, usize) = if b1 < 0x80 {
        (2, b1)
    } else if b1 == 0x81 {
        if buf.len() < 3 {
            return None;
        }
        (3, buf[2] as usize)
    } else if b1 == 0x82 {
        if buf.len() < 4 {
            return None;
        }
        (4, ((buf[2] as usize) << 8) | buf[3] as usize)
    } else {
        return None; // indefinite / >2-byte length not used by SPNEGO
    };
    let end = hdr.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some(Tlv { tag, val: &buf[hdr..end], len: end })
}

/// Walk the children of a constructed element, yielding each TLV in order.
fn children(mut buf: &[u8]) -> impl Iterator<Item = Tlv<'_>> {
    std::iter::from_fn(move || {
        let t = tlv(buf)?;
        buf = &buf[t.len..];
        Some(t)
    })
}

// --------------------------------------------------------- NegTokenInit hint

/// Build the `NegTokenInit2` advertised in the NEGOTIATE response security
/// buffer. Mechanisms are listed in the given order (put Kerberos first so a
/// Kerberos-capable client prefers it); an empty list yields an empty buffer.
pub fn neg_init_hint(mechs: &[Mech]) -> Vec<u8> {
    if mechs.is_empty() {
        return Vec::new();
    }
    let mut oids = Vec::new();
    for m in mechs {
        let oid: &[u8] = match m {
            Mech::Krb5 => OID_KRB5,
            Mech::Ntlmssp => OID_NTLMSSP,
            Mech::Unknown => continue,
        };
        oids.extend_from_slice(&der_oid(oid));
    }
    let mech_list = der(0xA0, &der(0x30, &oids));
    // The bogus hint string Windows expects (RFC 4178 §4.2.1 negHints).
    let hint_str = der(0x1B, b"not_defined_in_RFC4178@please_ignore");
    let hints = der(0xA3, &der(0x30, &der(0xA0, &hint_str)));
    let mut init = mech_list;
    init.extend_from_slice(&hints);
    let token = der(0xA0, &der(0x30, &init));
    let mut body = der_oid(OID_SPNEGO);
    body.extend_from_slice(&token);
    der(0x60, &body)
}

// ---------------------------------------------------- inbound classification

/// What an inbound SESSION_SETUP security blob carries.
pub struct Incoming<'a> {
    /// The selected mechanism.
    pub mech: Mech,
    /// True when the blob was SPNEGO-wrapped (vs a raw mech token); the
    /// response must be SPNEGO-wrapped to match.
    pub spnego: bool,
    /// The mechanism token to feed the acceptor: for Kerberos the GSS-API
    /// AP-REQ (`0x60 …`), for NTLMSSP the `NTLMSSP\0…` message. For a bare
    /// SPNEGO `NegTokenInit` with no `mechToken`, this is empty.
    pub token: &'a [u8],
}

/// Classify a SESSION_SETUP security blob: SPNEGO `NegTokenInit` (`0x60` with
/// the SPNEGO OID), SPNEGO `NegTokenResp` (`0xA1`), a raw GSS Kerberos AP-REQ
/// (`0x60` with a Kerberos OID), or a raw NTLMSSP message.
pub fn classify(blob: &[u8]) -> Incoming<'_> {
    match blob.first() {
        // application-0: either SPNEGO NegTokenInit or a raw GSS mech token.
        Some(0x60) => {
            if let Some(t) = tlv(blob) {
                let mut it = children(t.val);
                if let Some(oid) = it.next() {
                    if oid.tag == 0x06 && oid.val == OID_SPNEGO {
                        // SPNEGO NegTokenInit: descend into the [0] NegTokenInit.
                        if let Some(neg) = it.next() {
                            return parse_neg_init(neg.val);
                        }
                    } else if oid.tag == 0x06 {
                        // Raw GSS mech token (Kerberos AP-REQ): the whole blob
                        // is the GSS token the acceptor wants.
                        return Incoming { mech: Mech::from_oid(oid.val), spnego: false, token: blob };
                    }
                }
            }
            Incoming { mech: Mech::Unknown, spnego: false, token: blob }
        }
        // SPNEGO NegTokenResp continuation from the client.
        Some(0xA1) => parse_neg_resp(blob),
        // Raw NTLMSSP message.
        _ if blob.starts_with(crate::ntlm_sig()) => {
            Incoming { mech: Mech::Ntlmssp, spnego: false, token: blob }
        }
        _ => Incoming { mech: Mech::Unknown, spnego: false, token: blob },
    }
}

/// Parse a SPNEGO `NegTokenInit` body: `[0] mechTypes`, optional `[2]
/// mechToken`. Selects the first mechanism we understand and returns its token.
fn parse_neg_init(body: &[u8]) -> Incoming<'_> {
    // NegTokenInit ::= SEQUENCE { ... }
    let seq = match tlv(body) {
        Some(t) if t.tag == 0x30 => t,
        _ => return Incoming { mech: Mech::Unknown, spnego: true, token: &[] },
    };
    let mut mech = Mech::Unknown;
    let mut token: &[u8] = &[];
    for field in children(seq.val) {
        match field.tag {
            0xA0 => {
                // mechTypes: SEQUENCE OF OID — pick the first we support.
                if let Some(list) = tlv(field.val).filter(|t| t.tag == 0x30) {
                    for oid in children(list.val).filter(|t| t.tag == 0x06) {
                        let m = Mech::from_oid(oid.val);
                        if m != Mech::Unknown {
                            mech = m;
                            break;
                        }
                    }
                }
            }
            0xA2 => {
                // mechToken: OCTET STRING.
                if let Some(os) = tlv(field.val).filter(|t| t.tag == 0x04) {
                    token = os.val;
                }
            }
            _ => {}
        }
    }
    Incoming { mech, spnego: true, token }
}

/// Parse a SPNEGO `NegTokenResp`: extract `[1] supportedMech` (if present) and
/// `[2] responseToken`. The mech is inferred from the response token when the
/// supportedMech field is absent (common on later legs).
fn parse_neg_resp(blob: &[u8]) -> Incoming<'_> {
    let outer = match tlv(blob) {
        Some(t) if t.tag == 0xA1 => t,
        _ => return Incoming { mech: Mech::Unknown, spnego: true, token: &[] },
    };
    let seq = match tlv(outer.val) {
        Some(t) if t.tag == 0x30 => t,
        _ => return Incoming { mech: Mech::Unknown, spnego: true, token: &[] },
    };
    let mut mech = Mech::Unknown;
    let mut token: &[u8] = &[];
    for field in children(seq.val) {
        match field.tag {
            0xA1 => {
                if let Some(oid) = tlv(field.val).filter(|t| t.tag == 0x06) {
                    mech = Mech::from_oid(oid.val);
                }
            }
            0xA2 => {
                if let Some(os) = tlv(field.val).filter(|t| t.tag == 0x04) {
                    token = os.val;
                }
            }
            _ => {}
        }
    }
    // Fall back to sniffing the response token if supportedMech was omitted.
    if mech == Mech::Unknown {
        if token.starts_with(crate::ntlm_sig()) {
            mech = Mech::Ntlmssp;
        } else if token.first() == Some(&0x60) {
            mech = Mech::Krb5;
        }
    }
    Incoming { mech, spnego: true, token }
}

// ------------------------------------------------------ NegTokenResp builders

/// SPNEGO `negState` values (RFC 4178 §4.2.2).
pub const ACCEPT_COMPLETED: u8 = 0x00;
pub const ACCEPT_INCOMPLETE: u8 = 0x01;

/// Wrap a mechanism's output token in a `NegTokenResp` with the given
/// `negState` and `supportedMech`. `token` may be empty (e.g. the final
/// accept-completed leg with no AP-REP).
pub fn neg_resp(state: u8, mech: Mech, token: &[u8]) -> Vec<u8> {
    let oid: &[u8] = match mech {
        Mech::Krb5 => OID_KRB5,
        Mech::Ntlmssp => OID_NTLMSSP,
        Mech::Unknown => &[],
    };
    let mut inner = der(0xA0, &[0x0A, 0x01, state]); // negState ENUMERATED
    if !oid.is_empty() {
        inner.extend_from_slice(&der(0xA1, &der_oid(oid))); // supportedMech
    }
    if !token.is_empty() {
        inner.extend_from_slice(&der(0xA2, &der(0x04, token))); // responseToken
    }
    der(0xA1, &der(0x30, &inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_advertises_kerberos_first_then_ntlm() {
        let h = neg_init_hint(&[Mech::Krb5, Mech::Ntlmssp]);
        assert_eq!(h.first(), Some(&0x60));
        // SPNEGO OID present, then both mech OIDs in order.
        let krb = h.windows(OID_KRB5.len()).position(|w| w == OID_KRB5).unwrap();
        let ntlm = h.windows(OID_NTLMSSP.len()).position(|w| w == OID_NTLMSSP).unwrap();
        assert!(krb < ntlm, "kerberos must be advertised before ntlm");
        assert!(h.windows(OID_SPNEGO.len()).any(|w| w == OID_SPNEGO));
    }

    #[test]
    fn empty_mech_list_is_empty_hint() {
        assert!(neg_init_hint(&[]).is_empty());
    }

    #[test]
    fn classify_spnego_wrapped_kerberos_ap_req() {
        // A (fake) GSS AP-REQ: application-0 + KRB5 OID + token id + body.
        let mut gss_body = der_oid(OID_KRB5);
        gss_body.extend_from_slice(&[0x01, 0x00]); // AP-REQ token id
        gss_body.extend_from_slice(b"ap-req-bytes");
        let ap_req = der(0x60, &gss_body);
        // Wrap it in a SPNEGO NegTokenInit with mechTypes=[krb5] mechToken=ap_req.
        let mech_list = der(0xA0, &der(0x30, &der_oid(OID_KRB5)));
        let mech_tok = der(0xA2, &der(0x04, &ap_req));
        let mut init = mech_list;
        init.extend_from_slice(&mech_tok);
        let neg = der(0xA0, &der(0x30, &init));
        let mut body = der_oid(OID_SPNEGO);
        body.extend_from_slice(&neg);
        let blob = der(0x60, &body);

        let inc = classify(&blob);
        assert_eq!(inc.mech, Mech::Krb5);
        assert!(inc.spnego);
        assert_eq!(inc.token, ap_req.as_slice(), "token fed to acceptor is the GSS AP-REQ");
    }

    #[test]
    fn classify_raw_kerberos_token() {
        let mut gss_body = der_oid(OID_MS_KRB5);
        gss_body.extend_from_slice(&[0x01, 0x00]);
        gss_body.extend_from_slice(b"x");
        let blob = der(0x60, &gss_body);
        let inc = classify(&blob);
        assert_eq!(inc.mech, Mech::Krb5);
        assert!(!inc.spnego);
        assert_eq!(inc.token, blob.as_slice());
    }

    #[test]
    fn classify_raw_ntlmssp() {
        let mut blob = crate::ntlm_sig().to_vec();
        blob.extend_from_slice(&3u32.to_le_bytes());
        let inc = classify(&blob);
        assert_eq!(inc.mech, Mech::Ntlmssp);
        assert!(!inc.spnego);
    }

    #[test]
    fn neg_resp_roundtrip_shape() {
        let r = neg_resp(ACCEPT_INCOMPLETE, Mech::Krb5, b"ap-rep");
        // Re-classify our own NegTokenResp to confirm it parses back.
        let inc = classify(&r);
        assert_eq!(inc.mech, Mech::Krb5);
        assert!(inc.spnego);
        assert_eq!(inc.token, b"ap-rep");
    }

    #[test]
    fn malformed_blobs_do_not_panic() {
        for b in [&[][..], &[0x60], &[0x60, 0x82], &[0xA1, 0x05, 0x30], &[0x60, 0x7F]] {
            let _ = classify(b); // must not panic
        }
    }
}
