//! Minimal NTLMSSP for guest/anonymous sessions (phase 1).
//!
//! We accept any AUTHENTICATE token and grant a guest session. The CHALLENGE
//! we emit is well-formed (target name + AV pairs) so NTLMv2 clients can
//! compute a response, which we do not verify yet. Real verification and
//! signing key derivation are phase 2.

use crate::wire::{utf16le, Put};

pub const SIG: &[u8; 8] = b"NTLMSSP\0";

#[derive(Debug, PartialEq, Eq)]
pub enum Token {
    Negotiate,
    Authenticate,
    Other,
}

/// Locate an NTLMSSP token inside a raw or SPNEGO-wrapped blob and classify
/// it. Searching for the signature avoids a full ASN.1 parser.
pub fn classify(blob: &[u8]) -> Token {
    let Some(p) = find(blob, SIG) else {
        return Token::Other;
    };
    let rest = &blob[p + 8..];
    if rest.len() < 4 {
        return Token::Other;
    }
    match u32::from_le_bytes(rest[..4].try_into().unwrap()) {
        1 => Token::Negotiate,
        3 => Token::Authenticate,
        _ => Token::Other,
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

const FLAGS: u32 = 0x0000_0001  // UNICODE
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_raw() {
        let mut t1 = SIG.to_vec();
        t1.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(classify(&t1), Token::Negotiate);
        let mut t3 = vec![0xA1, 0x82, 0x01, 0x00]; // fake SPNEGO prefix
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
        // Server challenge at offset 24.
        assert_eq!(&c[24..32], &[7; 8]);
        // Target name offset points at "SRV" in UTF-16LE.
        let off = u32::from_le_bytes(c[16..20].try_into().unwrap()) as usize;
        assert_eq!(&c[off..off + 6], &utf16le("SRV")[..]);
    }
}
