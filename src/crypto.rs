//! Crypto constructions for NTLMv2 and SMB2/3 signing.
//!
//! Primitives come from RustCrypto; this module owns the SMB-specific
//! compositions: the SP800-108 counter-mode KDF used for SMB3 signing keys,
//! RC4 for the NTLM key exchange, and the two wire signature algorithms.

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256, Sha512};

pub type HmacMd5 = Hmac<Md5>;
pub type HmacSha256 = Hmac<Sha256>;

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = HmacMd5::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// NT hash: MD4 of the UTF-16LE password.
pub fn nt_hash(password: &str) -> [u8; 16] {
    use md4::Md4;
    let mut h = Md4::new();
    h.update(crate::wire::utf16le(password));
    h.finalize().into()
}

pub fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// SP800-108 KDF in counter mode with HMAC-SHA256, 128-bit output — the
/// SMB3 key derivation (MS-SMB2 3.1.4.2). `label` and `context` are used
/// exactly as given (the spec's labels include their trailing NUL).
pub fn kdf128(key: &[u8; 16], label: &[u8], context: &[u8]) -> [u8; 16] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    m.update(&1u32.to_be_bytes());
    m.update(label);
    m.update(&[0]);
    m.update(context);
    m.update(&128u32.to_be_bytes());
    let out = m.finalize().into_bytes();
    out[..16].try_into().unwrap()
}

/// RC4 — used only for the NTLMSSP EncryptedRandomSessionKey unwrap.
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j
            .wrapping_add(s[i])
            .wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            b ^ s[(s[i as usize].wrapping_add(s[j as usize])) as usize]
        })
        .collect()
}

/// Which signature goes on the wire for a given dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlg {
    /// SMB 2.0.2 / 2.1: HMAC-SHA256(session key)
    HmacSha256,
    /// SMB 3.x: AES-128-CMAC(derived signing key)
    AesCmac,
}

/// Compute the 16-byte SMB2 signature over a message supplied in parts
/// (so callers can substitute a zeroed signature field without copying).
pub fn smb2_signature(alg: SignAlg, key: &[u8; 16], parts: &[&[u8]]) -> [u8; 16] {
    match alg {
        SignAlg::HmacSha256 => {
            let mut m = HmacSha256::new_from_slice(key).unwrap();
            for p in parts {
                m.update(p);
            }
            let out = m.finalize().into_bytes();
            out[..16].try_into().unwrap()
        }
        SignAlg::AesCmac => {
            let mut m = <Cmac<Aes128> as Mac>::new_from_slice(key).unwrap();
            for p in parts {
                m.update(p);
            }
            let out = m.finalize().into_bytes();
            out[..16].try_into().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn nt_hash_classic() {
        // The canonical NT hash of "password".
        assert_eq!(nt_hash("password").to_vec(), hex("8846f7eaee8fb117ad06bdd830b7586c"));
    }

    #[test]
    fn hmac_md5_reference() {
        // Verified against Python: hmac.new(b"Jefe", b"what do ya wanna do
        // for nothing?", hashlib.md5)
        let mac = hmac_md5(b"Jefe", b"what do ya wanna do for nothing?");
        assert_eq!(mac.to_vec(), hex("78eb0e153d16ebb2a9a5c3be5965c8ab"));
    }

    #[test]
    fn hmac_sha256_rfc4231() {
        let sig = smb2_signature(
            SignAlg::HmacSha256,
            &[0x0b; 16],
            &[b"Hi There"],
        );
        // RFC 4231 case 1 uses a 20-byte key; recompute the truncated
        // variant independently with the hmac crate to pin our part-feeding.
        let mut m = HmacSha256::new_from_slice(&[0x0b; 16]).unwrap();
        m.update(b"Hi There");
        assert_eq!(sig.to_vec(), m.finalize().into_bytes()[..16].to_vec());
    }

    #[test]
    fn cmac_rfc4493() {
        let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let sig = smb2_signature(SignAlg::AesCmac, &key, &[]);
        assert_eq!(sig.to_vec(), hex("bb1d6929e95937287fa37d129b756746"));
        let msg = hex("6bc1bee22e409f96e93d7e117393172a");
        // Feed in two parts to exercise chunked updates.
        let sig = smb2_signature(SignAlg::AesCmac, &key, &[&msg[..7], &msg[7..]]);
        assert_eq!(sig.to_vec(), hex("070a16b46b4d4144f79bdd9dd04a287c"));
    }

    #[test]
    fn rc4_known() {
        assert_eq!(rc4(b"Key", b"Plaintext"), hex("bbf316e8d940af0ad3"));
    }

    #[test]
    fn kdf128_structure() {
        // Pin the exact SP800-108 message layout against a manual HMAC.
        let key = [7u8; 16];
        let label = b"SMB2AESCMAC\0";
        let ctx = b"SmbSign\0";
        let mut m = HmacSha256::new_from_slice(&key).unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(&1u32.to_be_bytes());
        msg.extend_from_slice(label);
        msg.push(0);
        msg.extend_from_slice(ctx);
        msg.extend_from_slice(&128u32.to_be_bytes());
        m.update(&msg);
        let expect = &m.finalize().into_bytes()[..16];
        assert_eq!(kdf128(&key, label, ctx).to_vec(), expect.to_vec());
    }
}
