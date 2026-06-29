//! Crypto constructions for NTLMv2 and SMB2/3 signing.
//!
//! Primitives come from RustCrypto; this module owns the SMB-specific
//! compositions: the SP800-108 counter-mode KDF used for SMB3 signing keys,
//! RC4 for the NTLM key exchange, and the two wire signature algorithms.

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub type HmacSha256 = Hmac<Sha256>;

// ------------------------------------------------ NTLM-only legacy primitives
// MD4 (NT hash), HMAC-MD5 (NTLMv2), and RC4 (NTLMSSP key exchange) are used
// only by the NTLM auth path and are the primitives a FIPS/OpenSSL backend
// cannot provide. Gated behind the `ntlm` feature (#30).

#[cfg(feature = "ntlm")]
pub type HmacMd5 = Hmac<md5::Md5>;

#[cfg(feature = "ntlm")]
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut m = HmacMd5::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// NT hash: MD4 of the UTF-16LE password.
#[cfg(feature = "ntlm")]
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
#[cfg(feature = "ntlm")]
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

// ----------------------------------------------------------- SMB3 encryption

// SMB3 cipher ids (MS-SMB2 SMB2_ENCRYPTION_CAPABILITIES), in preference order.
pub const CIPHER_AES128_CCM: u16 = 0x0001;
pub const CIPHER_AES128_GCM: u16 = 0x0002;
pub const CIPHER_AES256_CCM: u16 = 0x0003;
pub const CIPHER_AES256_GCM: u16 = 0x0004;

/// AES key length for a cipher (16 = 128-bit, 32 = 256-bit).
pub fn cipher_key_len(cipher: u16) -> usize {
    match cipher {
        CIPHER_AES256_GCM | CIPHER_AES256_CCM => 32,
        _ => 16,
    }
}

/// AEAD nonce length: GCM uses 12 bytes, CCM uses 11 (MS-SMB2 3.1.1).
pub fn cipher_nonce_len(cipher: u16) -> usize {
    match cipher {
        CIPHER_AES128_CCM | CIPHER_AES256_CCM => 11,
        _ => 12,
    }
}

/// SP800-108 counter-mode KDF (HMAC-SHA256) producing `out_bits/8` bytes.
fn kdf(key: &[u8], label: &[u8], context: &[u8], out_bits: u32) -> Vec<u8> {
    let out_bytes = (out_bits / 8) as usize;
    let mut out = Vec::with_capacity(out_bytes + 32);
    let mut counter = 1u32;
    while out.len() < out_bytes {
        let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
        m.update(&counter.to_be_bytes());
        m.update(label);
        m.update(&[0]);
        m.update(context);
        m.update(&out_bits.to_be_bytes());
        out.extend_from_slice(&m.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(out_bytes);
    out
}

/// Derive the SMB 3.1.1 encryption keys for `cipher` from the session key and
/// preauth hash: (client→server decrypt key, server→client encrypt key). Keys
/// are returned in 32-byte buffers; only the first `cipher_key_len` bytes are
/// used (16 for AES-128, 32 for AES-256).
pub fn smb311_encryption_keys(
    cipher: u16,
    session_key: &[u8; 16],
    preauth: &[u8; 64],
) -> ([u8; 32], [u8; 32]) {
    let bits = (cipher_key_len(cipher) * 8) as u32;
    let c2s = kdf(session_key, b"SMBC2SCipherKey\0", preauth, bits);
    let s2c = kdf(session_key, b"SMBS2CCipherKey\0", preauth, bits);
    let mut c = [0u8; 32];
    let mut s = [0u8; 32];
    c[..c2s.len()].copy_from_slice(&c2s);
    s[..s2c.len()].copy_from_slice(&s2c);
    (c, s)
}

/// SMB3 AEAD seal: encrypt `buf` in place for `cipher` and return the 16-byte
/// tag. `key`/`nonce` must be the cipher's correct length (see cipher_key_len /
/// cipher_nonce_len); `aad` is the authenticated TRANSFORM_HEADER bytes.
pub fn aead_seal(cipher: u16, key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use ccm::aead::generic_array::GenericArray;
    match cipher {
        CIPHER_AES128_GCM => aes_gcm::Aes128Gcm::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf)
            .expect("gcm")
            .into(),
        CIPHER_AES256_GCM => aes_gcm::Aes256Gcm::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf)
            .expect("gcm")
            .into(),
        CIPHER_AES128_CCM => Ccm128::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf)
            .expect("ccm")
            .into(),
        CIPHER_AES256_CCM => Ccm256::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf)
            .expect("ccm")
            .into(),
        _ => panic!("unknown cipher {cipher:#x}"),
    }
}

/// SMB3 AEAD open: verify the tag and decrypt `buf` in place. Returns false on
/// authentication failure.
pub fn aead_open(
    cipher: u16,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use ccm::aead::generic_array::GenericArray;
    match cipher {
        CIPHER_AES128_GCM => aes_gcm::Aes128Gcm::new(GenericArray::from_slice(key))
            .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf, tag.into())
            .is_ok(),
        CIPHER_AES256_GCM => aes_gcm::Aes256Gcm::new(GenericArray::from_slice(key))
            .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf, tag.into())
            .is_ok(),
        CIPHER_AES128_CCM => Ccm128::new(GenericArray::from_slice(key))
            .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf, tag.into())
            .is_ok(),
        CIPHER_AES256_CCM => Ccm256::new(GenericArray::from_slice(key))
            .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf, tag.into())
            .is_ok(),
        _ => false,
    }
}

// AES-CCM with SMB3 parameters: 16-byte tag, 11-byte nonce.
type Ccm128 = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U11>;
type Ccm256 = ccm::Ccm<aes::Aes256, ccm::consts::U16, ccm::consts::U11>;

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[cfg(feature = "ntlm")]
    #[test]
    fn nt_hash_classic() {
        // The canonical NT hash of "password".
        assert_eq!(nt_hash("password").to_vec(), hex("8846f7eaee8fb117ad06bdd830b7586c"));
    }

    #[cfg(feature = "ntlm")]
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

    #[cfg(feature = "ntlm")]
    #[test]
    fn rc4_known() {
        assert_eq!(rc4(b"Key", b"Plaintext"), hex("bbf316e8d940af0ad3"));
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let aad = b"smb2-transform-header-aad";
        let plain = b"the quick brown fox jumps over the lazy SMB share".to_vec();
        for &cipher in &[
            CIPHER_AES128_GCM,
            CIPHER_AES256_GCM,
            CIPHER_AES128_CCM,
            CIPHER_AES256_CCM,
        ] {
            let key = vec![0x11u8; cipher_key_len(cipher)];
            let nonce = vec![0x22u8; cipher_nonce_len(cipher)];
            let mut buf = plain.clone();
            let tag = aead_seal(cipher, &key, &nonce, aad, &mut buf);
            assert_ne!(buf, plain, "ct must differ ({cipher:#x})");
            let mut dec = buf.clone();
            assert!(aead_open(cipher, &key, &nonce, aad, &mut dec, &tag), "open {cipher:#x}");
            assert_eq!(dec, plain, "recover {cipher:#x}");
            // Tampered tag, wrong AAD, and wrong key must all fail.
            let mut t = tag;
            t[0] ^= 1;
            assert!(!aead_open(cipher, &key, &nonce, aad, &mut buf.clone(), &t));
            assert!(!aead_open(cipher, &key, &nonce, b"other", &mut buf.clone(), &tag));
            let bad = vec![0u8; cipher_key_len(cipher)];
            assert!(!aead_open(cipher, &bad, &nonce, aad, &mut buf.clone(), &tag));
        }
    }

    #[test]
    fn enc_keys_deterministic_and_distinct() {
        let sk = [7u8; 16];
        let pa = [9u8; 64];
        // AES-128 keys use 16 bytes; AES-256 keys use 32.
        let (c2s, s2c) = smb311_encryption_keys(CIPHER_AES128_GCM, &sk, &pa);
        assert_ne!(c2s, s2c);
        let (c2s2, _) = smb311_encryption_keys(CIPHER_AES128_GCM, &sk, &pa);
        assert_eq!(c2s, c2s2, "deterministic");
        let (c256, _) = smb311_encryption_keys(CIPHER_AES256_GCM, &sk, &pa);
        assert_ne!(&c256[..32], &[0u8; 32], "256-bit key fills 32 bytes");
        assert_ne!(c256, c2s, "128 and 256 derivations differ");
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
