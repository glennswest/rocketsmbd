//! RustCrypto crypto backend (default) — pure-Rust primitives, no system
//! library. Selected unless `backend-openssl` is enabled (#29). The NTLM-only
//! primitives (MD4/MD5/RC4) live in `crypto.rs` and are always RustCrypto;
//! this backend covers the FIPS-able SMB2/3 primitives so an alternative
//! (OpenSSL) backend can be swapped in for FIPS deployments.

use aes::Aes128;
use aes_gcm::aead::{AeadInOut, Nonce, Tag};
use cmac::Cmac;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};

use super::{CIPHER_AES128_CCM, CIPHER_AES128_GCM, CIPHER_AES256_CCM, CIPHER_AES256_GCM};

type HmacSha256 = Hmac<Sha256>;

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

pub fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn aes128_cmac(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut m = <Cmac<Aes128> as KeyInit>::new_from_slice(key).expect("cmac key");
    for p in parts {
        m.update(p);
    }
    let out = m.finalize().into_bytes();
    out[..16].try_into().unwrap()
}

// AES-CCM with SMB3 parameters: 16-byte tag, 11-byte nonce.
type Ccm128 = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U11>;
type Ccm256 = ccm::Ccm<aes::Aes256, ccm::consts::U16, ccm::consts::U11>;

/// Seal `buf` in place with AEAD `C`; returns the 16-byte tag. Key and nonce
/// lengths are fixed by the SMB3 cipher, so a mismatch is a caller bug.
fn seal_with<C: AeadInOut + KeyInit>(key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    let nonce = Nonce::<C>::try_from(nonce).expect("aead nonce length");
    let tag = C::new_from_slice(key)
        .expect("aead key length")
        .encrypt_inout_detached(&nonce, aad, buf.into())
        .expect("aead seal");
    tag[..].try_into().expect("16-byte tag")
}

/// Open `buf` in place with AEAD `C`; false on a bad tag (or bad lengths).
fn open_with<C: AeadInOut + KeyInit>(key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> bool {
    let (Ok(c), Ok(nonce), Ok(tag)) = (
        C::new_from_slice(key),
        Nonce::<C>::try_from(nonce),
        Tag::<C>::try_from(&tag[..]),
    ) else {
        return false;
    };
    c.decrypt_inout_detached(&nonce, aad, buf.into(), &tag).is_ok()
}

pub fn aead_seal(cipher: u16, key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    match cipher {
        CIPHER_AES128_GCM => seal_with::<aes_gcm::Aes128Gcm>(key, nonce, aad, buf),
        CIPHER_AES256_GCM => seal_with::<aes_gcm::Aes256Gcm>(key, nonce, aad, buf),
        CIPHER_AES128_CCM => seal_with::<Ccm128>(key, nonce, aad, buf),
        CIPHER_AES256_CCM => seal_with::<Ccm256>(key, nonce, aad, buf),
        _ => panic!("unknown cipher {cipher:#x}"),
    }
}

pub fn aead_open(
    cipher: u16,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    match cipher {
        CIPHER_AES128_GCM => open_with::<aes_gcm::Aes128Gcm>(key, nonce, aad, buf, tag),
        CIPHER_AES256_GCM => open_with::<aes_gcm::Aes256Gcm>(key, nonce, aad, buf, tag),
        CIPHER_AES128_CCM => open_with::<Ccm128>(key, nonce, aad, buf, tag),
        CIPHER_AES256_CCM => open_with::<Ccm256>(key, nonce, aad, buf, tag),
        _ => false,
    }
}
