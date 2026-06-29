//! OpenSSL crypto backend (#29) — routes the FIPS-able SMB2/3 primitives
//! through the system OpenSSL (the `openssl` crate). Selected by
//! `--features backend-openssl`. Links system libcrypto, so it is a
//! dynamically-linked build (incompatible with the static-musl `scratch`
//! container) — the intended profile for FIPS deployments where OpenSSL is the
//! validated module. See docs/KERBEROS.md / docs/FIPS notes.
//!
//! Built/validated on a Linux host with `openssl-devel`; the symbol surface of
//! the `openssl` crate is stable across 0.10.x.

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};

use super::{CIPHER_AES128_CCM, CIPHER_AES128_GCM, CIPHER_AES256_CCM, CIPHER_AES256_GCM};

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let pkey = PKey::hmac(key).expect("hmac key");
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("hmac signer");
    for p in parts {
        signer.update(p).expect("hmac update");
    }
    let mut out = [0u8; 32];
    let n = signer.sign(&mut out).expect("hmac sign");
    debug_assert_eq!(n, 32);
    out
}

pub fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = openssl::hash::Hasher::new(MessageDigest::sha512()).expect("sha512");
    for p in parts {
        h.update(p).expect("sha512 update");
    }
    let d = h.finish().expect("sha512 finish");
    let mut out = [0u8; 64];
    out.copy_from_slice(&d);
    out
}

pub fn aes128_cmac(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    // CMAC-AES128 via a CMAC PKey + Signer (no digest).
    let pkey = PKey::cmac(&Cipher::aes_128_cbc(), key).expect("cmac key");
    let mut signer = Signer::new_without_digest(&pkey).expect("cmac signer");
    for p in parts {
        signer.update(p).expect("cmac update");
    }
    let mac = signer.sign_to_vec().expect("cmac sign");
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    out
}

fn gcm_cipher(cipher: u16) -> Option<Cipher> {
    match cipher {
        CIPHER_AES128_GCM => Some(Cipher::aes_128_gcm()),
        CIPHER_AES256_GCM => Some(Cipher::aes_256_gcm()),
        _ => None,
    }
}

pub fn aead_seal(cipher: u16, key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    // AES-GCM (the SMB3 default and the FIPS-relevant cipher) goes through
    // OpenSSL. OpenSSL's one-shot AEAD does not handle AES-CCM's length-prefix
    // requirement, and CCM is rarely negotiated, so CCM stays on the pure-Rust
    // `ccm` crate (a FIPS deployment negotiates GCM anyway). See #29.
    match gcm_cipher(cipher) {
        Some(c) => {
            let mut tag = [0u8; 16];
            let ct = encrypt_aead(c, key, Some(nonce), aad, buf, &mut tag).expect("gcm seal");
            debug_assert_eq!(ct.len(), buf.len());
            buf.copy_from_slice(&ct);
            tag
        }
        None => ccm_fallback::seal(cipher, key, nonce, aad, buf),
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
    match gcm_cipher(cipher) {
        Some(c) => match decrypt_aead(c, key, Some(nonce), aad, buf, tag) {
            Ok(pt) => {
                buf.copy_from_slice(&pt);
                true
            }
            Err(_) => false,
        },
        None => ccm_fallback::open(cipher, key, nonce, aad, buf, tag),
    }
}

/// AES-CCM via the pure-Rust `ccm` crate (OpenSSL's one-shot AEAD can't do CCM).
mod ccm_fallback {
    use super::{CIPHER_AES128_CCM, CIPHER_AES256_CCM};

    type Ccm128 = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U11>;
    type Ccm256 = ccm::Ccm<aes::Aes256, ccm::consts::U16, ccm::consts::U11>;

    pub fn seal(cipher: u16, key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        use ccm::aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
        match cipher {
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

    pub fn open(cipher: u16, key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> bool {
        use ccm::aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
        match cipher {
            CIPHER_AES128_CCM => Ccm128::new(GenericArray::from_slice(key))
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf, tag.into())
                .is_ok(),
            CIPHER_AES256_CCM => Ccm256::new(GenericArray::from_slice(key))
                .decrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buf, tag.into())
                .is_ok(),
            _ => false,
        }
    }
}
