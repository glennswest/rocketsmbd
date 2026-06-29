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

fn cipher_for(cipher: u16) -> Cipher {
    match cipher {
        CIPHER_AES128_GCM => Cipher::aes_128_gcm(),
        CIPHER_AES256_GCM => Cipher::aes_256_gcm(),
        CIPHER_AES128_CCM => Cipher::aes_128_ccm(),
        CIPHER_AES256_CCM => Cipher::aes_256_ccm(),
        _ => panic!("unknown cipher {cipher:#x}"),
    }
}

pub fn aead_seal(cipher: u16, key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
    let mut tag = [0u8; 16];
    // OpenSSL's high-level AEAD allocates the ciphertext; copy it back in place.
    let ct = encrypt_aead(cipher_for(cipher), key, Some(nonce), aad, buf, &mut tag)
        .expect("aead seal");
    debug_assert_eq!(ct.len(), buf.len());
    buf.copy_from_slice(&ct);
    tag
}

pub fn aead_open(
    cipher: u16,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    match decrypt_aead(cipher_for(cipher), key, Some(nonce), aad, buf, tag) {
        Ok(pt) => {
            buf.copy_from_slice(&pt);
            true
        }
        Err(_) => false,
    }
}
