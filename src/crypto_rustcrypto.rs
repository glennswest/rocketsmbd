//! RustCrypto crypto backend (default) — pure-Rust primitives, no system
//! library. Selected unless `backend-openssl` is enabled (#29). The NTLM-only
//! primitives (MD4/MD5/RC4) live in `crypto.rs` and are always RustCrypto;
//! this backend covers the FIPS-able SMB2/3 primitives so an alternative
//! (OpenSSL) backend can be swapped in for FIPS deployments.

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
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
    let mut m = <Cmac<Aes128> as Mac>::new_from_slice(key).expect("cmac key");
    for p in parts {
        m.update(p);
    }
    let out = m.finalize().into_bytes();
    out[..16].try_into().unwrap()
}

// AES-CCM with SMB3 parameters: 16-byte tag, 11-byte nonce.
type Ccm128 = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U11>;
type Ccm256 = ccm::Ccm<aes::Aes256, ccm::consts::U16, ccm::consts::U11>;

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
