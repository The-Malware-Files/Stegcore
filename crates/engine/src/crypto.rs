// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use argon2::{Algorithm, Argon2, Params, Version};
use ascon_aead::Ascon128;
use chacha20poly1305::ChaCha20Poly1305;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::errors::StegError;

// ── Cipher ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cipher {
    #[serde(rename = "ascon-128")]
    Ascon128,
    #[serde(rename = "chacha20-poly1305")]
    ChaCha20Poly1305,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

impl Cipher {
    pub fn key_len(self) -> usize {
        match self {
            Cipher::Ascon128 => 16,
            Cipher::ChaCha20Poly1305 => 32,
            Cipher::Aes256Gcm => 32,
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            Cipher::Ascon128 => 16,
            Cipher::ChaCha20Poly1305 => 12,
            Cipher::Aes256Gcm => 12,
        }
    }
}

// ── Random material ───────────────────────────────────────────────────────────

const SALT_LEN: usize = 32;

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut buf = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn generate_nonce(cipher: Cipher) -> Vec<u8> {
    let mut buf = vec![0u8; cipher.nonce_len()];
    OsRng.fill_bytes(&mut buf);
    buf
}

// ── KDF ───────────────────────────────────────────────────────────────────────

pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    cipher: Cipher,
) -> Result<Zeroizing<Vec<u8>>, StegError> {
    let klen = cipher.key_len();
    let mut key = Zeroizing::new(vec![0u8; klen]);

    let params = Params::new(131072, 4, 2, Some(klen)).map_err(|_| StegError::CorruptedFile)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut_slice())
        .map_err(|_| StegError::DecryptionFailed)?;

    Ok(key)
}

// ── Compression ───────────────────────────────────────────────────────────────

pub fn compress(data: &[u8]) -> Result<Vec<u8>, StegError> {
    zstd::encode_all(data, 3).map_err(StegError::Io)
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>, StegError> {
    use std::io::Read;
    // Cap decompressed output at 256 MB to prevent decompression bombs.
    const MAX_DECOMP: u64 = 256 * 1024 * 1024;
    let cursor = std::io::Cursor::new(data);
    let decoder = zstd::Decoder::new(cursor).map_err(|_| StegError::CorruptedFile)?;
    let mut out = Vec::new();
    let n = decoder
        .take(MAX_DECOMP + 1)
        .read_to_end(&mut out)
        .map_err(|_| StegError::CorruptedFile)?;
    if n as u64 > MAX_DECOMP {
        return Err(StegError::CorruptedFile);
    }
    Ok(out)
}

// ── AEAD encrypt / decrypt ────────────────────────────────────────────────────

/// Compress then encrypt `plaintext`.
/// Returns `(ciphertext, nonce)` — both must be stored alongside the payload.
pub fn encrypt(
    key: &[u8],
    plaintext: &[u8],
    cipher: Cipher,
) -> Result<(Vec<u8>, Vec<u8>), StegError> {
    let compressed = compress(plaintext)?;
    let nonce_bytes = generate_nonce(cipher);

    let ciphertext = encrypt_raw(key, &compressed, &nonce_bytes, cipher)?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypt then decompress `ciphertext`.
pub fn decrypt(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    cipher: Cipher,
) -> Result<Vec<u8>, StegError> {
    if nonce.len() != cipher.nonce_len() {
        return Err(StegError::CorruptedFile);
    }
    let compressed = decrypt_raw(key, ciphertext, nonce, cipher)?;
    decompress(&compressed)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn encrypt_raw(
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    cipher: Cipher,
) -> Result<Vec<u8>, StegError> {
    match cipher {
        Cipher::Ascon128 => {
            if nonce.len() != 16 {
                return Err(StegError::CorruptedFile);
            }
            let c = Ascon128::new_from_slice(key).map_err(|_| StegError::CorruptedFile)?;
            let n = ascon_aead::Nonce::<Ascon128>::from_slice(nonce);
            c.encrypt(n, data).map_err(|_| StegError::DecryptionFailed)
        }
        Cipher::ChaCha20Poly1305 => {
            if nonce.len() != 12 {
                return Err(StegError::CorruptedFile);
            }
            let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| StegError::CorruptedFile)?;
            let n = chacha20poly1305::Nonce::from_slice(nonce);
            c.encrypt(n, data).map_err(|_| StegError::DecryptionFailed)
        }
        Cipher::Aes256Gcm => {
            if nonce.len() != 12 {
                return Err(StegError::CorruptedFile);
            }
            let c = Aes256Gcm::new_from_slice(key).map_err(|_| StegError::CorruptedFile)?;
            let n = aes_gcm::Nonce::from_slice(nonce);
            c.encrypt(n, data).map_err(|_| StegError::DecryptionFailed)
        }
    }
}

fn decrypt_raw(
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    cipher: Cipher,
) -> Result<Vec<u8>, StegError> {
    match cipher {
        Cipher::Ascon128 => {
            let c = Ascon128::new_from_slice(key).map_err(|_| StegError::CorruptedFile)?;
            let n = ascon_aead::Nonce::<Ascon128>::from_slice(nonce);
            c.decrypt(n, data).map_err(|_| StegError::DecryptionFailed)
        }
        Cipher::ChaCha20Poly1305 => {
            let c = ChaCha20Poly1305::new_from_slice(key).map_err(|_| StegError::CorruptedFile)?;
            let n = chacha20poly1305::Nonce::from_slice(nonce);
            c.decrypt(n, data).map_err(|_| StegError::DecryptionFailed)
        }
        Cipher::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(key).map_err(|_| StegError::CorruptedFile)?;
            let n = aes_gcm::Nonce::from_slice(nonce);
            c.decrypt(n, data).map_err(|_| StegError::DecryptionFailed)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"correct-horse-battery-staple";
    const PASS_WRONG: &[u8] = b"wrong-passphrase";

    fn round_trip(cipher: Cipher, payload: &[u8]) {
        let salt = generate_salt();
        let key = derive_key(PASS, &salt, cipher).expect("derive_key failed");
        let (ciphertext, nonce) = encrypt(&key, payload, cipher).expect("encrypt failed");
        let plaintext = decrypt(&key, &ciphertext, &nonce, cipher).expect("decrypt failed");
        assert_eq!(plaintext, payload, "round-trip failed for {cipher:?}");
    }

    #[test]
    fn round_trip_ascon128() {
        round_trip(Cipher::Ascon128, b"hello steganography");
    }

    #[test]
    fn round_trip_chacha20() {
        round_trip(Cipher::ChaCha20Poly1305, b"hello steganography");
    }

    #[test]
    fn round_trip_aes256gcm() {
        round_trip(Cipher::Aes256Gcm, b"hello steganography");
    }

    #[test]
    fn round_trip_empty_payload() {
        for cipher in [
            Cipher::Ascon128,
            Cipher::ChaCha20Poly1305,
            Cipher::Aes256Gcm,
        ] {
            round_trip(cipher, b"");
        }
    }

    #[test]
    fn round_trip_large_payload() {
        let payload = vec![0xABu8; 1_000_000];
        for cipher in [
            Cipher::Ascon128,
            Cipher::ChaCha20Poly1305,
            Cipher::Aes256Gcm,
        ] {
            round_trip(cipher, &payload);
        }
    }

    #[test]
    fn wrong_key_returns_decryption_failed() {
        let salt = generate_salt();
        let key_right = derive_key(PASS, &salt, Cipher::ChaCha20Poly1305).unwrap();
        let key_wrong = derive_key(PASS_WRONG, &salt, Cipher::ChaCha20Poly1305).unwrap();

        let (ciphertext, nonce) = encrypt(&key_right, b"secret", Cipher::ChaCha20Poly1305).unwrap();
        let result = decrypt(&key_wrong, &ciphertext, &nonce, Cipher::ChaCha20Poly1305);

        assert!(
            matches!(result, Err(StegError::DecryptionFailed)),
            "expected DecryptionFailed, got: {result:?}"
        );
    }

    #[test]
    fn corrupted_ciphertext_returns_decryption_failed() {
        let salt = generate_salt();
        let key = derive_key(PASS, &salt, Cipher::Aes256Gcm).unwrap();
        let (mut ciphertext, nonce) = encrypt(&key, b"secret data", Cipher::Aes256Gcm).unwrap();

        // Flip a byte in the middle of the ciphertext.
        let mid = ciphertext.len() / 2;
        ciphertext[mid] ^= 0xFF;

        let result = decrypt(&key, &ciphertext, &nonce, Cipher::Aes256Gcm);
        assert!(matches!(result, Err(StegError::DecryptionFailed)));
    }

    #[test]
    fn wrong_nonce_length_returns_corrupted_file() {
        let salt = generate_salt();
        let key = derive_key(PASS, &salt, Cipher::ChaCha20Poly1305).unwrap();
        let (ciphertext, _) = encrypt(&key, b"data", Cipher::ChaCha20Poly1305).unwrap();

        let bad_nonce = vec![0u8; 8]; // wrong length
        let result = decrypt(&key, &ciphertext, &bad_nonce, Cipher::ChaCha20Poly1305);
        assert!(matches!(result, Err(StegError::CorruptedFile)));
    }

    #[test]
    fn kdf_is_deterministic() {
        let salt = generate_salt();
        let k1 = derive_key(PASS, &salt, Cipher::ChaCha20Poly1305).unwrap();
        let k2 = derive_key(PASS, &salt, Cipher::ChaCha20Poly1305).unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn kdf_different_salts_produce_different_keys() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        let k1 = derive_key(PASS, &s1, Cipher::ChaCha20Poly1305).unwrap();
        let k2 = derive_key(PASS, &s2, Cipher::ChaCha20Poly1305).unwrap();
        assert_ne!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn cipher_serde_roundtrip() {
        let cases = [
            (Cipher::Ascon128, "\"ascon-128\""),
            (Cipher::ChaCha20Poly1305, "\"chacha20-poly1305\""),
            (Cipher::Aes256Gcm, "\"aes-256-gcm\""),
        ];
        for (cipher, expected_json) in cases {
            let json = serde_json::to_string(&cipher).unwrap();
            assert_eq!(json, expected_json);
            let back: Cipher = serde_json::from_str(&json).unwrap();
            assert_eq!(back, cipher);
        }
    }

    #[test]
    fn compress_reduces_compressible_data() {
        let data = vec![0u8; 10_000]; // highly compressible
        let compressed = compress(&data).unwrap();
        assert!(
            compressed.len() < data.len(),
            "compression did not reduce size"
        );
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let compressed = compress(data).unwrap();
        let restored = decompress(&compressed).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn decompress_garbage_returns_corrupted_file() {
        let result = decompress(b"this is not valid zstd data");
        assert!(matches!(result, Err(StegError::CorruptedFile)));
    }
}
