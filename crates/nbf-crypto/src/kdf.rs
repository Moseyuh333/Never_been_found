//! KDF lai (X25519 ‖ ML-KEM) + nonce + AEAD ChaCha20-Poly1305.
//! Mọi nonce được suy ra tất định từ (tag, dir/position, seq) — không bao giờ tái dùng
//! cùng (key, nonce) vì seq đơn điệu cho từng chiều của từng circuit.

use crate::{CryptoError, DIR_BWD, DIR_FWD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const INFO_HDR: &[u8] = b"nbf/hdr/v1";
const INFO_TRAFFIC: &[u8] = b"nbf/traffic/v1";

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).expect("độ dài OKM hợp lệ");
    okm
}

/// Khóa mã hóa một lớp Sphinx header (chỉ từ X25519 ss — KEM ct nằm trong lớp).
pub fn derive_hdr_key(ss_x: &[u8; 32], tag: &[u8; 16]) -> [u8; 32] {
    let v = hkdf(ss_x, tag, INFO_HDR, 32);
    v.try_into().unwrap()
}

/// Khóa traffic (fwd, bwd) của một hop = HKDF(X25519 ‖ ML-KEM) — PQC lai.
pub fn derive_traffic_keys(ss_x: &[u8; 32], ss_kem: &[u8; 32], tag: &[u8; 16]) -> ([u8; 32], [u8; 32]) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ss_x);
    ikm[32..].copy_from_slice(ss_kem);
    let v = hkdf(&ikm, tag, INFO_TRAFFIC, 64);
    let f: [u8; 32] = v[..32].try_into().unwrap();
    let b: [u8; 32] = v[32..].try_into().unwrap();
    (f, b)
}

/// Nonce lớp header: vị trí trong chuỗi = giá trị `n` mà hop nhìn thấy.
pub fn hdr_nonce(tag: &[u8; 16], n_field: u8) -> [u8; 12] {
    let h = Sha256::new().chain_update(tag).chain_update(b"hdr").chain_update([n_field]).finalize();
    h[..12].try_into().unwrap()
}

/// Nonce relay: (tag, chiều, số thứ tự) — seq đơn điệu từng chiều, chặn replay.
pub fn relay_nonce(tag: &[u8; 16], dir: u8, seq: u32) -> [u8; 12] {
    debug_assert!(dir == DIR_FWD || dir == DIR_BWD);
    let h = Sha256::new().chain_update(tag).chain_update([dir]).chain_update(seq.to_le_bytes()).finalize();
    h[..12].try_into().unwrap()
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let c = ChaCha20Poly1305::new(Key::from_slice(key));
    c.encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: b"nbf" })
        .expect("mã hóa luôn thành công")
}

pub fn open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let c = ChaCha20Poly1305::new(Key::from_slice(key));
    c.decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: b"nbf" })
        .map_err(|_| CryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_xac_dinh_nhau_cung_input() {
        let a = derive_hdr_key(&[1u8; 32], &[9u8; 16]);
        let b = derive_hdr_key(&[1u8; 32], &[9u8; 16]);
        assert_eq!(a, b);
    }

    #[test]
    fn doi_tag_hay_ss_thi_khoa_doi() {
        assert_ne!(derive_hdr_key(&[1; 32], &[9; 16]), derive_hdr_key(&[1; 32], &[8; 16]));
        assert_ne!(derive_hdr_key(&[1; 32], &[9; 16]), derive_hdr_key(&[2; 32], &[9; 16]));
    }

    #[test]
    fn khoa_traffic_hop_le_va_fwd_khac_bwd() {
        let (f, b) = derive_traffic_keys(&[1; 32], &[2; 32], &[3; 16]);
        assert_ne!(f, b);
        assert_ne!(f, [0u8; 32]);
    }

    #[test]
    fn nonce_doi_theo_dir_va_seq() {
        let t = [7u8; 16];
        assert_ne!(hdr_nonce(&t, 3), hdr_nonce(&t, 2));
        assert_ne!(relay_nonce(&t, DIR_FWD, 1), relay_nonce(&t, DIR_BWD, 1));
        assert_ne!(relay_nonce(&t, DIR_FWD, 1), relay_nonce(&t, DIR_FWD, 2));
    }

    #[test]
    fn aead_roundtrip_va_sua_hong_loi() {
        let k = [5u8; 32];
        let n = [6u8; 12];
        let ct = seal(&k, &n, b"hello from the void");
        assert_eq!(open(&k, &n, &ct).unwrap(), b"hello from the void");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(&k, &n, &bad).is_err());
        assert_eq!(ct.len(), 19 + 16); // plaintext + tag Poly1305
    }
}