//! NBF crypto thuần: định danh, KDF lai, Sphinx. Không I/O mạng.

pub mod identity;
pub mod kdf;
pub mod kem;
pub mod replay;
pub mod sphinx;

// re-export tiện dùng cho các crate khác:
pub use curve25519_dalek::montgomery::MontgomeryPoint;
pub use curve25519_dalek::Scalar;
pub use ed25519_dalek::SigningKey;
pub use identity::{
    node_id_from_ed_pub, x25519_pub_from_clamped, Descriptor, NodeIdentity, DESC_LEN,
};
pub use kdf::{derive_hdr_key, derive_traffic_keys, hdr_nonce, open, relay_nonce, seal};
pub use kem::{kem_decap, kem_encap};
pub use sphinx::{build_header, process_header, BuiltHeader, ProcessOutcome};

/// ID node 160-bit: SHA-256(Ed25519 pub) cắt 20 byte đầu.
pub type NodeId = [u8; 20];

/// Độ dài ciphertext ML-KEM-768.
pub const CT_LEN: usize = 1088;
/// Độ dài public key ML-KEM-768.
pub const KEM_PK_LEN: usize = 1184;
/// Một lớp Sphinx: next(20B) + ip(4B) + port(2B) + link_pub(32B) + pad(6B) + ct(1088B).
pub const LAYER_INFO_LEN: usize = 64 + CT_LEN;
/// Một lớp Sphinx: AEAD-tag(16B) + info.
pub const LAYER_LEN: usize = 16 + LAYER_INFO_LEN;
/// Số hop tối đa trong một route.
pub const MAX_HOPS: usize = 5;
/// node_id đánh dấu "đích cuối" trong thông tin routing.
pub const TERMINAL_ID: NodeId = [0xFF; 20];
/// Chiều forward (origin → terminal).
pub const DIR_FWD: u8 = 0;
/// Chiều backward (terminal → origin).
pub const DIR_BWD: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("độ dài dữ liệu không đúng: {0}")]
    BadLength(usize),
    #[error("AEAD mở thất bại (sai key hoặc dữ liệu hỏng)")]
    Aead,
    #[error("ML-KEM thất bại")]
    Kem,
    #[error("Noise thất bại: {0}")]
    Noise(String),
    #[error("header Sphinx không hợp lệ")]
    Sphinx,
    #[error("descriptor không hợp lệ")]
    Descriptor,
    #[error("chữ ký Ed25519 sai")]
    Ed25519,
}
