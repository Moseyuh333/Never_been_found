//! NBF net: cell, link Noise-IK, engine circuit, cover traffic.

pub mod builder;
pub mod cell;
pub mod cover;
pub mod link;
pub mod node;
pub mod relay;
pub use builder::*;
pub use cell::*;

use nbf_crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("độ dài không hợp lệ: {0}")]
    BadLength(usize),
    #[error("cmd không hợp lệ: {0}")]
    BadCmd(u8),
    #[error("payload quá ngắn")]
    TooShort,
    #[error("hết thời gian chờ")]
    Timeout,
    #[error("chưa có session/circuit")]
    NoSession,
    #[error("lỗi crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("lỗi I/O: {0}")]
    Io(String),
}