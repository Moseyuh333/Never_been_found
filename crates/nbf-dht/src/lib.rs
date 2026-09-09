//! NBF DHT: Kademlia thu nhỏ trên UDP (k=3, alpha=3), descriptor store/lookup.
//! Không directory trung tâm — thông tin node tự chủ, ký Ed25519.

pub mod kademlia;
pub mod rpc;
pub use rpc::*;