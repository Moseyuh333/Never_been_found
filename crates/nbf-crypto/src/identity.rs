//! Định danh node (Ed25519 + X25519 link + Scalar Sphinx + ML-KEM) và descriptor tự chủ.

use crate::kem::kem_generate;
use crate::{CryptoError, NodeId, KEM_PK_LEN};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};

pub const DESC_LEN: usize = 4 + 1 + 20 + 32 + 32 + 32 + KEM_PK_LEN + 4 + 2 + 2 + 8 + 64; // 1385
const DESC_MAGIC: [u8; 4] = *b"NBFD";
const DESC_VER: u8 = 1;

/// Bộ khóa đầy đủ của một node NBF.
pub struct NodeIdentity {
    pub ed: SigningKey,
    /// khóa static của link Noise (clamped theo quy tắc X25519).
    pub link_priv: [u8; 32],
    pub link_pub: [u8; 32],
    /// khóa mù (blinding) của header Sphinx.
    pub sphinx_priv: crate::Scalar,
    pub sphinx_pub: [u8; 32],
    pub kem_sk: crate::kem::DecapsKey,
    pub kem_pk: [u8; KEM_PK_LEN],
}

impl NodeIdentity {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let ed = SigningKey::generate(rng);
        // link key: 32 byte ngẫu nhiên, clamp đúng quy tắc x25519 (để khớp công thức pub = a×G).
        let mut link_priv = [0u8; 32];
        rng.fill_bytes(&mut link_priv);
        link_priv[0] &= 248;
        link_priv[31] &= 127;
        link_priv[31] |= 64;
        let link_pub = x25519_pub_from_clamped(&link_priv);
        let sphinx_priv = crate::Scalar::random(rng);
        let sphinx_pub = crate::MontgomeryPoint::mul_base(&sphinx_priv).to_bytes();
        let (kem_sk, kem_pk) = kem_generate(rng);
        Self {
            ed,
            link_priv,
            link_pub,
            sphinx_priv,
            sphinx_pub,
            kem_sk,
            kem_pk,
        }
    }

    pub fn node_id(&self) -> NodeId {
        node_id_from_ed_pub(self.ed.verifying_key().as_bytes())
    }

    /// Ký một message bằng khóa Ed25519 (dùng cho descriptor).
    pub fn sign_ed(&self, msg: &[u8]) -> [u8; 64] {
        self.ed.sign(msg).to_bytes()
    }
}

pub fn node_id_from_ed_pub(ed_pub: &[u8; 32]) -> NodeId {
    let h = Sha256::digest(ed_pub);
    let mut id = [0u8; 20];
    id.copy_from_slice(&h[..20]);
    id
}

/// X25519 pub từ private clamped (a × G Montgomery).
pub fn x25519_pub_from_clamped(priv_clamped: &[u8; 32]) -> [u8; 32] {
    crate::MontgomeryPoint::mul_base(&crate::Scalar::from_bytes_mod_order(*priv_clamped)).to_bytes()
}

/// Descriptor node — dữ liệu công khai, tự chủ, ký Ed25519, hết hạn do DHT kiểm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub node_id: NodeId,
    pub ed_pub: [u8; 32],
    pub link_pub: [u8; 32],
    pub sphinx_pub: [u8; 32],
    pub kem_pk: [u8; KEM_PK_LEN],
    pub cell_addr: SocketAddr,
    pub dht_port: u16,
    pub ts: u64,
    pub sig: [u8; 64],
}

impl Descriptor {
    pub fn sign(id: &NodeIdentity, cell_addr: SocketAddr, dht_port: u16, now_unix: u64) -> Self {
        let mut d = Descriptor {
            node_id: id.node_id(),
            ed_pub: *id.ed.verifying_key().as_bytes(),
            link_pub: id.link_pub,
            sphinx_pub: id.sphinx_pub,
            kem_pk: id.kem_pk,
            cell_addr,
            dht_port,
            ts: now_unix,
            sig: [0u8; 64],
        };
        let signing = d.signing_bytes();
        d.sig = id.sign_ed(&signing);
        d
    }

    /// Địa chỉ DHT đầy đủ từ descriptor (tiện dùng cho Kademlia).
    pub fn dht_addr(&self) -> std::net::SocketAddr {
        let ip = match self.cell_addr.ip() {
            std::net::IpAddr::V4(v) => v,
            _ => std::net::Ipv4Addr::UNSPECIFIED,
        };
        std::net::SocketAddr::new(std::net::IpAddr::V4(ip), self.dht_port)
    }

    /// Phần được ký = toàn bộ descriptor trừ 64 byte sig cuối.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = self.to_bytes();
        let n = b.len() - 64;
        b.truncate(n);
        b
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(DESC_LEN);
        b.extend_from_slice(&DESC_MAGIC);
        b.push(DESC_VER);
        b.extend_from_slice(&self.node_id);
        b.extend_from_slice(&self.ed_pub);
        b.extend_from_slice(&self.link_pub);
        b.extend_from_slice(&self.sphinx_pub);
        b.extend_from_slice(&self.kem_pk);
        match self.cell_addr.ip() {
            IpAddr::V4(ip) => b.extend_from_slice(&ip.octets()),
            _ => panic!("v1 chỉ hỗ trợ IPv4"),
        }
        b.extend_from_slice(&self.cell_addr.port().to_le_bytes());
        b.extend_from_slice(&self.dht_port.to_le_bytes());
        b.extend_from_slice(&self.ts.to_le_bytes());
        b.extend_from_slice(&self.sig);
        b
    }

    /// Parse + verify chữ ký + verify node_id khớp ed_pub.
    pub fn from_signed_bytes(bytes: &[u8]) -> Result<Descriptor, CryptoError> {
        if bytes.len() != DESC_LEN {
            return Err(CryptoError::BadLength(bytes.len()));
        }
        if bytes[..4] != DESC_MAGIC || bytes[4] != DESC_VER {
            return Err(CryptoError::Descriptor);
        }
        let mut o = 5usize;
        let node_id: NodeId = bytes[o..o + 20].try_into().unwrap();
        o += 20;
        let ed_pub: [u8; 32] = bytes[o..o + 32].try_into().unwrap();
        o += 32;
        let link_pub: [u8; 32] = bytes[o..o + 32].try_into().unwrap();
        o += 32;
        let sphinx_pub: [u8; 32] = bytes[o..o + 32].try_into().unwrap();
        o += 32;
        let kem_pk: [u8; KEM_PK_LEN] = bytes[o..o + KEM_PK_LEN].try_into().unwrap();
        o += KEM_PK_LEN;
        let ip = std::net::Ipv4Addr::new(bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]);
        o += 4;
        let port = u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        o += 2;
        let dht_port = u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        o += 2;
        let ts = u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        o += 8;
        let sig: [u8; 64] = bytes[o..o + 64].try_into().unwrap();

        let vk = VerifyingKey::from_bytes(&ed_pub).map_err(|_| CryptoError::Ed25519)?;
        let sig_s = Signature::from_slice(&sig).map_err(|_| CryptoError::Ed25519)?;
        vk.verify(&bytes[..DESC_LEN - 64], &sig_s)
            .map_err(|_| CryptoError::Ed25519)?;
        if node_id_from_ed_pub(&ed_pub) != node_id {
            return Err(CryptoError::Descriptor);
        }
        Ok(Descriptor {
            node_id,
            ed_pub,
            link_pub,
            sphinx_pub,
            kem_pk,
            cell_addr: SocketAddr::new(IpAddr::V4(ip), port),
            dht_port,
            ts,
            sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn node_id_phai_la_sha256_cua_ed_pub() {
        let mut rng = StdRng::seed_from_u64(1);
        let id = NodeIdentity::random(&mut rng);
        let expect = Sha256::digest(id.ed.verifying_key().as_bytes());
        assert_eq!(id.node_id(), expect[..20]);
    }

    #[test]
    fn descriptor_roundtrip_va_verify() {
        let mut rng = StdRng::seed_from_u64(2);
        let id = NodeIdentity::random(&mut rng);
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let d = Descriptor::sign(&id, addr, 9002, 1_700_000_000);
        let back = Descriptor::from_signed_bytes(&d.to_bytes()).unwrap();
        assert_eq!(back.node_id, id.node_id());
        assert_eq!(back.cell_addr, addr);
        assert_eq!(back.dht_port, 9002);
        assert_eq!(back.kem_pk.len(), crate::KEM_PK_LEN);
    }

    #[test]
    fn descriptor_sua_1_byte_phai_loi() {
        let mut rng = StdRng::seed_from_u64(3);
        let id = NodeIdentity::random(&mut rng);
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut b = Descriptor::sign(&id, addr, 2, 10).to_bytes();
        let n = b.len();
        b[n - 70] ^= 0x01; // đảo 1 byte trong vùng ts
        assert!(Descriptor::from_signed_bytes(&b).is_err());
    }

    #[test]
    fn descriptor_ky_boi_nguoi_khac_phai_loi() {
        let mut rng = StdRng::seed_from_u64(4);
        let a = NodeIdentity::random(&mut rng);
        let b = NodeIdentity::random(&mut rng);
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut d = Descriptor::sign(&a, addr, 2, 10);
        d.sig = b.sign_ed(&d.signing_bytes()); // ký lại bằng key B nhưng giữ node_id A
        assert!(Descriptor::from_signed_bytes(&d.to_bytes()).is_err());
    }
}
