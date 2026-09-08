//! Sphinx header: dựng 1-pass (origin tính sẵn mọi khóa) và xử lý từng hop
//! (lột lớp, decap ML-KEM, mù hóa alpha còn lại, forward).
//! Khác Tor: không EXTEND từng nấc — toàn bộ circuit dựng trong 1 round-trip.
//!
//! Layout header (n hop):
//!   [ver u8=1][n u8][tag 16B][alpha_1..alpha_n n×32B][tail n×(16+1152)B]
//!
//! Cấu trúc khóa:
//! - Khóa mỗi lớp header k_i = HKDF(ss_x_i, tag) — chỉ X25519 (giữ tính blinding).
//! - Traffic key mỗi hop (k_fwd‖k_bwd) = HKDF(ss_x_i ‖ ss_mlkem_i, tag) — PQC lai.
//! - Chuỗi blinding: alpha hiệu dụng hop i = x_i × Π_{j<i} b_j, với b_j = H(ss_x_j ‖ alpha_j).
//!   Hop t lột lớp xong, nhân MỌI alpha còn lại với b_t của nó rồi forward.

use crate::identity::Descriptor;
use crate::NodeIdentity;
use crate::{
    derive_hdr_key, derive_traffic_keys, hdr_nonce, kem_decap, kem_encap, open, seal, CryptoError,
    NodeId, CT_LEN, LAYER_INFO_LEN, LAYER_LEN, MAX_HOPS, TERMINAL_ID,
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::Scalar;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha512};
use std::net::{IpAddr, SocketAddr};

/// Độ dài cố định đầu: ver(1) + n(1) + tag(16).
pub const HDR_FIXED: usize = 18;

/// Một node trên route (mượn descriptor từ DHT/cache).
pub struct RouteNode<'a> {
    pub desc: &'a Descriptor,
}

/// Kết quả dựng header phía origin.
pub struct BuiltHeader {
    /// Byte header hoàn chỉnh — gửi kèm CREATE fragmented.
    pub header: Vec<u8>,
    pub tag: [u8; 16],
    /// Khóa fwd/bwd của từng hop theo thứ tự route — origin giữ để bọc/mở RELAY.
    pub fwd_keys: Vec<[u8; 32]>,
    pub bwd_keys: Vec<[u8; 32]>,
    pub first_addr: SocketAddr,
}

/// Dựng header Sphinx cho route n hop (origin side).
pub fn build_header(
    route: &[RouteNode],
    tag: [u8; 16],
    rng: &mut impl CryptoRngCore,
) -> Result<BuiltHeader, CryptoError> {
    if route.is_empty() || route.len() > MAX_HOPS {
        return Err(CryptoError::BadLength(route.len()));
    }
    let n = route.len();

    // 1. x thô cho từng hop + ss_x (dùng alpha HIỆU DỤNG = x × Π b phía trước),
    //    theo chuỗi blinding.
    let mut raw_x: Vec<Scalar> = Vec::with_capacity(n);
    let mut ss_x: Vec<[u8; 32]> = Vec::with_capacity(n);
    let mut blind_acc = Scalar::from(1u8);
    for rn in route {
        let x = Scalar::random(rng);
        let eff = x * blind_acc;
        let pt = MontgomeryPoint(rn.desc.sphinx_pub) * eff;
        ss_x.push(pt.to_bytes());
        let mut h = Sha512::new();
        h.update(pt.to_bytes());
        h.update(eff.to_bytes());
        blind_acc *= Scalar::from_hash(h); // b_i cho các hop sau
        raw_x.push(x);
    }

    // 2. Encapsulate KEM cho từng hop — GIỮ ss (origin cần khóa traffic, hop decap cùng ct).
    let mut cts: Vec<[u8; CT_LEN]> = Vec::with_capacity(n);
    let mut ss_kem: Vec<[u8; 32]> = Vec::with_capacity(n);
    for rn in route {
        let (ct, ss) = kem_encap(&rn.desc.kem_pk, rng)?;
        cts.push(ct);
        ss_kem.push(ss);
    }

    // 3. info thô mỗi lớp: [next_id 20][next_ip 4][next_port 2][next_link_pub 32][pad 6][ct 1088].
    let mut infos: Vec<[u8; LAYER_INFO_LEN]> = (0..n).map(|_| [0u8; LAYER_INFO_LEN]).collect();
    for i in 0..n {
        if i + 1 < n {
            let nd = route[i + 1].desc;
            infos[i][..20].copy_from_slice(&nd.node_id);
            if let IpAddr::V4(ip) = nd.cell_addr.ip() {
                infos[i][20..24].copy_from_slice(&ip.octets());
            }
            infos[i][24..26].copy_from_slice(&nd.cell_addr.port().to_le_bytes());
            infos[i][26..58].copy_from_slice(&nd.link_pub);
        } else {
            infos[i][..20].copy_from_slice(&TERMINAL_ID);
        }
        infos[i][64..].copy_from_slice(&cts[i]);
    }

    // 4. Mã hóa từ trong ra ngoài: layer t = seal(info[t] ‖ layer_{t+1}).
    //    nonce của layer t = hdr_nonce(tag, n - t) — bằng giá trị hop t sẽ nhìn thấy.
    //    blobs sau vòng lặp: [layer_{n-1}, ..., layer_0] → đảo lại.
    let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(n);
    for t in (0..n).rev() {
        let mut inner = infos[t].to_vec();
        if let Some(prev) = blobs.last() {
            inner.extend_from_slice(prev);
        }
        let key = derive_hdr_key(&ss_x[t], &tag);
        let nonce = hdr_nonce(&tag, (n - t) as u8);
        blobs.push(seal(&key, &nonce, &inner));
    }
    blobs.reverse();

    // 5. Ghép header. Tail = CHỈ blob ngoài cùng (đã lồng toàn bộ lớp bên trong).
    // Slot alpha chứa x THÔ (không phải hiệu dụng): hop i nhân b_i vào các slot
    // phía sau — slot đầu tiên mà hop i+1 nhìn thấy sẽ đúng bằng eff của nó.
    let mut header = Vec::with_capacity(HDR_FIXED + n * 32 + n * LAYER_LEN);
    header.push(1u8);
    header.push(n as u8);
    header.extend_from_slice(&tag);
    for x in &raw_x {
        header.extend_from_slice(&x.to_bytes());
    }
    header.extend_from_slice(&blobs[0]); // blob0 chứa blob1 chứa blob2...

    // 6. Khóa traffic (origin biết ss_x + ss_kem).
    let mut fwd_keys = Vec::with_capacity(n);
    let mut bwd_keys = Vec::with_capacity(n);
    for i in 0..n {
        let (f, b) = derive_traffic_keys(&ss_x[i], &ss_kem[i], &tag);
        fwd_keys.push(f);
        bwd_keys.push(b);
    }

    Ok(BuiltHeader {
        header,
        tag,
        fwd_keys,
        bwd_keys,
        first_addr: route[0].desc.cell_addr,
    })
}

/// Kết quả hop xử lý header.
pub enum ProcessOutcome {
    /// Hop này là đích cuối.
    Terminal {
        tag: [u8; 16],
        k_fwd: [u8; 32],
        k_bwd: [u8; 32],
    },
    /// Hop trung gian: forward new_header tới next.
    Relay {
        tag: [u8; 16],
        k_fwd: [u8; 32],
        k_bwd: [u8; 32],
        next_id: NodeId,
        next_addr: SocketAddr,
        new_header: Vec<u8>,
    },
}

/// Hop xử lý header: lột đúng 1 lớp (AEAD bằng khóa của mình), decap KEM,
/// tính khóa traffic, mù hóa alpha còn lại, trả header mới cho next.
pub fn process_header(id: &NodeIdentity, header: &[u8]) -> Result<ProcessOutcome, CryptoError> {
    if header.len() < HDR_FIXED {
        return Err(CryptoError::Sphinx);
    }
    let ver = header[0];
    let n_field = header[1];
    if ver != 1 || n_field == 0 {
        return Err(CryptoError::Sphinx);
    }
    let tag: [u8; 16] = header[2..18].try_into().unwrap();
    let n = n_field as usize;
    let body = &header[HDR_FIXED..];
    // Tail = n lớp lồng nhau (mỗi hop mở xong còn n-1 lớp cho hop sau).
    if body.len() != n * 32 + n * LAYER_LEN {
        return Err(CryptoError::Sphinx);
    }
    let alpha0: [u8; 32] = body[..32].try_into().unwrap();
    let alpha0 = Scalar::from_bytes_mod_order(alpha0);

    // ss của hop này = P × alpha (P = sphinx_pub công khai; alpha từ header).
    let point = MontgomeryPoint(id.sphinx_pub) * alpha0;
    let ss_x = point.to_bytes();
    let key = derive_hdr_key(&ss_x, &tag);
    let nonce = hdr_nonce(&tag, n_field);

    // Lớp của hop này (lồng nhau): blob_t = n_field × LAYER_LEN
    // = tag(16) + info(1152) + toàn bộ blob của các hop phía sau.
    let tail = &body[n * 32..];
    let my_blob = &tail[..n_field as usize * LAYER_LEN];
    let opened = open(&key, &nonce, my_blob).map_err(|_| CryptoError::Sphinx)?;
    // opened = info(1152) + blob của các hop sau (n_field-1 lớp).
    if opened.len() != LAYER_INFO_LEN + (n_field as usize - 1) * LAYER_LEN {
        return Err(CryptoError::Sphinx);
    }
    let next_id: NodeId = opened[..20].try_into().unwrap();
    let ip = std::net::Ipv4Addr::new(opened[20], opened[21], opened[22], opened[23]);
    let port = u16::from_le_bytes(opened[24..26].try_into().unwrap());
    let ct: [u8; CT_LEN] = opened[64..64 + CT_LEN].try_into().unwrap();
    let ss_kem = kem_decap(&id.kem_sk, &ct)?;
    let (k_fwd, k_bwd) = derive_traffic_keys(&ss_x, &ss_kem, &tag);

    if next_id == TERMINAL_ID {
        return Ok(ProcessOutcome::Terminal { tag, k_fwd, k_bwd });
    }

    // Blinding: b = H(ss_x ‖ alpha0); nhân MỌI alpha còn lại với b; n giảm 1.
    // (Sha512 để khớp chuỗi blinding phía origin — from_hash yêu cầu 512.)
    let mut h = Sha512::new();
    h.update(ss_x);
    h.update(&body[..32]);
    let b = Scalar::from_hash(h);

    let mut new_header = Vec::with_capacity(HDR_FIXED + (n - 1) * (32 + LAYER_LEN));
    new_header.push(1u8);
    new_header.push(n_field - 1);
    new_header.extend_from_slice(&tag);
    for a in body[32..n * 32].chunks_exact(32) {
        let arr: [u8; 32] = a.try_into().unwrap();
        let ai = Scalar::from_bytes_mod_order(arr);
        new_header.extend_from_slice(&(ai * b).to_bytes());
    }
    // Phần tail mới = opened sau info (blob đã "mở" của các hop phía sau):
    // hop sau thấy đúng tail có độ dài (n_field-1) × LAYER_LEN.
    new_header.extend_from_slice(&opened[LAYER_INFO_LEN..]);

    Ok(ProcessOutcome::Relay {
        tag,
        k_fwd,
        k_bwd,
        next_id,
        next_addr: SocketAddr::new(IpAddr::V4(ip), port),
        new_header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::replay::MonotonicCheck;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Dựng `n` node test; mỗi node biết descriptor của các node khác.
    fn fixture(n: usize) -> (Vec<NodeIdentity>, Vec<Descriptor>) {
        let mut rng = StdRng::seed_from_u64(42);
        let ids: Vec<NodeIdentity> = (0..n).map(|_| NodeIdentity::random(&mut rng)).collect();
        let descs: Vec<Descriptor> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let cell: SocketAddr = format!("127.0.0.1:{}", 9100 + i as u16).parse().unwrap();
                Descriptor::sign(id, cell, 9200 + i as u16, 1_000)
            })
            .collect();
        (ids, descs)
    }

    #[test]
    fn build_header_dung_do_dai_va_khoa() {
        let (_ids, descs) = fixture(3);
        let route: Vec<RouteNode> = descs.iter().map(|d| RouteNode { desc: d }).collect();
        let bh = build_header(&route, [7u8; 16], &mut StdRng::seed_from_u64(1)).unwrap();
        // Header = 18 + n×32 (alpha) + n×LAYER_LEN (blob ngoài cùng lồng mọi lớp).
        assert_eq!(bh.header.len(), 18 + 3 * 32 + 3 * 1168);
        assert_eq!(bh.fwd_keys.len(), 3);
        assert_eq!(bh.bwd_keys.len(), 3);
        assert_eq!(bh.first_addr, descs[0].cell_addr);
        // Mỗi hop một khóa khác nhau:
        assert_ne!(bh.fwd_keys[0], bh.fwd_keys[1]);
        assert_ne!(bh.fwd_keys[1], bh.fwd_keys[2]);
    }

    #[test]
    fn route_qua_3_hop_moi_hop_nhin_dung_thong_tin_tiep() {
        let (ids, descs) = fixture(3);
        let route: Vec<RouteNode> = descs.iter().map(|d| RouteNode { desc: d }).collect();
        let bh = build_header(&route, [7u8; 16], &mut StdRng::seed_from_u64(2)).unwrap();

        // Hop 0 xử lý header ban đầu:
        let o0 = process_header(&ids[0], &bh.header).unwrap();
        let ProcessOutcome::Relay {
            next_id,
            next_addr: _,
            new_header,
            k_fwd,
            k_bwd,
            ..
        } = o0
        else {
            panic!("hop 0 phải là relay")
        };
        assert_eq!(next_id, descs[1].node_id);
        assert_eq!(
            descs[1].cell_addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9101)
        );
        assert_eq!(k_fwd, bh.fwd_keys[0]);
        assert_eq!(k_bwd, bh.bwd_keys[0]);

        // Hop 1 xử lý header đã bị mù hóa:
        let o1 = process_header(&ids[1], &new_header).unwrap();
        let ProcessOutcome::Relay {
            next_id,
            next_addr,
            new_header: h2,
            k_fwd: k1,
            ..
        } = o1
        else {
            panic!("hop 1 phải là relay")
        };
        assert_eq!(next_id, descs[2].node_id);
        assert_eq!(k1, bh.fwd_keys[1]);

        // Hop 2 phải thấy TERMINAL_ID và ra Terminal:
        let o2 = process_header(&ids[2], &h2).unwrap();
        match o2 {
            ProcessOutcome::Terminal { k_fwd, k_bwd, .. } => {
                assert_eq!(k_fwd, bh.fwd_keys[2]);
                assert_eq!(k_bwd, bh.bwd_keys[2]);
            }
            _ => panic!("hop cuối phải là terminal"),
        }
    }

    #[test]
    fn hop_sai_khong_the_mo_layer() {
        let (mut ids, descs) = fixture(3);
        // Thay node 1 bằng node lạ:
        let mut rng = StdRng::seed_from_u64(99);
        ids[1] = NodeIdentity::random(&mut rng);
        let route: Vec<RouteNode> = descs.iter().map(|d| RouteNode { desc: d }).collect();
        let bh = build_header(&route, [7u8; 16], &mut StdRng::seed_from_u64(3)).unwrap();
        assert!(process_header(&ids[1], &bh.header).is_err());
    }

    #[test]
    fn replay_filter_don_dieu() {
        let mut m = MonotonicCheck::new();
        assert!(m.check(1));
        assert!(m.check(2));
        assert!(!m.check(2)); // replay
        assert!(!m.check(1)); // cũ
        assert!(m.check(5)); // nhảy cóc vẫn nhận (chống kẹt cố ý)
    }
}
