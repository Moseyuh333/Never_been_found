//! Xử lý RELAY: xác định hướng (từ prev/next), lột/bọc onion đúng chiều,
//! seq replay theo chiều, dispatch ECHO/DATA/DROP. Origin nhận chiều về → đẩy stream.

use crate::cell::{open_bwd, open_onion, seal_bwd};
use crate::node::{CircuitEntry, Node};
use crate::{Cell, Cmd, RCmd};
use std::net::SocketAddr;
use std::sync::Arc;

/// payload RELAY: [seq u32][rcmd u8][stream u16][onion…]
pub async fn handle(node: Arc<Node>, from: SocketAddr, cell: Cell) {
    if cell.payload.len() < 7 {
        return;
    }
    let seq = u32::from_le_bytes(cell.payload[0..4].try_into().unwrap());
    let rcmd_u8 = cell.payload[4];
    let rcmd = match RCmd::try_from(rcmd_u8) {
        Ok(r) => r,
        Err(_) => return,
    };
    let stream = u16::from_le_bytes(cell.payload[5..7].try_into().unwrap());
    let onion = cell.payload[7..].to_vec();

    let entry = node.circuits.lock().await.get(&cell.cid).map(|e| e.cloned_entry());
    let entry = match entry {
        Some(e) => e,
        None => return,
    };
    node.stats.lock().await.relayed += 1;
    match entry {
        CircuitEntry::Origin { bwd, tag, streams, .. } => {
            // Origin nhận RELAY chỉ từ hop1. Chiều về: mở bwd[0]→bwd[1]→…→bwd[n-1].
            let mut data = onion;
            for k in &bwd {
                match open_bwd(k, &tag, seq, &data) {
                    Ok(d) => data = d,
                    Err(_) => return,
                }
            }
            if let Some(tx) = streams.get(&stream) {
                let _ = tx.send(data).await;
            }
        }
        CircuitEntry::Relay { tag, k_fwd, k_bwd, prev, next, last_fwd, .. } => {
            let from_prev = from == prev.peer;
            let from_next = from == next.peer;
            if from_prev {
                // Hướng tiến: lột 1 lớp k_fwd, kiểm seq, forward tiếp.
                if seq <= last_fwd {
                    return; // replay
                }
                let inner = match open_onion(&k_fwd, &tag, seq, &onion) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if let Some(CircuitEntry::Relay { last_fwd, .. }) =
                    node.circuits.lock().await.get_mut(&cell.cid)
                {
                    *last_fwd = seq;
                }
                let mut payload = Vec::with_capacity(7 + inner.len());
                payload.extend_from_slice(&seq.to_le_bytes());
                payload.push(rcmd_u8);
                payload.extend_from_slice(&stream.to_le_bytes());
                payload.extend_from_slice(&inner);
                let c = Cell { cid: next.cid, cmd: Cmd::Relay, flags: 0, payload };
                let _ = node.link.send_cell(next.peer, &c).await;
            } else if from_next {
                // Hướng về: bọc thêm 1 lớp k_bwd rồi gửi về prev.
                let payload = seal_bwd(&k_bwd, &tag, seq, &onion);
                let mut out = Vec::with_capacity(7 + payload.len());
                out.extend_from_slice(&seq.to_le_bytes());
                out.push(rcmd_u8);
                out.extend_from_slice(&stream.to_le_bytes());
                out.extend_from_slice(&payload);
                let c = Cell { cid: prev.cid, cmd: Cmd::Relay, flags: 0, payload: out };
                let _ = node.link.send_cell(prev.peer, &c).await;
            }
            // Khác: datagram từ nơi không thuộc circuit → bỏ.
        }
        CircuitEntry::Terminal { tag, k_fwd, k_bwd, prev, last_fwd } => {
            // Terminal chỉ nhận từ prev (hướng tiến). DROP → bỏ (cover). ECHO/DATA → trả lời.
            if from != prev.peer || seq <= last_fwd {
                return;
            }
            let inner = match open_onion(&k_fwd, &tag, seq, &onion) {
                Ok(v) => v,
                Err(_) => return,
            };
            if let Some(CircuitEntry::Terminal { last_fwd, .. }) =
                node.circuits.lock().await.get_mut(&cell.cid)
            {
                *last_fwd = seq;
            }
            match rcmd {
                RCmd::Echo => {
                    // bọc bwd rồi gửi về prev, payload giữ rcmd=ECHO, stream giữ nguyên:
                    let out_payload = seal_bwd(&k_bwd, &tag, seq, &inner);
                    let mut payload = Vec::with_capacity(7 + out_payload.len());
                    payload.extend_from_slice(&seq.to_le_bytes());
                    payload.push(RCmd::Echo as u8);
                    payload.extend_from_slice(&stream.to_le_bytes());
                    payload.extend_from_slice(&out_payload);
                    let c = Cell { cid: prev.cid, cmd: Cmd::Relay, flags: 0, payload };
                    let _ = node.link.send_cell(prev.peer, &c).await;
                }
                RCmd::Data => {
                    // v1: chưa có ứng dụng stream đa năng — bỏ.
                }
                RCmd::Drop => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::{open_bwd, seal_onion};
    use nbf_crypto::NodeIdentity;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // Đơn vị: mở/mã 3 lớp đúng chiều tiến/lùi qua 1 hop trung gian (mô phỏng chuỗi xử lý).
    #[test]
    fn relay_forward_then_backward_roundtrip() {
        let mut rng = StdRng::seed_from_u64(7);
        let _a = NodeIdentity::random(&mut rng);
        let _b = NodeIdentity::random(&mut rng);
        let _c = NodeIdentity::random(&mut rng);
        // Khóa tưởng tượng (không cần identity thật):
        let fwd = [[11u8; 32], [12u8; 32], [13u8; 32]];
        let bwd = [[21u8; 32], [22u8; 32], [23u8; 32]];
        let tag = [1u8; 16];
        let seq = 5u32;

        // Origin bọc:
        let onion = seal_onion(&fwd, &tag, seq, b"ping");
        // Hop b mở lớp 1:
        let l1 = open_onion(&fwd[0], &tag, seq, &onion).unwrap();
        // Hop c mở lớp 2:
        let l2 = open_onion(&fwd[1], &tag, seq, &l1).unwrap();
        // Terminal mở lớp 3 → plaintext:
        let l3 = open_onion(&fwd[2], &tag, seq, &l2).unwrap();
        assert_eq!(l3, b"ping");

        // Terminal trả lời: terminal bọc bwd[2], hop1 bọc thêm bwd[1], hop0 bọc bwd[0]; origin mở [0]→[1]→[2].
        let r1 = seal_bwd(&bwd[2], &tag, seq, b"pong");
        let r2 = seal_bwd(&bwd[1], &tag, seq, &r1);
        let r3 = seal_bwd(&bwd[0], &tag, seq, &r2);
        let m1 = open_bwd(&bwd[0], &tag, seq, &r3).unwrap();
        let m2 = open_bwd(&bwd[1], &tag, seq, &m1).unwrap();
        let m3 = open_bwd(&bwd[2], &tag, seq, &m2).unwrap();
        assert_eq!(m3, b"pong");
    }
}
