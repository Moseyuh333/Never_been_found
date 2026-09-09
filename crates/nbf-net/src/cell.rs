//! Cell 1280B cố định + fragmentation CREATE + onion seal/peel.
//! Cell là đơn vị trước mã hóa link; mọi cmd dùng chung 1 format để chống phân tích
//! lượng (kích thước trên link luôn 1280B, payload bên trong đã đệm zero).

use crate::NetError;
use std::collections::HashMap;

pub const CELL: usize = 1280;
pub const CELL_HDR: usize = 8; // cid u32 + cmd u8 + flags u8 + len u16
pub const CELL_DATA: usize = CELL - CELL_HDR; // 1272
/// Payload user tối đa trong một message onion (đã trừ ~header).
pub const MSG_MAX: usize = 1024;
/// Payload PADDING tối đa (fill 1280B).
pub const FILLER_MAX: usize = CELL_DATA - 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    Create = 1,
    Created,
    Destroy,
    Relay,
    Padding,
}

impl TryFrom<u8> for Cmd {
    type Error = NetError;
    fn try_from(v: u8) -> Result<Self, NetError> {
        match v {
            1 => Ok(Cmd::Create),
            2 => Ok(Cmd::Created),
            3 => Ok(Cmd::Destroy),
            4 => Ok(Cmd::Relay),
            5 => Ok(Cmd::Padding),
            _ => Err(NetError::BadCmd(v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RCmd {
    Echo = 1,
    Data,
    Drop,
}

impl TryFrom<u8> for RCmd {
    type Error = NetError;
    fn try_from(v: u8) -> Result<Self, NetError> {
        match v {
            1 => Ok(RCmd::Echo),
            2 => Ok(RCmd::Data),
            3 => Ok(RCmd::Drop),
            _ => Err(NetError::BadCmd(v)),
        }
    }
}

/// Parse 1 mảnh CREATE: [total u16][idx u16][chunk] → (total, idx, chunk).
pub fn parse_frag(payload: &[u8]) -> Result<(u16, u16, &[u8]), NetError> {
    if payload.len() < 4 {
        return Err(NetError::TooShort);
    }
    let total = u16::from_le_bytes([payload[0], payload[1]]);
    let idx = u16::from_le_bytes([payload[2], payload[3]]);
    Ok((total, idx, &payload[4..]))
}

#[derive(Debug, Clone)]
pub struct Cell {
    pub cid: u32,
    pub cmd: Cmd,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Cell {
    /// Mã hóa thành đúng 1280 byte (zero-pad phần dư). Panic nếu payload > CELL_DATA.
    pub fn encode(&self) -> [u8; CELL] {
        assert!(
            self.payload.len() <= CELL_DATA,
            "payload {} > CELL_DATA {}",
            self.payload.len(),
            CELL_DATA
        );
        let mut buf = [0u8; CELL];
        buf[..4].copy_from_slice(&self.cid.to_le_bytes());
        buf[4] = self.cmd as u8;
        buf[5] = self.flags;
        buf[6..8].copy_from_slice(&(self.payload.len() as u16).to_le_bytes());
        buf[8..8 + self.payload.len()].copy_from_slice(&self.payload);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Cell, NetError> {
        if buf.len() != CELL {
            return Err(NetError::BadLength(buf.len()));
        }
        let len = u16::from_le_bytes([buf[6], buf[7]]) as usize;
        if len > CELL_DATA {
            return Err(NetError::TooShort);
        }
        Ok(Cell {
            cid: u32::from_le_bytes(buf[..4].try_into().unwrap()),
            cmd: Cmd::try_from(buf[4])?,
            flags: buf[5],
            payload: buf[8..8 + len].to_vec(),
        })
    }
}

/// Fragment payload thành các mảnh `[total u16][idx u16][chunk]`.
/// `total` = SỐ MẢNH (khớp reassemble), mỗi mảnh ≤ 1268B.
pub fn fragment(payload: &[u8]) -> Vec<Vec<u8>> {
    let chunk = CELL_DATA - 4; // 1268
    let cnt = payload.len().div_ceil(chunk).max(1) as u16;
    (0..cnt)
        .map(|i| {
            let a = i as usize * chunk;
            let b = ((i as usize + 1) * chunk).min(payload.len());
            let mut p = Vec::with_capacity(4 + (b - a));
            p.extend_from_slice(&cnt.to_le_bytes());
            p.extend_from_slice(&i.to_le_bytes());
            p.extend_from_slice(&payload[a..b]);
            p
        })
        .collect()
}

/// Bộ đệm tái lắp fragment của một cid.
#[derive(Default)]
pub struct FragBuf {
    pub total: u16,
    pub got: Vec<Option<Vec<u8>>>,
    pub count: usize,
}

/// Tái lắp fragment. `frag_idx`/`total` từ payload mảnh.
/// Trả Some(msg) khi đủ, None khi còn thiếu.
pub fn reassemble(
    cid: u32,
    frag_idx: u16,
    total: u16,
    chunk: &[u8],
    map: &mut HashMap<u32, FragBuf>,
) -> Option<Vec<u8>> {
    let fb = map.entry(cid).or_insert_with(|| FragBuf {
        total,
        got: vec![None; total as usize],
        count: 0,
    });
    if fb.total != total {
        fb.got = vec![None; total as usize];
        fb.total = total;
        fb.count = 0;
    }
    let i = frag_idx as usize;
    if i < fb.got.len() && fb.got[i].is_none() {
        fb.got[i] = Some(chunk.to_vec());
        fb.count += 1;
    }
    if fb.count == fb.total as usize {
        let mut out = Vec::with_capacity(fb.total as usize * 1268);
        for slot in fb.got.drain(..) {
            out.extend_from_slice(&slot?);
        }
        map.remove(&cid);
        return Some(out);
    }
    None
}

/// Bọc onion forward từ hop CUỐI vào (lớp ngoài cùng = hop đầu).
/// `keys` theo thứ tự route. Nonce không phụ thuộc vị trí hop: mỗi hop có KHÓA riêng
/// (ss_khác) nên cặp (key, nonce) vẫn duy nhất — đúng như chiều backward.
pub fn seal_onion(keys: &[[u8; 32]], tag: &[u8; 16], seq: u32, msg: &[u8]) -> Vec<u8> {
    let mut payload = msg.to_vec();
    for k in keys.iter().rev() {
        payload = nbf_crypto::seal(k, &nbf_crypto::relay_nonce(tag, 0, seq), &payload);
    }
    payload
}

/// Mở ONE lớp onion ở một hop (chiều forward).
pub fn open_onion(
    key: &[u8; 32],
    tag: &[u8; 16],
    seq: u32,
    onion: &[u8],
) -> Result<Vec<u8>, NetError> {
    nbf_crypto::open(key, &nbf_crypto::relay_nonce(tag, 0, seq), onion).map_err(NetError::from)
}

/// Bọc 1 lớp backward (terminal/hop trả lời origin).
pub fn seal_bwd(key: &[u8; 32], tag: &[u8; 16], seq: u32, msg: &[u8]) -> Vec<u8> {
    nbf_crypto::seal(key, &nbf_crypto::relay_nonce(tag, 1, seq), msg)
}

/// Mở 1 lớp backward (origin mở từng lớp khi nhận reply).
pub fn open_bwd(
    key: &[u8; 32],
    tag: &[u8; 16],
    seq: u32,
    onion: &[u8],
) -> Result<Vec<u8>, NetError> {
    nbf_crypto::open(key, &nbf_crypto::relay_nonce(tag, 1, seq), onion).map_err(NetError::from)
}

/// Bọc onion backward (terminal → origin): mỗi hop 1 lớp, cùng nonce (key riêng mỗi hop).
pub fn seal_onion_bwd(keys: &[[u8; 32]], tag: &[u8; 16], seq: u32, msg: &[u8]) -> Vec<u8> {
    let mut payload = msg.to_vec();
    for k in keys.iter().rev() {
        payload = nbf_crypto::seal(k, &nbf_crypto::relay_nonce(tag, 1, seq), &payload);
    }
    payload
}

/// Mở onion backward ở origin (lớp ngoài cùng = hop đầu, mở đúng thứ tự keys).
pub fn open_onion_bwd(
    keys: &[[u8; 32]],
    tag: &[u8; 16],
    seq: u32,
    onion: &[u8],
) -> Result<Vec<u8>, NetError> {
    let mut payload = onion.to_vec();
    for k in keys {
        payload = nbf_crypto::open(k, &nbf_crypto::relay_nonce(tag, 1, seq), &payload)?;
    }
    Ok(payload)
}

/// Tạo payload PADDING (chứa tổng số cell cần giữ link bận).
pub fn padding_payload(n_cells: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(2);
    p.extend_from_slice(&n_cells.to_le_bytes());
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_encode_decode_dung_1280() {
        let c = Cell { cid: 7, cmd: Cmd::Relay, flags: 0, payload: vec![1; 100] };
        let b = c.encode();
        assert_eq!(b.len(), CELL);
        let d = Cell::decode(&b).unwrap();
        assert_eq!(d.cid, 7);
        assert_eq!(d.cmd, Cmd::Relay);
        assert_eq!(d.payload, vec![1; 100]);
    }

    #[test]
    fn cell_sai_do_dai_bi_tu_choi() {
        assert!(Cell::decode(&[0u8; 100]).is_err());
        let c = Cell { cid: 1, cmd: Cmd::Create, flags: 0, payload: vec![0; CELL_DATA] };
        assert!(c.encode().len() == CELL);
    }

    #[test]
    fn fragment_reassemble_header_lon() {
        let data: Vec<u8> = (0..7122).map(|i| (i % 251) as u8).collect();
        let frags = fragment(&data);
        assert!(frags.len() >= 6);
        let mut map = HashMap::new();
        // feed lộn xộn:
        for &i in &[3usize, 0, 5, 1, 4, 2] {
            let p = &frags[i];
            let total = u16::from_le_bytes([p[0], p[1]]);
            let idx = u16::from_le_bytes([p[2], p[3]]);
            if let Some(done) = reassemble(7, idx, total, &p[4..], &mut map) {
                assert_eq!(done, data);
                return;
            }
        }
        panic!("chưa lắp đủ");
    }

    #[test]
    fn onion_3_hop_seal_peel_dung_thu_tu() {
        let keys: Vec<[u8; 32]> = (0..3)
            .map(|i| {
                let mut k = [0u8; 32];
                k[0] = i as u8 + 1;
                k
            })
            .collect();
        let tag = [0xA5u8; 16];
        let seq = 3u32;
        let inner = b"echo-hello";
        let onion = seal_onion(&keys, &tag, seq, inner);
        // Mỗi hop peel với key của mình (nonce = seq):
        let l2 = open_onion(&keys[0], &tag, seq, &onion).unwrap();
        let l1 = open_onion(&keys[1], &tag, seq, &l2).unwrap();
        let l0 = open_onion(&keys[2], &tag, seq, &l1).unwrap();
        assert_eq!(l0, inner);
        // sai key → fail:
        let mut bad = keys.clone();
        bad[1] = [7u8; 32];
        assert!(open_onion(&bad[1], &tag, seq, &onion).is_err());
        // backward — open phải dùng CÙNG seq với seal:
        let b = seal_onion_bwd(&keys, &tag, seq, inner);
        let out = open_onion_bwd(&keys, &tag, seq, &b).unwrap();
        assert_eq!(out, inner);
    }

    #[test]
    fn padding_payload_2_byte() {
        let p = padding_payload(5);
        assert_eq!(p.len(), 2);
        assert_eq!(u16::from_le_bytes([p[0], p[1]]), 5);
    }
}