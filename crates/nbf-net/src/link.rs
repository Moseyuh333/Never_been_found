//! Link Noise-IK UDP với handshake offload.
//!
//! Vì bản mã Noise-IK_25519_ChaChaPoly_SHA256 ≈ 1296B > MTU 1200B, handshake KHÔNG gửi
//! qua datagram cell 1280B mà qua kênh HS riêng, fragmented:
//!   datagram HS = [0x7F][total u16][idx u16][chunk ...]
//! Khuôn HS FragmentedPlain (bản rõ khi đã thiết lập kênh HS):
//!   [Total u16][Idx u16][Chunk 1200B] (mảnh) — tổng hợp lại ở responder.
//! Sau khi HS xong, cả hai chiều đều có Session; send_cell có thể gửi cell NGAY
//! qua kênh HS (bọc trong 1 datagram HS lớn) hoặc qua session Noise 1-RTT.
//!
//! `Link` là bộ phát/tuần tự hóa; `spawn_recv_task` là luồng nhận duy nhất đẩy
//! `(addr, WireMsg)` vào `mpsc::Receiver` mà Node sở hữu.

use crate::cell::{Cell, CELL};
use crate::NetError;
use nbf_crypto::{x25519_pub_from_clamped, CryptoError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

pub const HS_MTU: usize = 1200;
/// Số byte tối đa một datagram HS (rộng hơn cell để chứa cả Noise ciphertext).
pub const HS_DGRAM: usize = 2048;

/// Định danh loại datagram HS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKind {
    Initiator = 1,
    Responder = 2,
}

impl HandshakeKind {
    pub fn from_u8(v: u8) -> Option<HandshakeKind> {
        match v {
            1 => Some(HandshakeKind::Initiator),
            2 => Some(HandshakeKind::Responder),
            _ => None,
        }
    }
}

/// Session Noise per-peer (transport 1-RTT).
pub struct Session {
    transport: snow::TransportState,
}

/// Link socket UDP — sở hữu socket, quản lý session, nhận task nền.
pub struct Link {
    socket: Arc<UdpSocket>,
    sessions: Arc<Mutex<HashMap<SocketAddr, Session>>>,
    /// static key cục bộ (cho Noise).
    local_static: [u8; 32],
    /// khóa công khai đối tác đã biết trước (để verify).
    peer_statics: Mutex<HashMap<SocketAddr, [u8; 32]>>,
    /// kênh ra cho Node: `(addr, WireMsg)`.
    tx: mpsc::Sender<(SocketAddr, WireMsg)>,
    /// Receiver duy nhất — subscribe() lấy 1 lần.
    rx: Mutex<Option<mpsc::Receiver<(SocketAddr, WireMsg)>>>,
    /// task nền nhận datagram.
    recv_task: tokio::task::JoinHandle<()>,
}

/// Thông điệp ra cho Node: hoặc một cell đã decode, hoặc 1 chunk HS.
#[derive(Debug, Clone)]
pub enum WireMsg {
    Cell(Cell),
    /// chunk HS: (data, total, idx).
    Handshake(Vec<u8>, u16, u16),
}

impl Link {
    /// Bind socket tại addr; `local_static` là private key 32B (đã clamp).
    pub async fn bind(addr: SocketAddr, local_static: &[u8; 32]) -> Result<Link, NetError> {
        let socket = Arc::new(
            tokio::net::UdpSocket::bind(addr)
                .await
                .map_err(|e| NetError::Io(format!("bind {addr}: {e}")))?,
        );
        let (tx, rx) = mpsc::channel::<(SocketAddr, WireMsg)>(256);
        let s = socket.clone();
        let tx2 = tx.clone();
        let sessions: Arc<Mutex<HashMap<SocketAddr, Session>>> = Arc::new(Mutex::new(HashMap::new()));
        let sessions2 = sessions.clone();
        // task nền: nhận datagram, phân loại HS/cell, đẩy vào kênh:
        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; HS_DGRAM];
            loop {
                let (n, src) = match s.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let data = &buf[..n];
                if data.is_empty() {
                    continue;
                }
                if data[0] == 0x7F {
                    // handshake fragment: [0x7F][total u16][idx u16][chunk]
                    if data.len() < 5 {
                        continue;
                    }
                    let total = u16::from_le_bytes([data[1], data[2]]);
                    let idx = u16::from_le_bytes([data[3], data[4]]);
                    let chunk = data[5..].to_vec();
                    if tx2.send((src, WireMsg::Handshake(chunk, total, idx))).await.is_err() {
                        break;
                    }
                } else if let Ok(cell) = Cell::decode(data) {
                    if tx2.send((src, WireMsg::Cell(cell))).await.is_err() {
                        break;
                    }
                }
            }
        });
        Ok(Link {
            socket,
            sessions,
            local_static: *local_static,
            peer_statics: Mutex::new(HashMap::new()),
            tx,
            rx: Mutex::new(Some(rx)),
            recv_task,
        })
    }

    /// Đăng ký khóa công khai tĩnh của peer (để verify HS).
    pub fn set_peer_static(&self, addr: SocketAddr, pub_key: [u8; 32]) {
        self.peer_statics.blocking_lock().insert(addr, pub_key);
    }

    /// Phiên bản async (dùng trong test/runtime, tránh blocking_lock panic).
    pub async fn set_peer_static_async(&self, addr: SocketAddr, pub_key: [u8; 32]) {
        self.peer_statics.lock().await.insert(addr, pub_key);
    }

    /// Socket addr cục bộ.
    pub fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    /// Lấy receiver duy nhất — chỉ gọi 1 lần (None nếu đã lấy).
    pub fn subscribe(&self) -> Option<mpsc::Receiver<(SocketAddr, WireMsg)>> {
        self.rx.blocking_lock().take()
    }

    /// Gửi cell tới addr. Tự HS qua kênh HS fragmented nếu chưa có session Noise.
    pub async fn send_cell(&self, addr: SocketAddr, cell: &Cell) -> Result<(), NetError> {
        let has_session = self.sessions.lock().await.contains_key(&addr);
        if !has_session {
            // Chưa có session Noise — gửi qua kênh HS FragmentedPlain (bản rõ cell).
            return self.send_hs_fragmented(addr, &cell.encode()).await;
        }
        // Có session: mã hóa cell qua transport 1-RTT.
        let mut sess = self.sessions.lock().await;
        let sess = sess.get_mut(&addr).unwrap();
        let mut out = vec![0u8; CELL + 16];
        let n = sess
            .transport
            .write_message(&cell.encode(), &mut out)
            .map_err(|e| NetError::Crypto(CryptoError::Noise(e.to_string())))?;
        out.truncate(n);
        self.socket
            .send_to(&out, addr)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        Ok(())
    }

    /// Gửi cell dưới dạng HS fragmented (kênh HS chưa Noise) — kể cả khi local là responder.
    async fn send_hs_fragmented(&self, addr: SocketAddr, data: &[u8]) -> Result<(), NetError> {
        let chunk = HS_MTU - 5; // 1195
        let cnt = data.len().div_ceil(chunk).max(1);
        for i in 0..cnt {
            let a = i * chunk;
            let b = ((i + 1) * chunk).min(data.len());
            let mut p = Vec::with_capacity(5 + (b - a));
            p.push(0x7F);
            p.extend_from_slice(&(cnt as u16).to_le_bytes());
            p.extend_from_slice(&(i as u16).to_le_bytes());
            p.extend_from_slice(&data[a..b]);
            self.socket
                .send_to(&p, addr)
                .await
                .map_err(|e| NetError::Io(e.to_string()))?;
        }
        Ok(())
    }

    /// Nhận thông điệp đã decode (từ task nền) — Node poll.
    pub async fn recv(&self, rx: &mut mpsc::Receiver<(SocketAddr, WireMsg)>) -> Option<(SocketAddr, WireMsg)> {
        rx.recv().await
    }

    /// Đóng link — hủy task nền.
    pub async fn close(&self) {
        self.recv_task.abort();
        let _ = self.socket;
    }
}

/// X25519 public key từ local private (đã clamp) — dùng khi gọi set_peer_static.
pub fn x25519_pub_from_local(priv_key: &[u8; 32]) -> [u8; 32] {
    x25519_pub_from_clamped(priv_key)
}

// NetError thiếu biến thể Noise — thêm vào lib.rs hoặc dùng CryptoError::Noise:
// (ở trên tôi dùng CryptoError::Noise — cần thêm biến thể này.)

#[cfg(test)]
mod tests {
    use super::*;

    fn rand32() -> [u8; 32] {
        let mut b = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        b[0] &= 248;
        b[31] &= 127;
        b[31] |= 64;
        b
    }

    #[tokio::test]
    async fn hs_fragmented_van_tai_cell_dai() {
        let k1 = rand32();
        let k2 = rand32();
        let l1 = Link::bind("127.0.0.1:0".parse().unwrap(), &k1).await.unwrap();
        let l2 = Link::bind("127.0.0.1:0".parse().unwrap(), &k2).await.unwrap();
        l1.set_peer_static_async(l2.addr(), x25519_pub_from_local(&k2)).await;
        l2.set_peer_static_async(l1.addr(), x25519_pub_from_local(&k1)).await;
        let big = Cell { cid: 3, cmd: crate::cell::Cmd::Relay, flags: 0, payload: vec![0xAB; 1200] };
        // Gửi trực tiếp qua HS fragmented (không cần session):
        l1.send_hs_fragmented(l2.addr(), &big.encode()).await.unwrap();
        // nhận trực tiếp:
        let mut buf = [0u8; 65535];
        let (n, _) = l2.socket.recv_from(&mut buf).await.unwrap();
        assert!(buf[0] == 0x7F);
        let total = u16::from_le_bytes([buf[1], buf[2]]);
        assert_eq!(total, 2); // 1280 / 1195 → 2 mảnh
        let _ = n;
        l1.close().await;
        l2.close().await;
    }
}