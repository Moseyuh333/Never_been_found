//! Link Noise-IK UDP: handshake tự động, session 1-RTT per-peer.
//!
//! Datagram: `[0x7F][total u16][idx u16][chunk...]` = mảnh HS (IK msg ngắn ~96B nên
//! thường 1 mảnh); datagram còn lại là ciphertext session Noise — nếu chưa có session
//! thì coi là cell rõ (fallback MVP, kênh localhost/LAN tin cậy).
//!
//! `send_cell` tự khởi HS khi chưa có session (cần `set_peer_static_async` trước),
//! chờ session sẵn (2s) rồi gửi mã hóa. Bên responder hoàn thành HS ngay sau msg1.

use crate::cell::{Cell, CELL};
use crate::NetError;
use nbf_crypto::CryptoError;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

pub const HS_MTU: usize = 1200;
/// Datagram HS tối đa (reassembly buffer).
pub const HS_DGRAM: usize = 2048;
/// Khuôn Noise: IK (1-RTT, static key đã biết trước).
const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Session Noise per-peer (transport 1-RTT, hai chiều nonce riêng).
pub struct Session {
    pub transport: snow::TransportState,
}

/// Datagrams nhận được từ socket (chỉ cell — HS xử lý nội bộ trong link).
#[derive(Debug, Clone)]
pub enum WireMsg {
    Cell(Cell),
}

/// Link socket UDP — sở hữu socket, tự quản HS/session, đẩy cell lên Node.
pub struct Link {
    socket: Arc<UdpSocket>,
    sessions: Arc<Mutex<HashMap<SocketAddr, Session>>>,
    /// static key cục bộ (private, cho Noise).
    local_static: [u8; 32],
    peer_statics: Arc<Mutex<HashMap<SocketAddr, [u8; 32]>>>,
    hs_inflight: Arc<Mutex<HashMap<SocketAddr, snow::HandshakeState>>>,
    tx: mpsc::Sender<(SocketAddr, WireMsg)>,
    rx: Mutex<Option<mpsc::Receiver<(SocketAddr, WireMsg)>>>,
    recv_task: tokio::task::JoinHandle<()>,
}

impl Link {
    /// Bind UDP socket và khởi recv task.
    pub async fn bind(addr: SocketAddr, local_static: &[u8; 32]) -> Result<Link, NetError> {
        let socket = Arc::new(
            UdpSocket::bind(addr)
                .await
                .map_err(|e| NetError::Io(format!("bind {addr}: {e}")))?,
        );
        let (tx, rx) = mpsc::channel::<(SocketAddr, WireMsg)>(256);
        let sessions: Arc<Mutex<HashMap<SocketAddr, Session>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let peer_statics: Arc<Mutex<HashMap<SocketAddr, [u8; 32]>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let hs_inflight: Arc<Mutex<HashMap<SocketAddr, snow::HandshakeState>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let local = *local_static;
        let s = socket.clone();
        let tx2 = tx.clone();
        let sess2 = sessions.clone();
        let ps2 = peer_statics.clone();
        let infl2 = hs_inflight.clone();
        // Task nền duy nhất: nhận datagram, phân loại HS/cipher/cell:
        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; HS_DGRAM];
            // Gom mảnh HS theo src: (total, idx→chunk):
            let mut hs_buf: HashMap<SocketAddr, (u16, HashMap<u16, Vec<u8>>)> = HashMap::new();
            loop {
                let (n, src) = match s.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let data = &buf[..n];
                if data.is_empty() {
                    continue;
                }
                if data[0] == 0x7F && data.len() >= 5 {
                    // Mảnh HS: reassembly per-src rồi hoàn tất handshake:
                    let total = u16::from_le_bytes([data[1], data[2]]);
                    let idx = u16::from_le_bytes([data[3], data[4]]);
                    let e = hs_buf.entry(src).or_insert((total, HashMap::new()));
                    e.1.insert(idx, data[5..].to_vec());
                    if e.1.len() == e.0 as usize {
                        let (_, parts) = hs_buf.remove(&src).unwrap();
                        let mut msg = Vec::new();
                        for i in 0..total {
                            if let Some(c) = parts.get(&i) {
                                msg.extend_from_slice(c);
                            }
                        }
                        handle_hs(&sess2, &infl2, &ps2, local, &s, src, &msg).await;
                    }
                } else {
                    // Cell: decrypt qua session nếu có, ngược lại coi là cell rõ (MVP).
                    let plain = {
                        let mut sess = sess2.lock().await;
                        match sess.get_mut(&src) {
                            Some(ss) => {
                                let mut out = vec![0u8; HS_DGRAM];
                                match ss.transport.read_message(data, &mut out) {
                                    Ok(n) => Some(out[..n].to_vec()),
                                    Err(_) => None,
                                }
                            }
                            None => None,
                        }
                    };
                    let plain = plain.unwrap_or_else(|| data.to_vec());
                    if let Ok(cell) = Cell::decode(&plain) {
                        if tx2.send((src, WireMsg::Cell(cell))).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Link {
            socket,
            sessions,
            local_static: local,
            peer_statics,
            hs_inflight,
            tx,
            rx: Mutex::new(Some(rx)),
            recv_task,
        })
    }

    /// Đăng ký khóa công khai tĩnh của peer (cần trước khi gửi tới peer đó).
    pub async fn set_peer_static_async(&self, addr: SocketAddr, pub_key: [u8; 32]) {
        self.peer_statics.lock().await.insert(addr, pub_key);
    }

    /// Phiên bản sync (ngoài runtime).
    pub fn set_peer_static(&self, addr: SocketAddr, pub_key: [u8; 32]) {
        self.peer_statics.blocking_lock().insert(addr, pub_key);
    }

    /// Socket addr cục bộ.
    pub fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    /// Lấy receiver duy nhất — chỉ gọi 1 lần (None nếu đã lấy).
    pub async fn subscribe(&self) -> Option<mpsc::Receiver<(SocketAddr, WireMsg)>> {
        self.rx.lock().await.take()
    }

    /// Gửi cell tới addr: tự HS nếu chưa có session, chờ session (2s), gửi mã hóa.
    pub async fn send_cell(&self, addr: SocketAddr, cell: &Cell) -> Result<(), NetError> {
        if !self.sessions.lock().await.contains_key(&addr) {
            let pubk = *self
                .peer_statics
                .lock()
                .await
                .get(&addr)
                .ok_or(NetError::NoSession)?;
            let mut infl = self.hs_inflight.lock().await;
            if !infl.contains_key(&addr) {
                let params: snow::params::NoiseParams =
                    PATTERN.parse().map_err(|e| noise_err(&e))?;
                let mut st = snow::Builder::new(params)
                    .local_private_key(&self.local_static)
                    .remote_public_key(&pubk)
                    .build_initiator()
                    .map_err(|e| noise_err(&e))?;
                let mut out = vec![0u8; 512];
                let n = st.write_message(&[], &mut out).map_err(|e| noise_err(&e))?;
                self.send_hs_fragmented(addr, &out[..n]).await?;
                infl.insert(addr, st);
            }
            drop(infl);
            // Chờ responder hoàn tất (msg2 về → session xuất hiện):
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !self.sessions.lock().await.contains_key(&addr) {
                if std::time::Instant::now() >= deadline {
                    self.hs_inflight.lock().await.remove(&addr);
                    return Err(NetError::Timeout);
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        // Có session — mã hóa + gửi:
        let (n, out) = {
            let mut sess = self.sessions.lock().await;
            let ss = sess.get_mut(&addr).ok_or(NetError::NoSession)?;
            let mut out = vec![0u8; CELL + 16];
            let n = ss
                .transport
                .write_message(&cell.encode(), &mut out)
                .map_err(|e| noise_err(&e))?;
            (n, out)
        };
        self.socket
            .send_to(&out[..n], addr)
            .await
            .map_err(|e| NetError::Io(e.to_string()))?;
        Ok(())
    }

    /// Gửi mảnh HS (bản rõ, kênh 0x7F fragmented).
    async fn send_hs_fragmented(&self, addr: SocketAddr, data: &[u8]) -> Result<(), NetError> {
        let chunk = HS_MTU - 5;
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
}

fn noise_err(e: &impl std::fmt::Display) -> NetError {
    NetError::Crypto(CryptoError::Noise(e.to_string()))
}

/// Hoàn tất 1 handshake từ msg reassembled: initiator đang chờ coi là msg2,
/// ngược lại mình là responder (msg1) → trả msg2, insert session 2 chiều.
async fn handle_hs(
    sessions: &Mutex<HashMap<SocketAddr, Session>>,
    inflight: &Mutex<HashMap<SocketAddr, snow::HandshakeState>>,
    peer_statics: &Mutex<HashMap<SocketAddr, [u8; 32]>>,
    local_static: [u8; 32],
    socket: &Arc<UdpSocket>,
    src: SocketAddr,
    msg: &[u8],
) {
    // 1) Initiator đang chờ msg2:
    {
        let mut infl = inflight.lock().await;
        if let Some(mut st) = infl.remove(&src) {
            let mut out = vec![0u8; 1024];
            if st.read_message(msg, &mut out).is_ok() {
                if let Ok(t) = st.into_transport_mode() {
                    sessions.lock().await.insert(src, Session { transport: t });
                    return;
                }
            }
            // Đọc msg2 fail → rơi xuống coi như msg1 (responder mới).
        }
    }
    // 2) Responder: msg1 → msg2:
    let params: snow::params::NoiseParams = match PATTERN.parse() {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut st = match snow::Builder::new(params)
        .local_private_key(&local_static)
        .build_responder()
    {
        Ok(b) => b,
        Err(_) => return,
    };
    let mut out = vec![0u8; 1024];
    if st.read_message(msg, &mut out).is_err() {
        return; // KHÔNG phản hồi — tránh oracle
    }
    let mut out2 = vec![0u8; 1024];
    let n2 = match st.write_message(&[], &mut out2) {
        Ok(n) => n,
        Err(_) => return,
    };
    // Gửi msg2 qua kênh HS fragmented:
    let chunk = HS_MTU - 5;
    let cnt = n2.div_ceil(chunk).max(1);
    for i in 0..cnt {
        let a = i * chunk;
        let b = ((i + 1) * chunk).min(n2);
        let mut p = Vec::with_capacity(5 + (b - a));
        p.push(0x7F);
        p.extend_from_slice(&(cnt as u16).to_le_bytes());
        p.extend_from_slice(&(i as u16).to_le_bytes());
        p.extend_from_slice(&out2[a..b]);
        let _ = socket.send_to(&p, src).await;
    }
    // Học static của peer (để sau này gửi tới peer này không cần HS ngược):
    if let Some(r) = st.get_remote_static().map(|k| {
        let mut key = [0u8; 32];
        key.copy_from_slice(k);
        key
    }) {
        peer_statics.lock().await.insert(src, r);
    }
    if let Ok(t) = st.into_transport_mode() {
        sessions.lock().await.insert(src, Session { transport: t });
    }
}
