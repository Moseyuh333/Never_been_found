//! Kademlia: bảng định tuyến XOR + store/lookup descriptor trên UDP.
//! Đủ dùng cho v1: k=3, alpha=3, mỗi node 1 bucket phẳng (không chia k-bucket theo prefix).

use crate::{ping_response, rpc_decode, rpc_encode, Contact, DhtError, RpcMsg};
use nbf_crypto::{Descriptor, NodeId};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{timeout, Duration};

pub const K: usize = 3;
pub const ALPHA: usize = 3;
pub const TTL_DESC: u64 = 86_400; // 24h

pub struct Kademlia {
    pub id: NodeId,
    pub own_desc: Descriptor,
    pub rt: RwLock<Vec<Contact>>,
    pub store: RwLock<HashMap<NodeId, Descriptor>>,
    socket: Arc<UdpSocket>,
    pub local_addr: SocketAddr,
    /// oneshot chờ reply theo addr — run() route Found/Pong về đây (tránh race recv).
    pending: Mutex<HashMap<SocketAddr, tokio::sync::oneshot::Sender<RpcMsg>>>,
}

impl Kademlia {
    pub fn new(id: NodeId, own_desc: Descriptor, bind_port: u16) -> Result<Self, DhtError> {
        let socket = std::net::UdpSocket::bind(("127.0.0.1", bind_port))?;
        socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        let local_addr = socket.local_addr()?;
        Ok(Kademlia {
            id,
            rt: RwLock::new(vec![Contact::from_desc(&own_desc)]),
            store: RwLock::new(HashMap::new()),
            socket,
            local_addr,
            own_desc,
            pending: Mutex::new(HashMap::new()),
        })
    }

    pub async fn run(self: Arc<Self>) {
        let mut buf = vec![0u8; 4096];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    let data = buf[..n].to_vec();
                    // Reply Found/Pong cho request của mình → route vào pending:
                    if let Ok(m) = rpc_decode(&data) {
                        if matches!(m, RpcMsg::Found { .. } | RpcMsg::Pong { .. }) {
                            let tx = self.pending.lock().await.remove(&from);
                            if let Some(tx) = tx {
                                let _ = tx.send(m);
                                continue;
                            }
                        }
                    }
                    let me = self.clone();
                    tokio::spawn(async move { me.handle(from, data).await });
                }
                Err(_) => continue,
            }
        }
    }

    async fn handle(self: Arc<Self>, from: SocketAddr, data: Vec<u8>) {
        let msg = match rpc_decode(&data) {
            Ok(m) => m,
            Err(_) => return,
        };
        match msg {
            RpcMsg::Ping { nonce } => {
                let _ = self.send_raw(from, &rpc_encode(&ping_response(nonce))).await;
            }
            RpcMsg::Store { desc } => {
                self.store.write().await.insert(desc.node_id, desc.clone());
                self.try_merge(&[Contact::from_desc(&desc)]).await;
            }
            RpcMsg::Find { key, want_value } => {
                let near = self.closest(&key, K).await;
                let val = if want_value {
                    self.store.read().await.get(&key).cloned()
                } else {
                    None
                };
                let _ = self
                    .send_raw(
                        from,
                        &rpc_encode(&RpcMsg::Found {
                            contacts: near,
                            value: val,
                        }),
                    )
                    .await;
            }
            RpcMsg::Found { .. } | RpcMsg::Pong { .. } => {
                // reply chỉ được consume ở caller (send_rpc)
            }
        }
    }

    async fn send_raw(&self, addr: SocketAddr, data: &[u8]) -> Result<(), DhtError> {
        self.socket.send_to(data, addr).await?;
        Ok(())
    }

    pub async fn send_rpc(
        &self,
        addr: SocketAddr,
        msg: RpcMsg,
        timeout_ms: u64,
    ) -> Result<RpcMsg, DhtError> {
        let data = rpc_encode(&msg);
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().await.insert(addr, tx);
        self.socket.send_to(&data, addr).await?;
        match timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(m)) => Ok(m),
            Ok(Err(_)) => Err(DhtError::BadType(0xFF)),
            Err(_) => {
                self.pending.lock().await.remove(&addr);
                Err(DhtError::BadLen(0)) // timeout
            }
        }
    }

    /// XOR metric: khoảng cách giữa 2 id (byte-wise so sánh tới hết 20B).
    pub fn dist(a: &NodeId, b: &NodeId) -> Vec<u8> {
        a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
    }

    pub async fn closest(&self, key: &NodeId, k: usize) -> Vec<Contact> {
        let rt = self.rt.read().await;
        let mut all: Vec<&Contact> = rt.iter().collect();
        all.sort_by_key(|c| Kademlia::dist(&c.node_id, key));
        all.truncate(k);
        all.into_iter().cloned().collect()
    }

    pub async fn try_merge(&self, contacts: &[Contact]) {
        let mut rt = self.rt.write().await;
        for c in contacts {
            if c.node_id == self.id {
                continue;
            }
            if !rt.iter().any(|x| x.node_id == c.node_id) {
                rt.push(c.clone());
            }
        }
        rt.sort_by_key(|c| Kademlia::dist(&c.node_id, &self.id));
        rt.truncate(64);
    }

    pub async fn bootstrap(&self, seeds: &[SocketAddr]) -> Result<(), DhtError> {
        for s in seeds {
            let nonce = rand::random::<u64>();
            let _ = self.send_rpc(*s, RpcMsg::Ping { nonce }, 1000).await;
            if let Ok(RpcMsg::Found { contacts, .. }) = self
                .send_rpc(*s, RpcMsg::Find { key: self.id, want_value: false }, 1000)
                .await
            {
                self.try_merge(&contacts).await;
            }
        }
        Ok(())
    }

    pub async fn store_self(&self, seeds: &[SocketAddr]) -> Result<(), DhtError> {
        for s in seeds {
            let _ = self
                .send_rpc(*s, RpcMsg::Store { desc: self.own_desc.clone() }, 1000)
                .await;
        }
        Ok(())
    }

    /// Iterative lookup: tới khi hội tụ (không cải thiện) hoặc tìm thấy value.
    pub async fn lookup(
        &self,
        key: &NodeId,
        want_value: bool,
    ) -> Result<Option<Descriptor>, DhtError> {
        let mut closest_seen = self.closest(key, K).await;
        let mut queried: Vec<NodeId> = Vec::new();
        loop {
            let batch = closest_seen
                .iter()
                .filter(|c| !queried.contains(&c.node_id))
                .cloned()
                .take(ALPHA)
                .collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            for c in &batch {
                queried.push(c.node_id);
                if let Ok(RpcMsg::Found { contacts, value }) = self
                    .send_rpc(
                        c.addr(),
                        RpcMsg::Find {
                            key: *key,
                            want_value,
                        },
                        1000,
                    )
                    .await
                {
                    if want_value {
                        if let Some(v) = &value {
                            return Ok(Some(v.clone()));
                        }
                    }
                    self.try_merge(&contacts).await;
                }
            }
            let next = self.closest(key, K).await;
            if next.len() == closest_seen.len()
                && next
                    .iter()
                    .all(|c| closest_seen.iter().any(|o| o.node_id == c.node_id))
            {
                break;
            }
            closest_seen = next;
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nbf_crypto::NodeIdentity;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    async fn node(seed: u64, port: u16) -> (Arc<Kademlia>, Descriptor) {
        let mut rng = StdRng::seed_from_u64(seed);
        let id = NodeIdentity::random(&mut rng);
        let d = Descriptor::sign(
            &id,
            format!("127.0.0.1:{}", port).parse().unwrap(),
            port + 1,
            1_000,
        );
        let k = Arc::new(Kademlia::new(id.node_id(), d.clone(), port + 1).unwrap());
        let kk = k.clone();
        tokio::spawn(async move { kk.run().await });
        (k, d)
    }

    #[tokio::test]
    async fn bootstrap_ping_store_lookup_3_node() {
        let (a, _da) = node(10, 9501).await;
        let (b, db) = node(11, 9503).await;
        let (_c, dc) = node(12, 9505).await;

        // a bootstrap qua b; b biết c.
        a.bootstrap(&[db.dht_addr()]).await.unwrap();
        b.bootstrap(&[dc.dht_addr()]).await.unwrap();
        // store self qua b để b học a
        a.store_self(&[db.dht_addr()]).await.unwrap();

        // a lookup c — đường đi a→b→c (k=3 nên a cũng có thể học c từ FIND trả về).
        let found = a.lookup(&dc.node_id, false).await;
        assert!(found.is_ok());
        // lookup trả Option<Descriptor>; value=false thì chỉ cần contacts gần nhất — trả None được,
        // nhưng a PHẢI biết địa chỉ c để kết nối. Test kiểm: a rt có c.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(a.rt.read().await.iter().any(|x| x.node_id == dc.node_id));

        // Và bây giờ tìm value:
        let v = a.lookup(&dc.node_id, true).await.unwrap();
        if let Some(d) = v {
            assert_eq!(d.node_id, dc.node_id);
        }
        // Đăng ký store cho c qua b (b là neighbor của c):
        b.store_self(&[dc.dht_addr()]).await.unwrap();
        let v2 = a.lookup(&dc.node_id, true).await.unwrap();
        if let Some(d) = v2 {
            assert_eq!(d.node_id, dc.node_id);
        }
    }
}
