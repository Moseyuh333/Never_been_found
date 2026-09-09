//! Phía origin: dựng circuit (build header Sphinx, gửi CREATE fragmented, chờ CREATED),
//! giữ khóa fwd/bwd để bọc/mở RELAY, expose echo/data API.

use crate::cell::{fragment, seal_onion, Cell, Cmd, MSG_MAX};
use crate::node::{CircuitEntry, HopLink, Node};
use crate::{NetError, RCmd};
use nbf_crypto::sphinx::{build_header, RouteNode};
use nbf_crypto::NodeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub struct CircuitHandle {
    pub node: Arc<Node>,
    pub cid: u32,
    pub fwd: Vec<[u8; 32]>,
    pub bwd: Vec<[u8; 32]>,
    pub tag: [u8; 16],
}

pub async fn build_circuit(
    node: Arc<Node>,
    route: &[NodeId],
    _hint: Option<NodeId>,
) -> Result<CircuitHandle, NetError> {
    if route.is_empty() || route.len() > nbf_crypto::MAX_HOPS {
        return Err(NetError::BadLength(route.len()));
    }
    // Resolve mọi hop ra Descriptor (qua cache/store/DHT):
    let mut descs = Vec::with_capacity(route.len());
    for id in route {
        let d = node.lookup_route(*id).await?;
        descs.push(d);
    }
    let rns: Vec<RouteNode> = descs.iter().map(|d| RouteNode { desc: d }).collect();

    // Chuẩn bị khóa + tag ngẫu nhiên — sinh từ rng node:
    let mut tag = [0u8; 16];
    let built = {
        let mut rng = node.rng.lock().await;
        rand::RngCore::fill_bytes(&mut *rng, &mut tag);
        build_header(&rns, tag, &mut *rng)?
    };

    let cid = node.new_cid();
    // Gửi CREATE fragmented tới hop1:
    node.ensure_peer_link(built.first_addr, descs[0].link_pub)
        .await;
    for frag in fragment(&built.header) {
        let c = Cell {
            cid,
            cmd: Cmd::Create,
            flags: 0,
            payload: frag,
        };
        let _ = node.link.send_cell(built.first_addr, &c).await;
    }
    // Chờ CREATED:
    let (tx, rx) = tokio::sync::oneshot::channel();
    node.pending.lock().await.insert(cid, tx);
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(Ok(()))) => {}
        _ => {
            node.pending.lock().await.remove(&cid);
            return Err(NetError::Timeout);
        }
    }
    // Lưu entry Origin:
    let fwd = built.fwd_keys.clone();
    let bwd = built.bwd_keys.clone();
    node.circuits.lock().await.insert(
        cid,
        CircuitEntry::Origin {
            fwd: fwd.clone(),
            bwd: bwd.clone(),
            tag,
            next: HopLink {
                cid,
                peer: built.first_addr,
            },
            streams: HashMap::new(),
        },
    );
    Ok(CircuitHandle {
        node: node.clone(),
        cid,
        fwd,
        bwd,
        tag,
    })
}

impl CircuitHandle {
    /// Gửi ECHO tới terminal và chờ reply (tối đa timeout).
    pub async fn echo(&self, msg: &[u8], timeout: Duration) -> Result<Vec<u8>, NetError> {
        if msg.len() > MSG_MAX {
            return Err(NetError::BadLength(msg.len()));
        }
        let stream = 1u16;
        let mut rx = self.node.open_stream(self.cid, stream).await;
        self.send(stream, RCmd::Echo, msg).await?;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(data)) => Ok(data),
            _ => Err(NetError::Timeout),
        }
    }

    pub async fn send_data(&self, msg: &[u8], stream: u16) -> Result<(), NetError> {
        if msg.len() > MSG_MAX {
            return Err(NetError::BadLength(msg.len()));
        }
        self.send(stream, RCmd::Data, msg).await
    }

    async fn send(&self, stream: u16, rcmd: RCmd, msg: &[u8]) -> Result<(), NetError> {
        let seq = self
            .node
            .seq_origin
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let onion = seal_onion(&self.fwd, &self.tag, seq, msg);
        let mut payload = Vec::with_capacity(7 + onion.len());
        payload.extend_from_slice(&seq.to_le_bytes());
        payload.push(rcmd as u8);
        payload.extend_from_slice(&stream.to_le_bytes());
        payload.extend_from_slice(&onion);
        let c = Cell {
            cid: self.cid,
            cmd: Cmd::Relay,
            flags: 0,
            payload,
        };
        let next = match self
            .node
            .circuits
            .lock()
            .await
            .get(&self.cid)
            .map(|e| e.cloned_entry())
        {
            Some(CircuitEntry::Origin { next, .. }) => next,
            _ => return Err(NetError::NoSession),
        };
        self.node.link.send_cell(next.peer, &c).await?;
        Ok(())
    }

    pub async fn close(&self) -> Result<(), NetError> {
        let c = Cell {
            cid: self.cid,
            cmd: Cmd::Destroy,
            flags: 0,
            payload: vec![],
        };
        let next = match self
            .node
            .circuits
            .lock()
            .await
            .get(&self.cid)
            .map(|e| e.cloned_entry())
        {
            Some(CircuitEntry::Origin { next, .. }) => next,
            _ => return Ok(()),
        };
        let _ = self.node.link.send_cell(next.peer, &c).await;
        self.node.circuits.lock().await.remove(&self.cid);
        Ok(())
    }
}

/// Chọn 1 circuit origin đang mở (cho cover DROP) — tái dựng handle nhẹ.
pub async fn pick_origin(node: &Arc<Node>) -> Option<CircuitHandle> {
    let found = {
        let c = node.circuits.lock().await;
        c.iter().find_map(|(cid, v)| match v {
            CircuitEntry::Origin { fwd, bwd, tag, .. } => {
                Some((*cid, fwd.clone(), bwd.clone(), *tag))
            }
            _ => None,
        })
    }?;
    let (cid, fwd, bwd, tag) = found;
    Some(CircuitHandle {
        node: node.clone(),
        cid,
        fwd,
        bwd,
        tag,
    })
}
