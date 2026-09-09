//! Cover traffic: (1) PADDING giữ link luôn có tế bào nền khi rảnh,
//! (2) RELAY DROP giả trên circuit đang chạy — che độ dài/chủng loại luồng thật.
//! Thời gian ngẫu nhiên trong [min,max] — không tạo chu kỳ phát hiện được.

use crate::cell::Cell;
use crate::node::{CircuitEntry, Node};
use crate::{Cmd, RCmd};
use rand::Rng;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

/// Vòng lặp cover chạy nền (spawn từ Node::spawn khi config.cover.on).
pub async fn run_loop(node: Arc<Node>) {
    loop {
        let (min, max) = {
            let c = &node.config.cover;
            (c.min_interval_ms, c.max_interval_ms)
        };
        let wait_ms = {
            let mut rng = node.rng.lock().await;
            rng.gen_range(min..=max)
        };
        sleep(Duration::from_millis(wait_ms)).await;

        // (1) PADDING tới 1 peer ngẫu nhiên đã biết:
        if let Some((peer, link_pub)) = pick_peer(&node).await {
            node.ensure_peer_link(peer, link_pub).await;
            let c = Cell { cid: 0, cmd: Cmd::Padding, flags: 0, payload: vec![] };
            if node.link.send_cell(peer, &c).await.is_ok() {
                node.stats.lock().await.padding_sent += 1;
            }
        }

        // (2) DROP giả trên circuit origin đang mở:
        let drops_on = node
            .circuits
            .lock()
            .await
            .iter()
            .any(|(_, e)| matches!(e, CircuitEntry::Origin { .. }));
        if drops_on {
            if let Some(handle) = crate::builder::pick_origin(&node).await {
                // stream 0 = mồi DROP (terminal bỏ, nhưng onion vẫn đi hết route):
                let _ = handle.send_data(&[0u8; 64], 0).await;
                node.stats.lock().await.drops_sent += 1;
            }
        }
    }
}

async fn pick_peer(node: &Arc<Node>) -> Option<(std::net::SocketAddr, [u8; 32])> {
    let peers = node.route_peers().await;
    if peers.is_empty() {
        return None;
    }
    let mut rng = node.rng.lock().await;
    let i = rng.gen_range(0..peers.len());
    Some((peers[i].1, peers[i].2))
}
