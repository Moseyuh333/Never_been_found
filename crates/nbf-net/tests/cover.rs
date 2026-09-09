//! Cover traffic: PADDING link + RELAY DROP circuit — không đổi hành vi echo.

use std::time::Duration;
use nbf_net::node::{stats_of, CoverCfg, Node, NodeConfig};
use nbf_net::build_circuit;

fn cfg(base: u16, i: u16, on: bool) -> NodeConfig {
    NodeConfig {
        cell_port: base + i * 2,
        dht_port: base + i * 2 + 1,
        seeds: if i == 0 { vec![] } else { vec![format!("127.0.0.1:{}", base + 1)] },
        cover: CoverCfg { on, min_interval_ms: 200, max_interval_ms: 400 },
        rng_seed: Some(0xABC + i as u64),
    }
}

#[tokio::test]
async fn padding_duoc_gui_khi_bat_cover() {
    let mut nodes = Vec::new();
    for i in 0..4u16 {
        nodes.push(Node::spawn(cfg(11000, i, i != 3)).await); // node 3 tắt cover làm đối chứng
    }
    // Để cover loop kịp chạy vài vòng:
    tokio::time::sleep(Duration::from_millis(1600)).await;

    // Node bật cover phải có padding_recv > 0 (padding_sent > 0 chắc chắn nếu có peer):
    let mut any_recv = false;
    for i in 0..3 {
        let s = stats_of(&nodes[i]).await;
        if s.padding_recv > 0 {
            any_recv = true;
        }
    }
    assert!(any_recv, "ít nhất 1 node bật cover phải nhận padding");
    // Node tắt cover KHÔNG GỬI padding (đối chứng) — nhưng vẫn có thể NHẬN từ peer:
    let s_off = stats_of(&nodes[3]).await;
    assert_eq!(s_off.padding_sent, 0, "node tắt cover không gửi padding");
    drop(nodes);
}

#[tokio::test]
async fn drop_khong_lam_hong_echo() {
    let mut nodes = Vec::new();
    for i in 0..5u16 {
        nodes.push(Node::spawn(cfg(12000, i, true)).await);
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    let client = nodes[0].clone();
    let service = nodes[4].clone();
    let handle = build_circuit(
        client.clone(),
        &[nodes[1].node_id, nodes[2].node_id, service.node_id],
        None,
    )
    .await
    .unwrap();
    // Gửi vài DROP mồi trên circuit trước khi echo (terminal bỏ RCmd không Echo):
    for _ in 0..3 {
        handle.send_data(b"garbage-drop", 99).await.unwrap();
    }
    let reply = handle.echo(b"van con song", Duration::from_secs(5)).await.unwrap();
    assert_eq!(reply, b"van con song");
    handle.close().await;
    drop(nodes);
}
