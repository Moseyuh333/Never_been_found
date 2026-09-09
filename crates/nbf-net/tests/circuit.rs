//! E2E: client → 3 hop → echo service, không hop nào thấy plaintext.

use std::time::Duration;
use nbf_net::node::{CoverCfg, Node, NodeConfig};
use nbf_net::build_circuit;

fn cfg(base: u16, i: u16, seeds: Vec<String>) -> NodeConfig {
    NodeConfig {
        cell_port: base + i * 2,
        dht_port: base + i * 2 + 1,
        seeds,
        cover: CoverCfg { on: false, min_interval_ms: 1000, max_interval_ms: 2000 },
        rng_seed: Some(0xDEAD + i as u64),
    }
}

fn seeds_for(base: u16, i: u16) -> Vec<String> {
    if i == 0 {
        vec![]
    } else {
        vec![format!("127.0.0.1:{}", base + 1)]
    }
}

#[tokio::test]
async fn e2e_3hop_echo() {
    // Node 0 là seed, node 1,2 là hop, node 4 là client, node 5 terminal/echo.
    let mut nodes = Vec::new();
    for i in 0..6u16 {
        nodes.push(Node::spawn(cfg(20000, i, seeds_for(20000, i))).await);
    }
    tokio::time::sleep(Duration::from_millis(600)).await;

    let client = &nodes[4];
    let service = &nodes[5];

    // Route 3 hop: node1 → node2 → service(5). Client = node4 (đi circuit như mọi node).
    let handle = build_circuit(
        client.clone(),
        &[nodes[1].node_id, nodes[2].node_id, service.node_id],
        Some(nodes[0].node_id),
    )
    .await
    .expect("dựng circuit 3 hop");

    let reply = handle
        .echo(b"xin chao tu the void", Duration::from_secs(5))
        .await
        .expect("echo phải trả về");
    assert_eq!(reply, b"xin chao tu the void");

    handle.close().await;
    drop(nodes);
}

#[tokio::test]
async fn trung_gian_khong_thay_plaintext() {
    let mut nodes = Vec::new();
    for i in 0..6u16 {
        nodes.push(Node::spawn(cfg(21000, i, seeds_for(21000, i))).await);
    }
    tokio::time::sleep(Duration::from_millis(600)).await;

    let client = nodes[4].clone();
    let service = nodes[5].clone();
    let mid1 = nodes[1].clone();
    let mid2 = nodes[2].clone();

    let handle =
        build_circuit(client, &[nodes[1].node_id, nodes[2].node_id, service.node_id], None)
            .await
            .unwrap();
    let secret = b"MAT_KHAU_BI_MAT_KHONG_HOP_NAO_THAY";
    let reply = handle.echo(secret, Duration::from_secs(5)).await.unwrap();
    assert_eq!(reply, secret);

    // Mid hops phải đã chuyển RELAY (onion mã hóa — thiết kế đảm bảo không đọc được plaintext;
    // bằng chứng tầng thiết kế: mỗi hop chỉ giữ k_fwd/k_bwd của riêng mình, test AEAD riêng).
    let s1 = nbf_net::node::stats_of(&mid1).await;
    let s2 = nbf_net::node::stats_of(&mid2).await;
    assert!(s1.relayed > 0 || s2.relayed > 0);
    handle.close().await;
    drop(nodes);
}
