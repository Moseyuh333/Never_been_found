//! Demo 6 node + helper send_once dùng chung cho subcommand Send.

use anyhow::Result;
use nbf_crypto::NodeId;
use nbf_net::build_circuit;
use nbf_net::node::{stats_of, CoverCfg, Node, NodeConfig};
use rand::Rng;
use std::time::Duration;

fn cfg(i: u16, on: bool) -> NodeConfig {
    NodeConfig {
        cell_port: 12000 + i * 2,
        dht_port: 12000 + i * 2 + 1,
        seeds: if i == 0 {
            vec![]
        } else {
            vec!["127.0.0.1:12001".into()]
        },
        cover: CoverCfg {
            on,
            min_interval_ms: 500,
            max_interval_ms: 2000,
        },
        rng_seed: None,
    }
}

/// Spawn n_nodes node, build circuit 3 hop ngẫu nhiên tới target, echo, trả reply.
pub async fn send_once(seed: &str, target: NodeId, msg: &[u8], n_nodes: usize) -> Result<Vec<u8>> {
    let _ = seed; // seed hiện dùng cục bộ trong cfg (localhost MVP)
    let mut nodes = Vec::new();
    for i in 0..n_nodes as u16 {
        nodes.push(Node::spawn(cfg(i, true)).await);
    }
    tokio::time::sleep(Duration::from_millis(600)).await; // DHT bootstrap

    // Chọn 3 hop ngẫu nhiên khác target:
    let peers = nodes[0].route_peers().await;
    let mut pool: Vec<NodeId> = peers
        .iter()
        .map(|p| p.0)
        .filter(|id| *id != target)
        .collect();
    if pool.len() < 3 {
        anyhow::bail!("cần ≥ 4 node biết nhau để chọn 3 hop, có {}", pool.len());
    }
    let mut rng = rand::thread_rng();
    let mut route = Vec::new();
    for _ in 0..3 {
        let i = rng.gen_range(0..pool.len());
        route.push(pool.remove(i));
    }
    route.push(target);

    let client = nodes[0].clone();
    let handle = build_circuit(client.clone(), &route, None).await?;
    let reply = handle.echo(msg, Duration::from_secs(5)).await?;
    handle.close().await;
    Ok(reply)
}

pub async fn demo() -> Result<()> {
    println!("== NBF demo: 6 node, circuit 3 hop, echo ẩn danh ==");
    let mut nodes = Vec::new();
    for i in 0..6u16 {
        nodes.push(Node::spawn(cfg(i, true)).await);
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    for (i, n) in nodes.iter().enumerate() {
        println!(
            "node{}: id={} cell={} dht={}",
            i,
            hex::encode(n.node_id),
            n.config.cell_port,
            n.config.dht_port
        );
    }

    let client = nodes[0].clone();
    let service = nodes[5].clone();
    let route = vec![
        nodes[1].node_id,
        nodes[2].node_id,
        nodes[3].node_id,
        service.node_id,
    ];
    let handle = build_circuit(client.clone(), &route, None).await?;
    let msg = b"demo: tin nhan nay di qua 4 hop ma khong hop nao doc duoc";
    let reply = handle.echo(msg, Duration::from_secs(5)).await?;
    assert_eq!(reply, msg);
    println!(
        "echo OK — {}/{}/{} hop đã chuyển RELAY",
        stats_of(&nodes[1]).await.relayed,
        stats_of(&nodes[2]).await.relayed,
        stats_of(&nodes[3]).await.relayed
    );
    handle.close().await;
    println!("== demo thành công ==");
    Ok(())
}
