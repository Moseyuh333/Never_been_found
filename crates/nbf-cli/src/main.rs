//! CLI NBF: chạy node, gửi tin ẩn danh, demo nhanh.

use anyhow::Result;
use clap::{Parser, Subcommand};
use nbf_net::node::{CoverCfg, Node, NodeConfig};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "nbf",
    about = "Never-Been-Found: routing ẩn danh 1-RTT + PQC + DHT"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Chạy một node nền.
    Node {
        #[arg(long, default_value_t = 20100)]
        cell_port: u16,
        #[arg(long, default_value_t = 20101)]
        dht_port: u16,
        #[arg(long)]
        seed: Vec<String>,
        #[arg(long, default_value_t = true)]
        cover: bool,
    },
    /// Gửi tin ẩn danh tới một node (echo).
    Send {
        #[arg(long)]
        seed: String,
        #[arg(long)]
        to: String,
        #[arg(long, default_value = "xin chao")]
        msg: String,
    },
    /// Demo 6 node trên localhost.
    Demo,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Node {
            cell_port,
            dht_port,
            seed,
            cover,
        } => {
            let cfg = NodeConfig {
                cell_port,
                dht_port,
                seeds: seed,
                cover: CoverCfg {
                    on: cover,
                    min_interval_ms: 500,
                    max_interval_ms: 2000,
                },
                rng_seed: None,
            };
            let node = Node::spawn(cfg).await;
            println!("NBF node up: node_id={}", hex::encode(node.node_id));
            println!(
                "cell={} dht={} cover={}",
                node.config.cell_port, node.config.dht_port, cover
            );
            println!("Nhấn Ctrl+C để dừng.");
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
        Cmd::Send { seed, to, msg } => {
            let to_bytes = hex::decode(&to)?;
            if to_bytes.len() != 20 {
                anyhow::bail!("--to phải là 20 byte hex (40 ký tự)");
            }
            let mut target = [0u8; 20];
            target.copy_from_slice(&to_bytes);
            let reply = nbf_cli::send_once(&seed, target, msg.as_bytes(), 6).await?;
            println!(
                "Reply từ {}: {}",
                hex::encode(target),
                String::from_utf8_lossy(&reply)
            );
            Ok(())
        }
        Cmd::Demo => {
            nbf_cli::demo().await?;
            Ok(())
        }
    }
}
