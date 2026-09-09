//! Node engine: xử lý CREATE/CREATED/DESTROY/PADDING, quản lý circuit, stats.
//! RELAY được delegate sang `crate::relay` (Task 10).

use crate::cell::{fragment, parse_frag, reassemble, Cell, Cmd, FragBuf};
use crate::link::{Link, WireMsg};
use crate::NetError;
use nbf_crypto::sphinx::ProcessOutcome;
use nbf_crypto::{process_header, Descriptor, NodeId, NodeIdentity};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

pub const MAX_HOPS: usize = 8;

#[derive(Debug, Clone)]
pub struct CoverCfg {
    pub on: bool,
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
}

impl Default for CoverCfg {
    fn default() -> Self {
        CoverCfg {
            on: true,
            min_interval_ms: 500,
            max_interval_ms: 2000,
        }
    }
}

pub struct NodeConfig {
    pub cell_port: u16,
    pub dht_port: u16,
    pub seeds: Vec<String>,
    pub cover: CoverCfg,
    pub rng_seed: Option<u64>,
}

#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub created: u64,
    pub relayed: u64,
    pub destroyed: u64,
    pub padding_recv: u64,
    pub padding_sent: u64,
    pub drops_sent: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct HopLink {
    pub cid: u32,
    pub peer: SocketAddr,
}

pub enum CircuitEntry {
    Origin {
        fwd: Vec<[u8; 32]>,
        bwd: Vec<[u8; 32]>,
        tag: [u8; 16],
        next: HopLink,
        streams: HashMap<u16, mpsc::Sender<Vec<u8>>>,
    },
    Relay {
        tag: [u8; 16],
        k_fwd: [u8; 32],
        k_bwd: [u8; 32],
        prev: HopLink,
        next: HopLink,
        last_fwd: u32,
    },
    Terminal {
        tag: [u8; 16],
        k_fwd: [u8; 32],
        k_bwd: [u8; 32],
        prev: HopLink,
        last_fwd: u32,
    },
}

pub struct Node {
    pub config: NodeConfig,
    pub identity: NodeIdentity,
    pub node_id: NodeId,
    pub own_desc: Descriptor,
    pub dht: Arc<nbf_dht::Kademlia>,
    pub link: Link,
    pub circuits: Mutex<HashMap<u32, CircuitEntry>>,
    pub pending: Mutex<HashMap<u32, oneshot::Sender<Result<(), NetError>>>>,
    pub routing: Mutex<HashMap<NodeId, (SocketAddr, [u8; 32])>>,
    pub next_cid: AtomicU32,
    pub seq_origin: AtomicU32,
    pub stats: Mutex<Stats>,
    pub dht_cache: Mutex<HashMap<NodeId, Descriptor>>,
    pub create_frags: Mutex<HashMap<u32, FragBuf>>,
    pub rng: Mutex<StdRng>,
}

impl Node {
    pub async fn spawn(config: NodeConfig) -> Arc<Node> {
        let mut rng = StdRng::seed_from_u64(config.rng_seed.unwrap_or(0x1234_5678));
        let identity = NodeIdentity::random(&mut rng);
        let node_id = identity.node_id();
        let cell_addr: SocketAddr = format!("127.0.0.1:{}", config.cell_port).parse().unwrap();
        let own_desc = Descriptor::sign(&identity, cell_addr, config.dht_port, now_unix());
        let dht = Arc::new(
            nbf_dht::Kademlia::new(node_id, own_desc.clone(), config.dht_port)
                .expect("bind DHT port"),
        );

        let link = Link::bind(cell_addr, &identity.link_priv).await.expect("bind cell port");
        let rx = link.subscribe().expect("subscribe 1 lần duy nhất");

        let node = Arc::new(Node {
            config,
            identity,
            node_id,
            own_desc: own_desc.clone(),
            dht,
            link,
            circuits: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            routing: Mutex::new(HashMap::new()),
            next_cid: AtomicU32::new(1),
            seq_origin: AtomicU32::new(1),
            stats: Mutex::new(Stats::default()),
            dht_cache: Mutex::new(HashMap::new()),
            create_frags: Mutex::new(HashMap::new()),
            rng: Mutex::new(rng),
        });

        // store_self cục bộ (để lookup về mình không cần DHT):
        node.dht.store.write().await.insert(node_id, own_desc);

        // Kết nối DHT với seed:
        let seeds: Vec<SocketAddr> = node
            .config
            .seeds
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let dht = node.dht.clone();
        tokio::spawn(async move {
            dht.bootstrap(&seeds).await;
            dht.store_self(&seeds).await;
        });

        // Vòng nhận cell:
        let n = node.clone();
        tokio::spawn(async move {
            let mut rx = rx;
            loop {
                if let Some((from, msg)) = rx.recv().await {
                    match msg {
                        WireMsg::Cell(cell) => {
                            let n2 = n.clone();
                            tokio::spawn(async move { n2.handle_cell(from, cell).await });
                        }
                        WireMsg::Handshake(..) => {}
                    }
                }
            }
        });

        // Cover loop (nếu bật):
        if node.config.cover.on {
            let n2 = node.clone();
            tokio::spawn(async move { crate::cover::run_loop(n2).await });
        }

        node
    }

    pub fn new_cid(&self) -> u32 {
        self.next_cid.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn handle_cell(self: Arc<Self>, from: SocketAddr, cell: Cell) {
        match cell.cmd {
            Cmd::Create => self.handle_create(from, cell).await,
            Cmd::Created => self.handle_created(from, cell).await,
            Cmd::Destroy => self.handle_destroy(from, cell).await,
            Cmd::Relay => self.handle_relay(from, cell).await,
            Cmd::Padding => {
                self.stats.lock().await.padding_recv += 1;
            }
        }
    }

    async fn handle_create(self: Arc<Self>, from: SocketAddr, cell: Cell) {
        let (total, idx, chunk) = match parse_frag(&cell.payload) {
            Ok(t) => t,
            Err(_) => return,
        };
        // Gom mảnh:
        let mut map = self.create_frags.lock().await;
        let full = reassemble(cell.cid, idx, total, chunk, &mut map);
        drop(map);
        let header = match full {
            Some(h) => h,
            None => return, // chờ thêm mảnh
        };
        let outcome = match process_header(&self.identity, &header) {
            Ok(o) => o,
            Err(_) => return, // header sai → bỏ (không phản hồi, tránh oracle)
        };
        match outcome {
            ProcessOutcome::Terminal { tag, k_fwd, k_bwd } => {
                self.circuits.lock().await.insert(
                    cell.cid,
                    CircuitEntry::Terminal {
                        tag,
                        k_fwd,
                        k_bwd,
                        prev: HopLink { cid: cell.cid, peer: from },
                        last_fwd: 0,
                    },
                );
                self.stats.lock().await.created += 1;
                // Phản hồi CREATED về prev:
                let c = Cell { cid: cell.cid, cmd: Cmd::Created, flags: 0, payload: vec![] };
                let _ = self.link.send_cell(from, &c).await;
            }
            ProcessOutcome::Relay { tag, k_fwd, k_bwd, next_addr, new_header, .. } => {
                let ncid = self.new_cid();
                self.circuits.lock().await.insert(
                    cell.cid,
                    CircuitEntry::Relay {
                        tag,
                        k_fwd,
                        k_bwd,
                        prev: HopLink { cid: cell.cid, peer: from },
                        next: HopLink { cid: ncid, peer: next_addr },
                        last_fwd: 0,
                    },
                );
                self.stats.lock().await.created += 1;
                // Forward header đã mù hóa tới next:
                let payload = new_header;
                for frag in fragment(&payload) {
                    let c = Cell { cid: ncid, cmd: Cmd::Create, flags: 0, payload: frag };
                    let _ = self.link.send_cell(next_addr, &c).await;
                }
            }
        }
    }

    async fn handle_created(self: Arc<Self>, _from: SocketAddr, cell: Cell) {
        // CREATED từ next (khi mình là relay) hoặc từ hop1 (khi mình là origin).
        // Origin: đánh thức pending.
        if let Some(tx) = self.pending.lock().await.remove(&cell.cid) {
            let _ = tx.send(Ok(()));
            return;
        }
        // Relay: chuyển CREATED về prev của circuit.
        let entry = self.circuits.lock().await.get(&cell.cid).map(|e| e.cloned_entry());
        if let Some(CircuitEntry::Relay { prev, .. }) = entry {
            let c = Cell { cid: prev.cid, cmd: Cmd::Created, flags: 0, payload: vec![] };
            let _ = self.link.send_cell(prev.peer, &c).await;
        }
    }

    async fn handle_destroy(self: Arc<Self>, _from: SocketAddr, cell: Cell) {
        // Hủy circuit ở mình; nếu là Relay/Terminal, chuyển tiếp DESTROY về prev.
        let entry = self.circuits.lock().await.remove(&cell.cid);
        self.stats.lock().await.destroyed += 1;
        if let Some(CircuitEntry::Relay { prev, next, .. }) = entry {
            let c = Cell { cid: prev.cid, cmd: Cmd::Destroy, flags: 0, payload: vec![] };
            let _ = self.link.send_cell(prev.peer, &c).await;
            let _ = next;
        } else if let Some(CircuitEntry::Terminal { prev, .. }) = entry {
            let c = Cell { cid: prev.cid, cmd: Cmd::Destroy, flags: 0, payload: vec![] };
            let _ = self.link.send_cell(prev.peer, &c).await;
        }
    }

    /// (Phần RELAY — Task 10 điền đầy đủ.) Khai báo để handle_cell biên dịch:
    async fn handle_relay(self: Arc<Self>, from: SocketAddr, cell: Cell) {
        crate::relay::handle(self, from, cell).await;
    }

    /// Đăng ký stream nhận dữ liệu chiều về (origin side).
    pub async fn register_stream(&self, cid: u32, stream: u16, tx: mpsc::Sender<Vec<u8>>) {
        if let Some(CircuitEntry::Origin { streams, .. }) =
            self.circuits.lock().await.get_mut(&cid)
        {
            streams.insert(stream, tx);
        }
    }

    /// Mở stream mới — trả Receiver để chờ dữ liệu về.
    pub async fn open_stream(&self, cid: u32, stream: u16) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(16);
        self.register_stream(cid, stream, tx).await;
        rx
    }

    /// Đăng ký khóa link của peer (để session Noise sau này).
    pub async fn ensure_peer_link(&self, addr: SocketAddr, link_pub: [u8; 32]) {
        self.link.set_peer_static_async(addr, link_pub).await;
    }

    /// Danh sách node biết được (rt ∩ store) kèm addr cell + link pub.
    pub async fn route_peers(&self) -> Vec<(NodeId, SocketAddr, [u8; 32])> {
        let rt = self.dht.rt.read().await.clone();
        let store = self.dht.store.read().await.clone();
        let mut out = Vec::new();
        for c in &rt {
            if let Some(d) = store.get(&c.node_id) {
                out.push((c.node_id, d.cell_addr, d.link_pub));
            }
        }
        out
    }

    /// Tìm descriptor của 1 node (cache trước, rồi DHT value lookup).
    pub async fn lookup_route(&self, target: NodeId) -> Result<Descriptor, NetError> {
        if let Some(d) = self.dht_cache.lock().await.get(&target) {
            return Ok(d.clone());
        }
        if let Some(d) = self.dht.store.read().await.get(&target) {
            self.dht_cache.lock().await.insert(target, d.clone());
            return Ok(d.clone());
        }
        match self.dht.lookup(&target, true).await {
            Ok(Some(d)) => {
                self.dht_cache.lock().await.insert(target, d.clone());
                Ok(d)
            }
            _ => Err(NetError::Timeout),
        }
    }
}

impl Clone for CircuitEntry {
    fn clone(&self) -> Self {
        // Circuits chứa mpsc Sender — Origin cần clone thủ công (Sender clone được).
        match self {
            CircuitEntry::Origin { fwd, bwd, tag, next, streams } => CircuitEntry::Origin {
                fwd: fwd.clone(),
                bwd: bwd.clone(),
                tag: *tag,
                next: *next,
                streams: streams.clone(),
            },
            CircuitEntry::Relay { tag, k_fwd, k_bwd, prev, next, last_fwd } => CircuitEntry::Relay {
                tag: *tag,
                k_fwd: *k_fwd,
                k_bwd: *k_bwd,
                prev: *prev,
                next: *next,
                last_fwd: *last_fwd,
            },
            CircuitEntry::Terminal { tag, k_fwd, k_bwd, prev, last_fwd } => CircuitEntry::Terminal {
                tag: *tag,
                k_fwd: *k_fwd,
                k_bwd: *k_bwd,
                prev: *prev,
                last_fwd: *last_fwd,
            },
        }
    }
}

impl CircuitEntry {
    /// Helper: clone entry từ lock (tránh giữ guard qua await).
    pub fn cloned_entry(&self) -> CircuitEntry {
        self.clone()
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
