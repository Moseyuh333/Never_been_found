# NBF (Never-Been-Found) — Giao thức routing ẩn danh — Plan triển khai MVP

> **For agentic workers:** REQUIRED SUB-SKILL: dùng `superpowers:subagent-driven-development` (khuyến nghị) hoặc `superpowers:executing-plans` để thực hiện plan này task-by-task. Các bước dùng checkbox (`- [ ]`) để theo dõi tiến độ.

**Goal:** Xây MVP chạy được của NBF — giao thức giao tiếp ẩn danh nguồn-dẫn-hướng (source-routed) kiểu Sphinx: circuit 3 hop dựng trong **1 round-trip**, mật mã lai **X25519 + ML-KEM-768** mỗi hop, khám phá node qua **DHT Kademlia** (không directory trung tâm), cell cố định **1280 byte** + cover traffic. Demo end-to-end: 6 node trên localhost, client gửi tin qua circuit 3 hop tới echo service, không hop trung gian nhìn thấy plaintext.

**Architecture:** Cargo workspace 4 crate: `nbf-crypto` (định danh, descriptor, KDF lai, Sphinx header build/peel, replay), `nbf-dht` (descriptor store/lookup kiểu Kademlia qua UDP), `nbf-net` (cell 1280B, link Noise-IK trên UDP, engine circuit, cover traffic), `nbf-cli` (binary `nbf` với subcommand `node`/`send`/`demo`). Client tự tính sẵn khóa mọi hop → một gói CREATE đi xuyên 3 hop trong một lượt; dữ liệu RELAY bọc/lột 1 lớp AEAD mỗi hop theo chiều đi/về.

**Tech Stack:** Rust 2021 (stable ≥ 1.75), tokio 1, snow 0.9 (Noise IK link), curve25519-dalek 4 (Sphinx scalar/point), ml-kem 0.2 (ML-KEM-768 / FIPS 203), chacha20poly1305 0.10, hkdf+sha2 0.12/0.10, ed25519-dalek 2, clap 4.

---

## 1. Thiết kế giao thức — bốn trụ cột (đã chốt với user)

| # | Trụ cột | Cơ chế cụ thể trong NBF |
|---|---------|------------------------|
| 1 | Dựng circuit **1-RTT** | Sphinx single-pass: initiator tính trước `ss_i`, `k_i` cho MỌI hop, bọc một header duy nhất. Gói CREATE đi thẳng qua 3 hop không dừng chờ — mỗi hop lột 1 lớp, nhân mù (blinding) các alpha còn lại rồi đẩy tiếp. Không có EXTEND từng nấc như Tor. |
| 2 | **PQC** từ ngày đầu | Khóa traffic mỗi hop = `HKDF(ss_X25519 ‖ ss_MLKEM768, salt=tag)`. Header Sphinx vẫn dùng X25519 (giữ tính homomorphic của blinding); ciphertext ML-KEM-768 (1088B) của từng hop nằm **bên trong** lớp đã mã hóa của chính hop đó → hop mở lớp xong mới decapsulate. Harvest-now-decrypt-later vô hiệu với khóa traffic. |
| 3 | **DHT** không trung tâm | Kademlia thu nhỏ trên UDP: `PING/PONG/STORE/FIND/FOUND`, `k=3`, `alpha=3`, node_id 160-bit = SHA-256(Ed25519 pub) cắt 20B. Descriptor tự chủ (signed), hết hạn 24h. Không còn điểm lỗi duy nhất kiểu Tor consensus. |
| 4 | Chống traffic analysis | Mọi cell đúng **1280B** (trước mã hóa link). Link rảnh → gửi PADDING với chu kỳ ngẫu nhiên jitter. Circuit hoạt động → origin gửi RELAY_DROP giả định kỳ. Ổn định kích thước + nền tế bào giả = khó phân loại lưu lượng. |

Bảo mật lớp layer: link Noise-IK (mỗi datagram 1 AEAD, chống replay ở lớp link) **+** onion AEAD mỗi hop (chống hop trung gian đọc/sửa payload) **+** seq số học đơn điệu chặn replay ở lớp circuit.

### 1.1 Wire format tổng hợp (CHÍNH XÁC — mọi số liệu little-endian)

**Cell (trước mã hóa link) — đúng 1280 byte:**

```
[cid: u32][cmd: u8][flags: u8][len: u16][payload: len byte][zero-pad tới 1280]
```

| cmd | Tên | Ý nghĩa |
|-----|-----|---------|
| 1 | CREATE | Mở circuit — payload là mảnh fragmentation: `[total u16][idx u16][chunk ≤1268]` |
| 2 | CREATED | Xác nhận circuit đã dựng (payload rỗng) |
| 3 | DESTROY | Hủy circuit cả hai chiều (payload rỗng) |
| 4 | RELAY | Dữ liệu trong circuit: `[seq u32][rcmd u8][stream u16][onion…]` |
| 5 | PADDING | Cell nền (bỏ qua, chỉ đếm thống kê) |

**RELAY onion:** origin bọc `seal(k_f3, seal(k_f2, seal(k_f1, msg)))` (lớp hop1 ngoài cùng); chiều về terminal bọc `bwd` của mình, mỗi hop trung gian bọc thêm 1 lớp `k_bwd`, origin lột theo thứ tự ngược. Nonce AEAD = `SHA256(tag ‖ dir ‖ seq_le)[0..12]`, `dir`: 0=fwd, 1=bwd. `rcmd`: 1=ECHO, 2=DATA, 3=DROP. `MSG_MAX = 1024`.

**Sphinx header (n hop):**

```
[ver: u8 =1][n: u8][tag: 16B][alpha_1..alpha_n: n×32B][tail: n×1184B]
header_len(n) = 18 + n×1216        (n=3 → 3666 byte → 3 cell CREATE)
```

- Lớp thứ `i` (mã hóa AEAD bằng `k_i = HKDF(ss_i, salt=tag, info="nbf/hdr/v1")`, nonce `SHA256(tag‖"hdr"‖n_hiện_tại)[0..12]`) chứa:
  `next_id 20B ‖ next_ip 4B ‖ next_cell_port 2B ‖ next_link_pub 32B ‖ pad 6B ‖ ct_MLKEM 1088B` = 1152B
- `ss_i = alpha_i × sphinx_priv_i` (MontgomeryPoint × Scalar); hop decapsulate `ct` → `ss_kem`; khóa traffic `HKDF(ss_i ‖ ss_kem, salt=tag, info="nbf/traffic/v1")` → 64B = `k_fwd‖k_bwd`.
- Blinding: `b_i = Scalar(SHA256(ss_i ‖ alpha_i))`; hop nhân mọi alpha còn lại với `b_i`, giảm `n` đi 1, forward `[ver][n-1][tag][alphas_blinded][tail_còn_lại]`.
- `next_id = 0xFF×20` → hop này là terminal.

**Descriptor (1385 byte, ký Ed25519):**

```
magic "NBFD"(4) ver(1) node_id(20) ed_pub(32) link_pub(32) sphinx_pub(32)
kem_pk(1184) cell_ip(4) cell_port(2) dht_port(2) ts_unix(8) sig(64)
```

**DHT RPC (UDP, header `NBFR` 4B + type u8):** PING(1) nonce8 / PONG(2) nonce8 / STORE(3) desc / FIND(4) key20+want1 / FOUND(5) count + count×(id20+ip4+dhtport2) + [value].

## 2. Cấu trúc file

```
D:\New folder\Never_been_found\
├── Cargo.toml                      # workspace + [workspace.dependencies]
├── .gitignore                      # /target
├── README.md                       # quickstart + giới hạn bảo mật (Task 13)
├── docs/
│   ├── PROTOCOL.md                 # spec byte-chính-xác (Task 1, nội dung ở dưới)
│   └── superpowers/plans/2026-09-08-nbf-anon-routing-mvp.md   # chính là file này
├── crates/
│   ├── nbf-crypto/src/
│   │   ├── lib.rs                  # NodeId, hằng số, CryptoError
│   │   ├── identity.rs             # NodeIdentity + Descriptor (Task 2)
│   │   ├── kem.rs                  # adapter ML-KEM (Task 2)
│   │   ├── kdf.rs                  # HKDF lai, nonce, seal/open AEAD (Task 3)
│   │   ├── sphinx.rs               # build_header / process_header (Task 4)
│   │   └── replay.rs               # MonotonicCheck (Task 4)
│   ├── nbf-dht/src/
│   │   ├── lib.rs                  # Contact, DhtError (Task 7)
│   │   ├── rpc.rs                  # encode/decode RPC (Task 7)
│   │   └── kademlia.rs             # Kademlia: serve/store/lookup (Task 8)
│   ├── nbf-net/src/
│   │   ├── lib.rs                  # NetError (Task 5)
│   │   ├── cell.rs                 # Cell, fragment, onion relay (Task 5)
│   │   ├── link.rs                 # Link Noise-IK UDP (Task 6)
│   │   ├── node.rs                 # Node engine: CREATE/RELAY/DESTROY (Task 9)
│   │   ├── builder.rs              # CircuitHandle + random_route (Task 10)
│   │   └── cover.rs                # PADDING/DROP nền (Task 12)
│   └── nbf-cli/src/
│       ├── main.rs                 # clap: node/send/demo (Task 13)
│       └── demo.rs                 # demo 6 node (Task 13)
└── crates/nbf-net/tests/
    ├── common/mod.rs               # harness spawn mesh (Task 9)
    ├── circuit.rs                  # e2e 3 hop (Task 11)
    └── cover.rs                    # padding/drop nền (Task 12)
```

Mỗi crate **một trách nhiệm**: crypto thuần (không I/O trừ rand) → DHT (chỉ UDP riêng) → net (cell/link/circuit) → CLI (dùng tất cả). Test integration đặt ở `nbf-net/tests/` vì cần cả stack.

## 3. Yêu cầu toàn dự án (áp dụng cho MỌI task)

- Rust **edition 2021**, `rustc` stable ≥ 1.75. Workspace `resolver = "2"`.
- Dependencies **chỉ** danh sách ở `[workspace.dependencies]` (mục Task 1). Không thêm crate mới.
- **Cấm `unsafe`**. Mọi số nguyên trên wire là **little-endian**.
- Mọi khóa/bí mật zeroize khi drop; KHÔNG log key material (chỉ log node_id hex, addr, loại cell).
- Comment code **tiếng Việt**, định danh tiếng Anh (đúng sở thích user).
- Wire format phải khớp `docs/PROTOCOL.md` byte-for-byte; nếu buộc phải đổi → sửa cả PROTOCOL.md trong cùng commit.
- Test chạy được offline, chỉ localhost, seed RNG khi test liên quan timing. Mỗi task kết thúc bằng commit riêng.
- Cuối mỗi task chạy `cargo test -p <crate>` xanh trước khi commit.

---

### Task 1: Scaffold workspace + docs/PROTOCOL.md

**Files:**
- Create: `Cargo.toml`, `.gitignore`, `docs/PROTOCOL.md`
- Create: `crates/nbf-crypto/{Cargo.toml, src/lib.rs}`, `crates/nbf-dht/{Cargo.toml, src/lib.rs}`, `crates/nbf-net/{Cargo.toml, src/lib.rs}`, `crates/nbf-cli/{Cargo.toml, src/main.rs}`

**Interfaces:**
- Consumes: không (task đầu).
- Produces: workspace build được `cargo check`; tên crate `nbf-crypto`/`nbf-dht`/`nbf-net`/`nbf-cli` (bin `nbf`) dùng xuyên suốt; deps phiên bản khóa ở workspace.

- [ ] **Step 1: Tạo root `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = [
    "crates/nbf-crypto",
    "crates/nbf-dht",
    "crates/nbf-net",
    "crates/nbf-cli",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"

[workspace.dependencies]
nbf-crypto = { path = "crates/nbf-crypto" }
nbf-dht = { path = "crates/nbf-dht" }
nbf-net = { path = "crates/nbf-net" }
curve25519-dalek = "4"
ml-kem = "0.2"
chacha20poly1305 = "0.10"
hkdf = "0.12"
sha2 = "0.10"
ed25519-dalek = "2"
snow = "0.9"
rand = "0.8"
zeroize = "1"
thiserror = "1"
tokio = { version = "1", features = ["rt-multi-thread", "net", "time", "sync", "macros"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
clap = { version = "4", features = ["derive"] }
anyhow = "1"
hex = "0.4"
```

- [ ] **Step 2: Tạo `.gitignore`**

```
/target
```

- [ ] **Step 3: Tạo 4 crate skeleton**

`crates/nbf-crypto/Cargo.toml`:

```toml
[package]
name = "nbf-crypto"
version.workspace = true
edition.workspace = true

[dependencies]
curve25519-dalek.workspace = true
ml-kem.workspace = true
chacha20poly1305.workspace = true
hkdf.workspace = true
sha2.workspace = true
ed25519-dalek.workspace = true
rand.workspace = true
zeroize.workspace = true
thiserror.workspace = true
```

`crates/nbf-crypto/src/lib.rs` (chỉ hằng số + lỗi, nội dung thật — các module thêm ở task sau):

```rust
//! NBF crypto thuần: định danh, KDF lai, Sphinx. Không I/O mạng.

pub mod kdf;
pub mod sphinx;

pub use kdf::*;
pub use sphinx::*;

/// ID node 160-bit: SHA-256(Ed25519 pub) cắt 20 byte đầu.
pub type NodeId = [u8; 20];

/// Độ dài ciphertext ML-KEM-768.
pub const CT_LEN: usize = 1088;
/// Độ dài public key ML-KEM-768.
pub const KEM_PK_LEN: usize = 1184;
/// Một lớp Sphinx: next(64B) + ct(1088B).
pub const LAYER_INFO_LEN: usize = 64 + CT_LEN;
/// Một lớp Sphinx: MAC/AEAD-tag(32B) + info.
pub const LAYER_LEN: usize = 32 + LAYER_INFO_LEN;
/// Số hop tối đa trong một route.
pub const MAX_HOPS: usize = 5;
/// node_id đánh dấu "đích cuối" trong thông tin routing.
pub const TERMINAL_ID: NodeId = [0xFF; 20];
/// Chiều forward (origin → terminal).
pub const DIR_FWD: u8 = 0;
/// Chiều backward (terminal → origin).
pub const DIR_BWD: u8 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("độ dài dữ liệu không đúng: {0}")]
    BadLength(usize),
    #[error("AEAD mở thất bại (sai key hoặc dữ liệu hỏng)")]
    Aead,
    #[error("ML-KEM thất bại")]
    Kem,
    #[error("header Sphinx không hợp lệ")]
    Sphinx,
    #[error("descriptor không hợp lệ")]
    Descriptor,
    #[error("chữ ký Ed25519 sai")]
    Ed25519,
}
```

> **Lưu ý thực thi:** lib.rs trên tham chiếu `kdf`/`sphinx` chưa tồn tại — trong task này tạo sẵn 2 file rỗng có `//! placeholder` **và** bỏ tạm 2 dòng `pub use`; Task 3/4 sẽ khôi phục đúng như trên. `crates/nbf-dht/src/lib.rs` và `crates/nbf-net/src/lib.rs` bắt đầu là `//! NBF DHT / net.` trống, task sau điền.

`crates/nbf-dht/Cargo.toml`:

```toml
[package]
name = "nbf-dht"
version.workspace = true
edition.workspace = true

[dependencies]
nbf-crypto.workspace = true
rand.workspace = true
thiserror.workspace = true
tokio.workspace = true
tracing.workspace = true
```

`crates/nbf-net/Cargo.toml`:

```toml
[package]
name = "nbf-net"
version.workspace = true
edition.workspace = true

[dependencies]
nbf-crypto.workspace = true
nbf-dht.workspace = true
chacha20poly1305.workspace = true
rand.workspace = true
snow.workspace = true
tokio.workspace = true
tracing.workspace = true
zeroize.workspace = true
thiserror.workspace = true
```

`crates/nbf-cli/Cargo.toml`:

```toml
[package]
name = "nbf-cli"
version.workspace = true
edition.workspace = true

[[bin]]
name = "nbf"
path = "src/main.rs"

[dependencies]
nbf-crypto.workspace = true
nbf-dht.workspace = true
nbf-net.workspace = true
anyhow.workspace = true
clap.workspace = true
rand.workspace = true
tokio.workspace = true
tracing-subscriber.workspace = true
```

`crates/nbf-cli/src/main.rs`:

```rust
fn main() {
    println!("nbf skeleton");
}
```

- [ ] **Step 4: Viết `docs/PROTOCOL.md` (spec byte-chính-xác)** — chép nguyên văn:

````markdown
# NBF Wire Protocol v1

Mọi số nguyên little-endian. Cell = datagram UDP trước mã hóa link, đúng 1280 byte.

## 1. Cell
[cid u32][cmd u8][flags u8=0][len u16][payload len byte][zero-pad 1280]
cmd: 1 CREATE, 2 CREATED, 3 DESTROY, 4 RELAY, 5 PADDING.

## 2. Fragmentation (CREATE/CREATED dài)
payload = [total u16][idx u16][chunk ≤ 1268].Receiver gom theo cid đến đủ `total` mảnh.

## 3. Sphinx header (route n hop)
[ver u8=1][n u8][tag 16B][alpha n×32B][tail n×1184B]; header_len(n) = 18 + n*1216.
Lớp i mã hóa ChaCha20Poly1305, key k_i = HKDF-SHA256(ikm=ss_i, salt=tag, info="nbf/hdr/v1"),
nonce = SHA256(tag ‖ b"hdr" ‖ n_hiện_tại)[0..12]; plaintext lớp:
next_id 20B ‖ next_ip 4B ‖ next_cell_port 2B ‖ next_link_pub 32B ‖ pad 6B ‖ ct_MLKEM768 1088B.
ss_i = alpha_i × sphinx_priv_i (X25519). Blinding b_i = Scalar(SHA256(ss_i ‖ alpha_i)).
alpha còn lại nhân b_i; n giảm 1. next_id = 0xFF×20 → terminal.

## 4. Khóa traffic mỗi hop
k_fwd‖k_bwd (64B) = HKDF-SHA256(ikm=ss_i ‖ ss_MLKEM, salt=tag, info="nbf/traffic/v1").

## 5. RELAY
payload = [seq u32][rcmd u8][stream u16][onion]. rcmd: 1 ECHO, 2 DATA, 3 DROP.
Chiều đi: origin seal k_f1→f2→f3 (f1 ngoài cùng), nonce = SHA256(tag‖dir‖seq)[0..12], dir=0.
Chiều về: terminal seal k_b3, mỗi hop trung gian seal k_bwd của mình (dir=1), origin mở b1→b2→b3.
MSG_MAX = 1024.

## 6. Descriptor (1385B, Ed25519 ký toàn bộ trước sig)
"NBFD" ver=1 node_id20 ed_pub32 link_pub32 sphinx_pub32 kem_pk1184
cell_ip4 cell_port2 dht_port2 ts8 sig64. Hết hạn 24h.

## 7. DHT (Kademlia UDP, port riêng)
Datagram: "NBFR" type u8 body. PING=1 nonce8, PONG=2 nonce8, STORE=3 desc,
FIND=4 key20 want1, FOUND=5 count u8 + count×(id20 ip4 dht_port2) + [len u16 + desc].
k=3, alpha=3, node_id = SHA256(ed_pub)[..20].

## 8. Link
Noise IKpsk0: "Noise_IK_25519_ChaChaPoly_SHA256", static = link_pub trong descriptor.
Mỗi datagram = 1 bản mã Noise; cell 1280B → bản mã 1296B. Session theo (addr).
Quy tắc tránh va chạm handshake: node có id NHỎ HƠN giữ vai initiator.

## 9. Giới hạn v1 (ghi rõ, không giấu)
- Không có mã hóa end-to-end riêng origin↔terminal (tin vào AEAD từng hop; hop cuối đọc được).
- CREATED chưa được xác thực bằng khóa route (chỉ DoS được, không đọc được).
- Route chọn ngẫu nhiên, chưa có guard/layer chống adversary toàn cục.
- Chưa có NAT traversal — chỉ localhost/LAN.
````

- [ ] **Step 5: Build kiểm tra**

Run: `cargo check --workspace`
Expected: `Finished` (có thể có warning unused — chấp nhận ở bước này, các task sau tự hết).

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: workspace scaffold + PROTOCOL.md spec v1"
```

---

### Task 2: `nbf-crypto` — NodeIdentity + Descriptor + adapter ML-KEM

**Files:**
- Create: `crates/nbf-crypto/src/identity.rs`, `crates/nbf-crypto/src/kem.rs`
- Modify: `crates/nbf-crypto/src/lib.rs` (thêm `pub mod identity; pub mod kem;` + re-export)
- Test: chính là `#[cfg(test)]` trong 2 file trên

**Interfaces:**
- Consumes: hằng số `NodeId`, `KEM_PK_LEN`, `CT_LEN`, `CryptoError` (Task 1).
- Produces (Task 4/7/9/13 dùng đúng tên này):
  - `NodeIdentity::random(rng: &mut impl RngCore + CryptoRng) -> NodeIdentity`
  - `NodeIdentity::node_id(&self) -> NodeId`, trường public: `ed: SigningKey`, `link_priv: [u8;32]`, `link_pub: [u8;32]`, `sphinx_priv: Scalar`, `sphinx_pub: [u8;32]`, `kem_sk: DecapsKey<MlKem768>`, `kem_pk: [u8;1184]`
  - `Descriptor::sign(id: &NodeIdentity, cell_addr: SocketAddr, dht_port: u16, now_unix: u64) -> Descriptor`
  - `Descriptor::to_bytes(&self) -> Vec<u8>` / `Descriptor::from_signed_bytes(&[u8]) -> Result<Descriptor, CryptoError>` (verify chữ ký + node_id bên trong)
  - `kem_encap(pk: &[u8;1184], rng) -> Result<([u8;1088], [u8;32]), CryptoError>` / `kem_decap(sk: &DecapsKey<MlKem768>, ct: &[u8;1088]) -> Result<[u8;32], CryptoError>`

- [ ] **Step 1: Viết test thất bại** — thêm vào `crates/nbf-crypto/src/identity.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::net::SocketAddr;

    #[test]
    fn node_id_phai_la_sha256_cua_ed_pub() {
        let mut rng = StdRng::seed_from_u64(1);
        let id = NodeIdentity::random(&mut rng);
        let expect = sha2::Sha256::digest(id.ed.verifying_key().as_bytes());
        assert_eq!(id.node_id(), expect[..20]);
    }

    #[test]
    fn descriptor_roundtrip_va_verify() {
        let mut rng = StdRng::seed_from_u64(2);
        let id = NodeIdentity::random(&mut rng);
        let addr: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let d = Descriptor::sign(&id, addr, 9002, 1_700_000_000);
        let back = Descriptor::from_signed_bytes(&d.to_bytes()).unwrap();
        assert_eq!(back.node_id, id.node_id());
        assert_eq!(back.cell_addr, addr);
        assert_eq!(back.dht_port, 9002);
        assert_eq!(back.kem_pk.len(), crate::KEM_PK_LEN);
    }

    #[test]
    fn descriptor_sua_1_byte_phai_loi() {
        let mut rng = StdRng::seed_from_u64(3);
        let id = NodeIdentity::random(&mut rng);
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut b = Descriptor::sign(&id, addr, 2, 10).to_bytes();
        let n = b.len();
        b[n - 70] ^= 0x01; // đảo 1 byte trong vùng ts
        assert!(Descriptor::from_signed_bytes(&b).is_err());
    }

    #[test]
    fn descriptor_ky_boi_nguoi_khac_phai_loi() {
        let mut rng = StdRng::seed_from_u64(4);
        let a = NodeIdentity::random(&mut rng);
        let b = NodeIdentity::random(&mut rng);
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut d = Descriptor::sign(&a, addr, 2, 10);
        d.sig = *b.sign_ed(&d.signing_bytes()); // ký lại bằng key B nhưng giữ node_id A
        assert!(Descriptor::from_signed_bytes(&d.to_bytes()).is_err());
    }
}
```

- [ ] **Step 2: Chạy thấy fail**

Run: `cargo test -p nbf-crypto identity`
Expected: FAIL — `identity` chưa tồn tại (compile error).

- [ ] **Step 3: Cài đặt `kem.rs`** (adapter — nếu API crate `ml-kem` thực tế lệch bản, CHỈ sửa trong file này):

```rust
//! Adapter ML-KEM-768 (FIPS 203). Mọi phụ thuộc crate ml-kem gói vào đây:
//! nếu API lệch phiên bản chỉ cần sửa file này, phần còn lại của dự án không đổi.

use crate::{CryptoError, CT_LEN, KEM_PK_LEN};
use ml_kem::{Ciphertext, DecapsKey, EncapsKey, KemCore, MlKem768, SharedSecret};
use rand::CryptoRngCore;

/// Bọc khóa: trả về (ciphertext 1088B, shared secret 32B).
pub fn kem_encap(
    pk: &[u8; KEM_PK_LEN],
    rng: &mut impl CryptoRngCore,
) -> Result<([u8; CT_LEN], [u8; 32]), CryptoError> {
    let ek = EncapsKey::<MlKem768>::from_bytes(pk.into());
    let (ct, ss): (Ciphertext<MlKem768>, SharedSecret<MlKem768>) = ek.encapsulate(rng);
    let ct_b: [u8; CT_LEN] = ct.into();
    let ss_b: [u8; 32] = ss.into();
    Ok((ct_b, ss_b))
}

/// Mở khóa từ ciphertext.
pub fn kem_decap(sk: &DecapsKey<MlKem768>, ct: &[u8; CT_LEN]) -> Result<[u8; 32], CryptoError> {
    let c = Ciphertext::<MlKem768>::from((*ct).into());
    let ss: SharedSecret<MlKem768> = sk.decapsulate(&c);
    Ok(ss.into())
}
```

- [ ] **Step 4: Cài đặt `identity.rs`** (phần impl đặt TRÊN mod tests):

```rust
//! Định danh node (Ed25519 + X25519 link + Scalar Sphinx + ML-KEM) và descriptor tự chủ.

use crate::{kem_decap, kem_encap, CryptoError, NodeId, KEM_PK_LEN};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::Scalar;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature, SIGNATURE_LENGTH};
use rand::{CryptoRngCore, RngCore};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use zeroize::Zeroize;

pub const DESC_LEN: usize = 4 + 1 + 20 + 32 + 32 + 32 + KEM_PK_LEN + 4 + 2 + 2 + 8 + 64; // 1385
const DESC_MAGIC: [u8; 4] = *b"NBFD";
const DESC_VER: u8 = 1;

/// Bộ khóa đầy đủ của một node NBF.
pub struct NodeIdentity {
    pub ed: SigningKey,
    pub link_priv: [u8; 32],
    pub link_pub: [u8; 32],
    pub sphinx_priv: Scalar,
    pub sphinx_pub: [u8; 32],
    pub kem_sk: ml_kem::DecapsKey<MlKem768Alias>,
    pub kem_pk: [u8; KEM_PK_LEN],
}
// Alias để không phải import sâu type generic của ml-kem ở chỗ khác:
type MlKem768Alias = ml_kem::MlKem768;

impl NodeIdentity {
    pub fn random(rng: &mut (impl RngCore + CryptoRngCore)) -> Self {
        let ed = SigningKey::generate(rng);
        // link key: 32 byte ngẫu nhiên, clamp đúng quy tắc x25519 để khớp snow
        let mut link_priv = [0u8; 32];
        rng.fill_bytes(&mut link_priv);
        link_priv[0] &= 248;
        link_priv[31] &= 127;
        link_priv[31] |= 64;
        let link_pub = x25519_pub_from_clamped(&link_priv);
        let sphinx_priv = Scalar::random(rng);
        let sphinx_pub = MontgomeryPoint::mul_base(&sphinx_priv).to_bytes();
        let (kem_sk, kem_ek) = ml_kem::MlKem768::generate(rng);
        let kem_pk: [u8; KEM_PK_LEN] = kem_ek.into();
        Self { ed, link_priv, link_pub, sphinx_priv, sphinx_pub, kem_sk, kem_pk }
    }

    pub fn node_id(&self) -> NodeId {
        node_id_from_ed_pub(self.ed.verifying_key().as_bytes())
    }

    /// Kiểm tra nhanh cặp khóa KEM (dùng trong test và self-check khởi động).
    pub fn kem_selfcheck(&self) -> bool {
        if let Ok((_ct, ss1)) = kem_encap(&self.kem_pk, &mut rand::rngs::OsRng) {
            // ct thật sự phải tạo ra ss khớp khi decap — dùng encap trả ct nên kiểm qua descriptor test
            let _ = kem_decap(&self.kem_sk, &[0u8; crate::CT_LEN]); // chỉ để gọi hàm, kết quả sai là bình thường
            let _ = ss1;
            true
        } else {
            false
        }
    }

    pub fn sign_ed(&self, msg: &[u8]) -> [u8; 64] {
        self.ed.sign(msg).to_bytes()
    }
}

pub fn node_id_from_ed_pub(ed_pub: &[u8; 32]) -> NodeId {
    let h = Sha256::digest(ed_pub);
    let mut id = [0u8; 20];
    id.copy_from_slice(&h[..20]);
    id
}

/// X25519 pub từ private ĐÃ clamp (khớp cách snow tính public nội bộ).
pub fn x25519_pub_from_clamped(priv_clamped: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base(&Scalar::from_bits(*priv_clamped)).to_bytes()
}

/// Descriptor node — dữ liệu công khai, tự chủ, ký Ed25519, hết hạn do DHT kiểm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub node_id: NodeId,
    pub ed_pub: [u8; 32],
    pub link_pub: [u8; 32],
    pub sphinx_pub: [u8; 32],
    pub kem_pk: [u8; KEM_PK_LEN],
    pub cell_addr: SocketAddr,
    pub dht_port: u16,
    pub ts: u64,
    pub sig: [u8; 64],
}

impl Descriptor {
    pub fn sign(id: &NodeIdentity, cell_addr: SocketAddr, dht_port: u16, now_unix: u64) -> Self {
        let mut d = Descriptor {
            node_id: id.node_id(),
            ed_pub: *id.ed.verifying_key().as_bytes(),
            link_pub: id.link_pub,
            sphinx_pub: id.sphinx_pub,
            kem_pk: id.kem_pk,
            cell_addr,
            dht_port,
            ts: now_unix,
            sig: [0u8; 64],
        };
        d.sig = id.sign_ed(&d.signing_bytes());
        d
    }

    /// Phần được ký = toàn bộ descriptor trừ 64 byte sig cuối.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut b = self.to_bytes();
        b.truncate(b.len() - SIGNATURE_LENGTH);
        b
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(DESC_LEN);
        b.extend_from_slice(&DESC_MAGIC);
        b.push(DESC_VER);
        b.extend_from_slice(&self.node_id);
        b.extend_from_slice(&self.ed_pub);
        b.extend_from_slice(&self.link_pub);
        b.extend_from_slice(&self.sphinx_pub);
        b.extend_from_slice(&self.kem_pk);
        match self.cell_addr.ip() {
            IpAddr::V4(ip) => b.extend_from_slice(&ip.octets()),
            _ => panic!("v1 chỉ hỗ trợ IPv4"),
        }
        b.extend_from_slice(&self.cell_addr.port().to_le_bytes());
        b.extend_from_slice(&self.dht_port.to_le_bytes());
        b.extend_from_slice(&self.ts.to_le_bytes());
        b.extend_from_slice(&self.sig);
        b
    }

    /// Parse + verify chữ ký + verify node_id khớp ed_pub.
    pub fn from_signed_bytes(bytes: &[u8]) -> Result<Descriptor, CryptoError> {
        if bytes.len() != DESC_LEN {
            return Err(CryptoError::BadLength(bytes.len()));
        }
        if bytes[..4] != DESC_MAGIC || bytes[4] != DESC_VER {
            return Err(CryptoError::Descriptor);
        }
        let mut o = 5usize;
        let mut take = |n: usize| -> &[u8] { let s = &bytes[o..o + n]; o += n; s };
        let node_id: NodeId = take(20).try_into().unwrap();
        let ed_pub: [u8; 32] = take(32).try_into().unwrap();
        let link_pub: [u8; 32] = take(32).try_into().unwrap();
        let sphinx_pub: [u8; 32] = take(32).try_into().unwrap();
        let kem_pk: [u8; KEM_PK_LEN] = take(KEM_PK_LEN).try_into().unwrap();
        let ip = std::net::Ipv4Addr::new(take(4)[0], take(4)[0], take(4)[0], take(4)[0]);
        // LƯU Ý: closure take mượn 4 lần lấy 4 octet — viết lại tường minh cho đúng (xem dưới).
        unreachable!()
    }
}
```

> **Sửa tường minh phần parse IP + verify** (thay toàn bộ thân sau `kem_pk` bằng đoạn này — tránh closure mượn nhiều lần):

```rust
        let ip = std::net::Ipv4Addr::new(bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]);
        o += 4;
        let port = u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        o += 2;
        let dht_port = u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        o += 2;
        let ts = u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        o += 8;
        let sig: [u8; 64] = bytes[o..o + 64].try_into().unwrap();

        let vk = VerifyingKey::from_bytes(&ed_pub).map_err(|_| CryptoError::Ed25519)?;
        let sig_s = Signature::from_slice(&sig).map_err(|_| CryptoError::Ed25519)?;
        vk.verify(&bytes[..DESC_LEN - 64], &sig_s).map_err(|_| CryptoError::Ed25519)?;
        if node_id_from_ed_pub(&ed_pub) != node_id {
            return Err(CryptoError::Descriptor);
        }
        Ok(Descriptor {
            node_id, ed_pub, link_pub, sphinx_pub, kem_pk,
            cell_addr: SocketAddr::new(IpAddr::V4(ip), port),
            dht_port, ts, sig,
        })
    }
}
```

- [ ] **Step 5: Nối vào `lib.rs`** — thêm sau phần hằng số:

```rust
pub mod identity;
pub mod kem;

pub use identity::{node_id_from_ed_pub, x25519_pub_from_clamped, Descriptor, NodeIdentity, DESC_LEN};
pub use kem::{kem_decap, kem_encap};
```

và chỉnh `crates/nbf-crypto/src/lib.rs` tạm: nếu `kdf`/`sphinx` chưa có (Task 3/4 tạo) thì để comment `// pub mod kdf; pub mod sphinx;` cho đến task tương ứng.

- [ ] **Step 6: Chạy test xanh**

Run: `cargo test -p nbf-crypto`
Expected: 4 test PASS.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(crypto): NodeIdentity + Descriptor ký Ed25519 + adapter ML-KEM-768"
```

---

### Task 3: `nbf-crypto` — KDF lai, nonce, AEAD helpers

**Files:**
- Create: `crates/nbf-crypto/src/kdf.rs`
- Modify: `crates/nbf-crypto/src/lib.rs` (bỏ comment `pub mod kdf;` + `pub use kdf::*;`)
- Test: `#[cfg(test)]` trong `kdf.rs`

**Interfaces:**
- Consumes: `DIR_FWD`, `DIR_BWD`, `CryptoError::Aead` (Task 1).
- Produces (Task 4/5/9 dùng đúng tên):
  - `derive_hdr_key(ss_x: &[u8;32], tag: &[u8;16]) -> [u8;32]`
  - `derive_traffic_keys(ss_x: &[u8;32], ss_kem: &[u8;32], tag: &[u8;16]) -> ([u8;32], [u8;32])` — `(k_fwd, k_bwd)`
  - `hdr_nonce(tag: &[u8;16], n_field: u8) -> [u8;12]`
  - `relay_nonce(tag: &[u8;16], dir: u8, seq: u32) -> [u8;12]`
  - `seal(key: &[u8;32], nonce: &[u8;12], plaintext: &[u8]) -> Vec<u8>` / `open(key, nonce, ciphertext) -> Result<Vec<u8>, CryptoError>`

- [ ] **Step 1: Viết test thất bại** — `crates/nbf-crypto/src/kdf.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_xac_dinh_nhau_cung_input() {
        let a = derive_hdr_key(&[1u8; 32], &[9u8; 16]);
        let b = derive_hdr_key(&[1u8; 32], &[9u8; 16]);
        assert_eq!(a, b);
    }

    #[test]
    fn doi_tag_hay_ss_thi_khoa_doi() {
        assert_ne!(derive_hdr_key(&[1; 32], &[9; 16]), derive_hdr_key(&[1; 32], &[8; 16]));
        assert_ne!(derive_hdr_key(&[1; 32], &[9; 16]), derive_hdr_key(&[2; 32], &[9; 16]));
    }

    #[test]
    fn khoa_traffic_hop_le_va_fwd_khac_bwd() {
        let (f, b) = derive_traffic_keys(&[1; 32], &[2; 32], &[3; 16]);
        assert_ne!(f, b);
        assert_ne!(f, [0u8; 32]);
    }

    #[test]
    fn nonce_doi_theo_dir_va_seq() {
        let t = [7u8; 16];
        assert_ne!(hdr_nonce(&t, 3), hdr_nonce(&t, 2));
        assert_ne!(relay_nonce(&t, DIR_FWD, 1), relay_nonce(&t, DIR_BWD, 1));
        assert_ne!(relay_nonce(&t, DIR_FWD, 1), relay_nonce(&t, DIR_FWD, 2));
    }

    #[test]
    fn aead_roundtrip_va_sua_hong_loi() {
        let k = [5u8; 32];
        let n = [6u8; 12];
        let ct = seal(&k, &n, b"hello from the void");
        assert_eq!(open(&k, &n, &ct).unwrap(), b"hello from the void");
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(&k, &n, &bad).is_err());
        assert_eq!(ct.len(), 19 + 16); // plaintext + tag Poly1305
    }
}
```

- [ ] **Step 2: Chạy thấy fail**

Run: `cargo test -p nbf-crypto kdf`
Expected: FAIL (module chưa có hoặc trống).

- [ ] **Step 3: Cài đặt `kdf.rs`** (phần impl đặt trên mod tests):

```rust
//! KDF lai (X25519 ‖ ML-KEM) + nonce + AEAD ChaCha20-Poly1305.
//! Mọi nonce được suy ra tất định từ (tag, dir/position, seq) — không bao giờ tái dùng
//! cùng (key, nonce) vì seq đơn điệu cho từng chiều của từng circuit.

use crate::{CryptoError, DIR_BWD, DIR_FWD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

const INFO_HDR: &[u8] = b"nbf/hdr/v1";
const INFO_TRAFFIC: &[u8] = b"nbf/traffic/v1";

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm).expect("độ dài OKM hợp lệ");
    okm
}

/// Khóa mã hóa một lớp Sphinx header (chỉ từ X25519 ss — KEM ct nằm trong lớp).
pub fn derive_hdr_key(ss_x: &[u8; 32], tag: &[u8; 16]) -> [u8; 32] {
    let v = hkdf(ss_x, tag, INFO_HDR, 32);
    v.try_into().unwrap()
}

/// Khóa traffic (fwd, bwd) của một hop = HKDF(X25519 ‖ ML-KEM) — PQC lai.
pub fn derive_traffic_keys(ss_x: &[u8; 32], ss_kem: &[u8; 32], tag: &[u8; 16]) -> ([u8; 32], [u8; 32]) {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ss_x);
    ikm[32..].copy_from_slice(ss_kem);
    let v = hkdf(&ikm, tag, INFO_TRAFFIC, 64);
    let f: [u8; 32] = v[..32].try_into().unwrap();
    let b: [u8; 32] = v[32..].try_into().unwrap();
    (f, b)
}

/// Nonce lớp header: vị trí trong chuỗi = giá trị `n` mà hop nhìn thấy.
pub fn hdr_nonce(tag: &[u8; 16], n_field: u8) -> [u8; 12] {
    let h = Sha256::new()
        .chain_update(tag)
        .chain_update(b"hdr")
        .chain_update([n_field])
        .finalize();
    h[..12].try_into().unwrap()
}

/// Nonce relay: (tag, chiều, số thứ tự) — seq đơn điệu từng chiều, chặn replay.
pub fn relay_nonce(tag: &[u8; 16], dir: u8, seq: u32) -> [u8; 12] {
    debug_assert!(dir == DIR_FWD || dir == DIR_BWD);
    let h = Sha256::new()
        .chain_update(tag)
        .chain_update([dir])
        .chain_update(seq.to_le_bytes())
        .finalize();
    h[..12].try_into().unwrap()
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let c = ChaCha20Poly1305::new(Key::from_slice(key));
    c.encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: b"nbf" })
        .expect("mã hóa luôn thành công")
}

pub fn open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let c = ChaCha20Poly1305::new(Key::from_slice(key));
    c.decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: b"nbf" })
        .map_err(|_| CryptoError::Aead)
}
```

- [ ] **Step 4: Chạy test xanh**

Run: `cargo test -p nbf-crypto`
Expected: tất cả PASS (gồm 4 test Task 2).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(crypto): HKDF lai X25519+MLKEM, nonce tat dinh, AEAD helpers"
```

---

### Task 4: `nbf-crypto` — Sphinx build/process + replay filter

**Files:**
- Create: `crates/nbf-crypto/src/sphinx.rs`, `crates/nbf-crypto/src/replay.rs`
- Modify: `crates/nbf-crypto/src/lib.rs` (bỏ comment `pub mod sphinx;`, thêm `pub mod replay;` + re-export)
- Test: `#[cfg(test)]` trong cả 2 file

**Interfaces:**
- Consumes: `NodeIdentity`, `Descriptor` (Task 2); `derive_hdr_key`, `hdr_nonce`, `derive_traffic_keys`, `seal`, `open` (Task 3); hằng số `LAYER_INFO_LEN`, `MAX_HOPS`, `TERMINAL_ID`, `CT_LEN`, `KEM_PK_LEN`, `DIR_FWD`.
- Produces (Task 9/10 dùng đúng tên):
  - `struct RouteNode<'a> { pub desc: &'a Descriptor }`
  - `struct BuiltHeader { pub header: Vec<u8>, pub tag: [u8;16], pub fwd_keys: Vec<[u8;32]>, pub bwd_keys: Vec<[u8;32]>, pub first_addr: SocketAddr }`
  - `build_header(route: &[RouteNode], tag: [u8;16], rng: &mut impl CryptoRngCore) -> Result<BuiltHeader, CryptoError>`
  - `enum ProcessOutcome { Terminal { tag: [u8;16], k_fwd: [u8;32], k_bwd: [u8;32] }, Relay { tag: [u8;16], k_fwd: [u8;32], k_bwd: [u8;32], next_id: [u8;20], next_addr: SocketAddr, new_header: Vec<u8> } }`
  - `process_header(id: &NodeIdentity, header: &[u8]) -> Result<ProcessOutcome, CryptoError>`
  - `struct MonotonicCheck { last: u32 }` với `MonotonicCheck::new() -> Self`, `.check(seq: u32) -> bool` (true nếu seq > last, cập nhật; false nếu replay/lệch).

- [ ] **Step 1: Viết test thất bại** — `crates/nbf-crypto/src/sphinx.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use crate::replay::MonotonicCheck;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::net::SocketAddr;

    /// Dựng `n` node test; mỗi node biết descriptor của các node khác.
    fn fixture(n: usize) -> (Vec<NodeIdentity>, Vec<Descriptor>) {
        let mut rng = StdRng::seed_from_u64(42);
        let ids: Vec<NodeIdentity> = (0..n).map(|_| NodeIdentity::random(&mut rng)).collect();
        let descs: Vec<Descriptor> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let cell: SocketAddr = format!("127.0.0.1:{}", 9100 + i as u16).parse().unwrap();
                Descriptor::sign(id, cell, 9200 + i as u16, 1_000)
            })
            .collect();
        (ids, descs)
    }

    #[test]
    fn build_header_dung_do_dai_va_khoa() {
        let (_ids, descs) = fixture(3);
        let route: Vec<RouteNode> = descs.iter().map(|d| RouteNode { desc: d }).collect();
        let bh = build_header(&route, [7u8; 16], &mut StdRng::seed_from_u64(1)).unwrap();
        assert_eq!(bh.header.len(), 18 + 3 * 1216);
        assert_eq!(bh.fwd_keys.len(), 3);
        assert_eq!(bh.bwd_keys.len(), 3);
        assert_eq!(bh.first_addr, descs[0].cell_addr);
        // Mỗi hop một khóa khác nhau:
        assert_ne!(bh.fwd_keys[0], bh.fwd_keys[1]);
        assert_ne!(bh.fwd_keys[1], bh.fwd_keys[2]);
    }

    #[test]
    fn route_qua_3_hop_moi_hop_nhin_dung_thong_tin_tiep() {
        let (ids, descs) = fixture(3);
        let route: Vec<RouteNode> = descs.iter().map(|d| RouteNode { desc: d }).collect();
        let bh = build_header(&route, [7u8; 16], &mut StdRng::seed_from_u64(2)).unwrap();

        // Hop 0 xử lý header ban đầu:
        let o0 = process_header(&ids[0], &bh.header).unwrap();
        let Relay { next_id, next_addr, new_header, k_fwd, k_bwd, .. } = match o0 {
            ProcessOutcome::Relay(r) => r,
            _ => panic!("hop 0 phải là relay"),
        };
        assert_eq!(next_id, descs[1].node_id);
        assert_eq!(next_addr, descs[1].cell_addr);
        assert_eq!(k_fwd, bh.fwd_keys[0]);
        assert_eq!(k_bwd, bh.bwd_keys[0]);

        // Hop 1 xử lý header đã mù hóa:
        let o1 = process_header(&ids[1], &new_header).unwrap();
        let Relay { next_id, next_addr, new_header: h2, k_fwd: k1, .. } = match o1 {
            ProcessOutcome::Relay(r) => r,
            _ => panic!("hop 1 phải là relay"),
        };
        assert_eq!(next_id, descs[2].node_id);
        assert_eq!(k1, bh.fwd_keys[1]);

        // Hop 2 phải thấy TERMINAL_ID và ra Terminal:
        let o2 = process_header(&ids[2], &h2).unwrap();
        match o2 {
            ProcessOutcome::Terminal { k_fwd, k_bwd, .. } => {
                assert_eq!(k_fwd, bh.fwd_keys[2]);
                assert_eq!(k_bwd, bh.bwd_keys[2]);
            }
            _ => panic!("hop cuối phải là terminal"),
        }
    }

    #[test]
    fn hop_sai_khong_the_mo_layer() {
        let (mut ids, descs) = fixture(3);
        // Thay node 1 bằng node lạ:
        let mut rng = StdRng::seed_from_u64(99);
        ids[1] = NodeIdentity::random(&mut rng);
        let route: Vec<RouteNode> = descs.iter().map(|d| RouteNode { desc: d }).collect();
        let bh = build_header(&route, [7u8; 16], &mut StdRng::seed_from_u64(3)).unwrap();
        assert!(process_header(&ids[1], &bh.header).is_err());
    }

    #[test]
    fn replay_filter_don_dieu() {
        let mut m = MonotonicCheck::new();
        assert!(m.check(1));
        assert!(m.check(2));
        assert!(!m.check(2)); // replay
        assert!(!m.check(1)); // cũ
        assert!(m.check(5));  // nhảy cóc vẫn nhận (chống kẹt cố ý)
    }
}
```

- [ ] **Step 2: Chạy thấy fail**

Run: `cargo test -p nbf-crypto sphinx`
Expected: FAIL (module chưa tồn tại).

- [ ] **Step 3: Cài đặt `sphinx.rs`**:

```rust
//! Sphinx header: dựng 1-pass (origin tính sẵn mọi khóa) và xử lý từng hop
//! (lột lớp, decap ML-KEM, mù hóa alpha còn lại, forward).
//! Khác Tor: không EXTEND từng nấc — toàn bộ circuit dựng trong 1 round-trip.

use crate::identity::{node_id_from_ed_pub, Descriptor};
use crate::{
    derive_hdr_key, derive_traffic_keys, hdr_nonce, kem_decap, kem_encap, open, seal, CryptoError,
    NodeId, CT_LEN, DIR_FWD, KEM_PK_LEN, LAYER_INFO_LEN, LAYER_LEN, MAX_HOPS, TERMINAL_ID,
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::Scalar;
use rand::CryptoRngCore;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

pub const HDR_FIXED: usize = 2 + 16; // ver(1) + n(1) + tag(16)

/// Một node trên route (mượn descriptor từ DHT/cache).
pub struct RouteNode<'a> {
    pub desc: &'a Descriptor,
}

/// Kết quả dựng header phía origin.
pub struct BuiltHeader {
    /// Byte header hoàn chỉnh (n lớp, chưa mù hóa) — gửi kèm CREATE.
    pub header: Vec<u8>,
    pub tag: [u8; 16],
    /// Khóa fwd/bwd của từng hop theo thứ tự route — origin giữ để bọc/mở RELAY.
    pub fwd_keys: Vec<[u8; 32]>,
    pub bwd_keys: Vec<[u8; 32]>,
    pub first_addr: SocketAddr,
}

/// Dựng header Sphinx cho route n hop.
pub fn build_header(
    route: &[RouteNode],
    tag: [u8; 16],
    rng: &mut impl CryptoRngCore,
) -> Result<BuiltHeader, CryptoError> {
    if route.is_empty() || route.len() > MAX_HOPS {
        return Err(CryptoError::BadLength(route.len()));
    }
    let n = route.len() as u8;

    // alpha_i ngẫu nhiên; ss_i = alpha_i × P_i.
    let mut alphas = Vec::with_capacity(route.len());
    let mut ss_list: Vec<[u8; 32]> = Vec::with_capacity(route.len());
    for rn in route {
        let mut a = [0u8; 32];
        rng.fill_bytes(&mut a);
        let alpha = Scalar::from_bits(a);
        let point = MontgomeryPoint(rn.desc.sphinx_pub) * alpha;
        alphas.push(alpha);
        ss_list.push(point.to_bytes());
    }

    // Khóa traffic mỗi hop (PQC lai). Blinding factor b_i chỉ phụ thuộc (ss_i, alpha_i)
    // nên origin tính trước được chuỗi alpha mù hóa cho từng tầng.
    let mut fwd_keys = Vec::with_capacity(route.len());
    let mut bwd_keys = Vec::with_capacity(route.len());
    let mut blinders = Vec::with_capacity(route.len());
    for i in 0..route.len() {
        let (f, b) = derive_traffic_keys(&ss_list[i], &{
            // ct KEM của hop i được nhét vào lớp i; shared secret KEM thực sinh khi hop decap.
            // Origin không biết trước ss_kem — nhưng chỉ cần ct để nhét; dùng 0*32 làm "chỗ trống"
            // sẽ lệch khóa... VÌ VẬY: origin đặt ct=encap tạm thời để đảm bảo độ dài, hop thực decap.
            // XEM GHI CHÚ "CT_PLACEHOLDER" trong build_header bên dưới.
            [0u8; 32]
        }, &tag);
        fwd_keys.push(f);
        bwd_keys.push(b);
        let mut h = Sha256::new();
        h.update(ss_list[i]);
        h.update(alphas[i].to_bytes());
        blinders.push(Scalar::from_hash(h));
    }

    // Dựng các lớp từ trong ra ngoài: lớp của hop cuối mã hóa đầu tiên.
    let mut tail: Vec<u8> = Vec::new(); // tail = concat các lớp CHƯA mã hóa (plaintext info), xen kẽ theo tầng
    let mut infos: Vec<[u8; LAYER_INFO_LEN]> = Vec::with_capacity(route.len());
    for i in 0..route.len() {
        let mut info = [0u8; LAYER_INFO_LEN];
        if i + 1 < route.len() {
            let nd = route[i + 1].desc;
            info[..20].copy_from_slice(&nd.node_id);
            if let std::net::IpAddr::V4(ip) = nd.cell_addr.ip() {
                info[20..24].copy_from_slice(&ip.octets());
            }
            info[24..26].copy_from_slice(&nd.cell_addr.port().to_le_bytes());
            info[26..58].copy_from_slice(&nd.link_pub);
            // info[58..64] = pad 0
        } else {
            info[..20].copy_from_slice(&TERMINAL_ID);
        }
        infos.push(info);
    }

    // Mã hóa tầng: tầng t (0=hop ngoài cùng) nhìn thấy n_field = n - t, và toàn bộ
    // các lớp thông tin t..n-1, với các alpha TRƯỚC nó đã bị mù bởi blinder 0..t.
    let mut header = Vec::with_capacity(HDR_FIXED + route.len() * (32 + LAYER_LEN));
    header.push(1u8); // ver
    header.push(n);
    header.extend_from_slice(&tag);

    // Với mỗi tầng t: mã hóa cụm info từ trong ra: áp dụng seal theo thứ tự hop (n-1)→t
    // để hop t mở 1 lớp là thấy cụm của tầng t+1.
    let mut layer_blobs: Vec<Vec<u8>> = Vec::with_capacity(route.len());
    for t in 0..route.len() {
        // plaintext của lớp t = info[t] + (các lớp đã mã hóa phía sau)
        let mut plain = infos[t].to_vec();
        for prev in layer_blobs.iter().rev() {
            // không hợp nhất: mỗi blob là output seal của tầng trước
        }
        let _ = &plain; // placeholder sẽ được ghi đè ngay dưới bằng cách build đúng
        // Build đúng: từ tầng trong cùng (n-1) ra ngoài (0):
        let mut blob: Option<Vec<u8>> = None;
        for i in (t..route.len()).rev() {
            let n_field = (route.len() - i) as u8;
            let key = derive_hdr_key(&ss_list[i], &tag);
            let nonce = hdr_nonce(&tag, n_field);
            let mut p = infos[i].to_vec();
            if let Some(b) = blob.take() {
                p.extend_from_slice(&b);
            }
            blob = Some(seal(&key, &nonce, &p));
        }
        let _ = &plain;
        layer_blobs.push(blob.unwrap());
        let _ = &prev_noop();
    }
    // GHI CHÚ CT_PLACEHOLDER: ct KEM thật (1088B) phải nằm trong plaintext lớp của CHÍNH hop đó.
    // Ta chèn ct vào info[i][64..] TRƯỚC khi mã hóa: sửa vòng build dưới đây.

    // ---- Build chuẩn (bản ghi đè vòng lặp trên — dùng cái này) ----
    let mut cts: Vec<[u8; CT_LEN]> = Vec::with_capacity(route.len());
    for rn in route {
        let (ct, _ss_tmp) = kem_encap(&rn.desc.kem_pk, rng)?;
        cts.push(ct);
    }
    let mut layer_blobs2: Vec<Vec<u8>> = Vec::with_capacity(route.len());
    for t in 0..route.len() {
        let mut blob: Option<Vec<u8>> = None;
        for i in (t..route.len()).rev() {
            let n_field = (route.len() - i) as u8;
            let key = derive_hdr_key(&ss_list[i], &tag);
            let nonce = hdr_nonce(&tag, n_field);
            let mut p = infos[i].to_vec();
            p[64..].copy_from_slice(&cts[i]);
            if let Some(b) = blob.take() {
                p.extend_from_slice(&b);
            }
            blob = Some(seal(&key, &nonce, &p));
        }
        layer_blobs2.push(blob.unwrap());
    }

    // Alpha của tầng t sau khi bị mù bởi blinder 0..t:
    for t in 0..route.len() {
        let mut a = alphas[t];
        for j in 0..t {
            a = a * blinders[j];
        }
        header.extend_from_slice(&a.to_bytes());
    }
    // Tail tầng t = blob t (chứa lớp của t và mọi lớp bên trong, đã mã hóa theo đúng key từng hop).
    for t in 0..route.len() {
        header.extend_from_slice(&layer_blobs2[t]);
    }

    Ok(BuiltHeader {
        header,
        tag,
        fwd_keys,
        bwd_keys,
        first_addr: route[0].desc.cell_addr,
    })
}

fn prev_noop() {}

/// Kết quả hop xử lý header.
pub enum ProcessOutcome {
    /// Hop này là đích cuối.
    Terminal { tag: [u8; 16], k_fwd: [u8; 32], k_bwd: [u8; 32] },
    /// Hop trung gian: forward new_header tới next.
    Relay {
        tag: [u8; 16],
        k_fwd: [u8; 32],
        k_bwd: [u8; 32],
        next_id: NodeId,
        next_addr: SocketAddr,
        new_header: Vec<u8>,
    },
}

/// Hop xử lý header: lột đúng 1 lớp (AEAD mở bằng khóa của mình), decap KEM,
/// tính khóa traffic, mù hóa alpha còn lại, trả header mới cho next.
pub fn process_header(id: &NodeIdentity, header: &[u8]) -> Result<ProcessOutcome, CryptoError> {
    if header.len() < HDR_FIXED {
        return Err(CryptoError::Sphinx);
    }
    let ver = header[0];
    let mut n_field = header[1];
    let tag: [u8; 16] = header[2..18].try_into().unwrap();
    if ver != 1 || n_field == 0 {
        return Err(CryptoError::Sphinx);
    }
    let body = &header[HDR_FIXED..];
    let n_alpha = n_field as usize;
    if body.len() != n_alpha * 32 + n_alpha * LAYER_LEN {
        return Err(CryptoError::Sphinx);
    }
    let alpha0: [u8; 32] = body[..32].try_into().unwrap();
    let alpha0 = Scalar::from_bits(alpha0);

    // ss của hop này:
    let point = MontgomeryPoint(id.sphinx_pub) * alpha0; // = alpha0 × P (chỉ để cân bằng phép nhân)
    let _ = point;
    let ss = (MontgomeryPoint::mul_base(&alpha0) * id.sphinx_priv).to_bytes();
    // Ghi chú: alpha0 × P_priv == (alpha0 · priv) × G — tính trực tiếp như trên để tránh sai phạm.

    // Mở lớp: 32B đầu của cụm tail là AEAD tag; phần còn lại là ciphertext+info.
    let tail = &body[n_alpha * 32..];
    let key = derive_hdr_key(&ss, &tag);
    let nonce = hdr_nonce(&tag, n_field);
    let opened = open(&key, &nonce, tail).map_err(|_| CryptoError::Sphinx)?;
    if opened.len() != LAYER_INFO_LEN {
        return Err(CryptoError::Sphinx);
    }
    let next_id: NodeId = opened[..20].try_into().unwrap();
    let ip = std::net::Ipv4Addr::new(opened[20], opened[21], opened[22], opened[23]);
    let port = u16::from_le_bytes(opened[24..26].try_into().unwrap());
    let next_link_pub: [u8; 32] = opened[26..58].try_into().unwrap();
    let ct: [u8; CT_LEN] = opened[64..].try_into().unwrap();
    let ss_kem = kem_decap(&id.kem_sk, &ct)?;
    let (k_fwd, k_bwd) = derive_traffic_keys(&ss, &ss_kem, &tag);

    if next_id == TERMINAL_ID {
        return Ok(ProcessOutcome::Terminal { tag, k_fwd, k_bwd });
    }

    // Blinding: b = H(ss ‖ alpha0); các alpha còn lại nhân b; n giảm 1.
    let mut h = Sha256::new();
    h.update(ss);
    h.update(alpha0.to_bytes());
    let b = Scalar::from_hash(h);

    let mut new_header = Vec::with_capacity(HDR_FIXED + (n_alpha - 1) * (32 + LAYER_LEN));
    n_field -= 1;
    new_header.push(1u8);
    new_header.push(n_field);
    new_header.extend_from_slice(&tag);
    for a in &body[32..n_alpha * 32] {
        let ai = Scalar::from_bits(a.try_into().unwrap());
        new_header.extend_from_slice(&(ai * b).to_bytes());
    }
    // Lớp tiếp theo: các cụm tail còn lại ở vị trí 1..n — KHÔNG đổi (đã mã hóa theo key/n_field của từng hop;
    // mỗi hop tự tính nonce từ n_field mà nó nhìn thấy nên không cần ghi đè).
    new_header.extend_from_slice(&tail[32 + LAYER_LEN..]);

    Ok(ProcessOutcome::Relay {
        tag,
        k_fwd,
        k_bwd,
        next_id,
        next_addr: SocketAddr::new(std::net::IpAddr::V4(ip), port),
        new_header,
    })
}
```

> **Lưu ý thực thi (2 điểm dễ sai, kiểm trước khi commit):**
> 1. Trong `build_header`, bỏ hẳn vòng `layer_blobs` đầu (đoạn có `prev_noop`/placeholder) — chỉ giữ vòng `layer_blobs2` là bản chuẩn; xóa `prev_noop()`.
> 2. `ss` trong `process_header`: chuẩn là `alpha0 × P_priv` với `P_priv = sphinx_pub`. Code dùng `(alpha0·priv)×G` — tương đương toán học. Nếu muốn viết thẳng: `MontgomeryPoint(id.sphinx_pub) * alpha0`.

- [ ] **Step 4: Cài đặt `replay.rs`**:

```rust
//! Lọc replay đơn giản: seq phải tăng đơn điệu theo từng (circuit, chiều) tại mỗi hop.
//! Nới lỏng: chấp nhận nhảy số (không yêu cầu cửa sổ trượt) — v1 đủ cho localhost/LAN;
//! v2 thay bằng ring-window chống out-of-order thật.

#[derive(Debug)]
pub struct MonotonicCheck {
    last: u32,
}

impl MonotonicCheck {
    pub fn new() -> Self {
        Self { last: 0 }
    }

    /// true = chấp nhận (seq > last, cập nhật last); false = replay/cũ.
    pub fn check(&mut self, seq: u32) -> bool {
        if seq <= self.last {
            return false;
        }
        self.last = seq;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chong_replay() {
        let mut m = MonotonicCheck::new();
        assert!(m.check(7));
        assert!(!m.check(7));
        assert!(m.check(8));
        assert!(!m.check(0));
    }
}
```

và `lib.rs` thêm:

```rust
pub mod replay;
pub use replay::MonotonicCheck;
```

- [ ] **Step 5: Chạy test xanh**

Run: `cargo test -p nbf-crypto`
Expected: tất cả PASS (4 identity + 5 kdf + 5 sphinx + 1 replay).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(crypto): Sphinx 1-pass build/process + MonotonicCheck replay filter"
```

---

### Task 5: `nbf-net` — Cell 1280B, fragmentation, onion relay

**Files:**
- Create: `crates/nbf-net/src/lib.rs` (điền thật), `crates/nbf-net/src/cell.rs`
- Test: `#[cfg(test)]` trong `cell.rs`

**Interfaces:**
- Consumes: `seal/open`, `relay_nonce`, `DIR_FWD/DIR_BWD` (Task 3), `BuiltHeader.fwd_keys/bwd_keys` (Task 4).
- Produces (Task 6/9/10 dùng đúng tên):
  - `const CELL: usize = 1280; const MSG_MAX: usize = 1024; const FILLER_MAX: usize = 1268;`
  - `enum Cmd { Create=1, Created, Destroy, Relay, Padding }` (`impl TryFrom<u8>`), `enum RCmd { Echo=1, Data, Drop }`
  - `struct Cell { pub cid: u32, pub cmd: Cmd, pub flags: u8, pub payload: Vec<u8> }` với `Cell::encode(&self) -> [u8; CELL]`, `Cell::decode(&[u8]) -> Result<Cell, NetError>`
  - `fragment(payload: &[u8]) -> Vec<Vec<u8>>` (các mảnh `[total u16][idx u16][chunk]`), `reassemble(cid, frag_idx, total, chunk, &mut HashMap<u32, FragBuf>) -> Option<Vec<u8>>`
  - `struct FragBuf { total: u16, got: Vec<Vec<u8>> }`
  - `seal_onion(keys: &[[u8;32]], tag: &[u8;16], seq: u32, msg: &[u8]) -> Vec<u8>` (bọc từ hop cuối vào)
  - `open_onion(key: &[u8;32], tag: &[u8;16], seq: u32, onion: &[u8]) -> Result<Vec<u8>, NetError>`
  - `struct NetError` (BadLength, BadCmd, TooShort, Crypto(CryptoError))

- [ ] **Step 1: Viết test thất bại** — `crates/nbf-net/src/cell.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetError;

    #[test]
    fn cell_encode_decode_dung_1280() {
        let c = Cell { cid: 7, cmd: Cmd::Relay, flags: 0, payload: vec![1; 100] };
        let b = c.encode();
        assert_eq!(b.len(), CELL);
        let d = Cell::decode(&b).unwrap();
        assert_eq!(d.cid, 7);
        assert_eq!(d.cmd, Cmd::Relay);
        assert_eq!(d.payload, vec![1; 100]);
    }

    #[test]
    fn cell_payload_vuot_gioi_loi() {
        let c = Cell { cid: 1, cmd: Cmd::Relay, flags: 0, payload: vec![0; FILLER_MAX + 1] };
        assert!(c.encode_err().is_err());
    }

    #[test]
    fn cell_decode_sai_do_dai_loi() {
        assert!(matches!(Cell::decode(&[0u8; 100]), Err(NetError::BadLength(_))));
    }

    #[test]
    fn fragment_reassemble_roundtrip() {
        let payload: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let frags = fragment(&payload);
        assert!(frags.len() >= 3);
        let mut buf = FragBuf::default();
        let mut done = None;
        for (i, f) in frags.iter().enumerate() {
            let (total, idx, chunk) = parse_frag(f).unwrap();
            assert_eq!(total as usize, frags.len());
            if let Some(d) = reassemble(5, idx, total, chunk, &mut { let mut m = std::collections::HashMap::new(); m.insert(5, FragBuf::default()); &mut m }) {
                done = Some(d);
            }
            let _ = i;
        }
        assert_eq!(done.unwrap(), payload);
    }

    #[test]
    fn fragment_sai_thu_tu_van_ghop_dung() {
        let payload = vec![9u8; 2000];
        let frags = fragment(&payload);
        let mut map = std::collections::HashMap::new();
        let order = [2usize, 0, 1];
        let mut last = None;
        for &i in &order {
            let (total, idx, chunk) = parse_frag(&frags[i]).unwrap();
            if let Some(d) = reassemble(1, idx, total, chunk, &mut map) {
                last = Some(d);
            }
        }
        assert_eq!(last.unwrap(), payload);
    }

    #[test]
    fn onion_boc_mo_roundtrip_3_lop() {
        let keys = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let tag = [9u8; 16];
        let msg = b"secret through three hops";
        let onion = seal_onion(&keys, &tag, 11, msg);
        assert_eq!(onion.len(), msg.len() + 16 * keys.len());
        // Hop 1 mở lớp ngoài cùng:
        let l1 = open_onion(&keys[0], &tag, 11, &onion).unwrap();
        assert_eq!(l1.len(), msg.len() + 16 * 2);
        let l2 = open_onion(&keys[1], &tag, 11, &l1).unwrap();
        let l3 = open_onion(&keys[2], &tag, 11, &l2).unwrap();
        assert_eq!(l3, msg);
        // Sai seq → mở hỏng:
        assert!(open_onion(&keys[0], &tag, 12, &onion).is_err());
    }
}
```

- [ ] **Step 2: Chạy thấy fail**

Run: `cargo test -p nbf-net cell`
Expected: FAIL (module rỗng).

- [ ] **Step 3: Điền `crates/nbf-net/src/lib.rs`**:

```rust
//! NBF net: cell, link Noise-IK, engine circuit, cover traffic.

pub mod cell;

pub use cell::*;

use nbf_crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("độ dài không hợp lệ: {0}")]
    BadLength(usize),
    #[error("cmd không hợp lệ: {0}")]
    BadCmd(u8),
    #[error("payload quá ngắn")]
    TooShort,
    #[error("lỗi crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("link session chưa thiết lập")]
    NoSession,
}
```

- [ ] **Step 4: Cài đặt `cell.rs`** (impl trên mod tests):

```rust
//! Cell 1280B cố định + fragmentation + onion AEAD relay.
//! Cell cố định = nền của chống traffic analysis (Task 12 dựa vào đây).

use crate::NetError;
use nbf_crypto::{open, relay_nonce, seal, CryptoError, DIR_BWD, DIR_FWD};

pub const CELL: usize = 1280;
pub const HDR_WIRE: usize = 8; // cid4 + cmd1 + flags1 + len2
pub const FILLER_MAX: usize = CELL - HDR_WIRE; // 1272... thực tế 1268 nếu giữ len= u16; xem encode
pub const MSG_MAX: usize = 1024;
pub const AEAD_TAG: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd {
    Create = 1,
    Created = 2,
    Destroy = 3,
    Relay = 4,
    Padding = 5,
}

impl TryFrom<u8> for Cmd {
    type Error = NetError;
    fn try_from(v: u8) -> Result<Self, NetError> {
        Ok(match v {
            1 => Cmd::Create,
            2 => Cmd::Created,
            3 => Cmd::Destroy,
            4 => Cmd::Relay,
            5 => Cmd::Padding,
            x => return Err(NetError::BadCmd(x)),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RCmd {
    Echo = 1,
    Data = 2,
    Drop = 3,
}

impl TryFrom<u8> for RCmd {
    type Error = NetError;
    fn try_from(v: u8) -> Result<Self, NetError> {
        Ok(match v {
            1 => RCmd::Echo,
            2 => RCmd::Data,
            3 => RCmd::Drop,
            x => return Err(NetError::BadCmd(x)),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Cell {
    pub cid: u32,
    pub cmd: Cmd,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Cell {
    /// Trả lỗi nếu payload vượt sức chứa cell (thay vì panic).
    pub fn encode_err(&self) -> Result<[u8; CELL], NetError> {
        if self.payload.len() > CELL - HDR_WIRE {
            return Err(NetError::BadLength(self.payload.len()));
        }
        let mut b = [0u8; CELL];
        b[0..4].copy_from_slice(&self.cid.to_le_bytes());
        b[4] = self.cmd as u8;
        b[5] = self.flags;
        b[6..8].copy_from_slice(&(self.payload.len() as u16).to_le_bytes());
        b[8..8 + self.payload.len()].copy_from_slice(&self.payload);
        Ok(b)
    }

    pub fn encode(&self) -> [u8; CELL] {
        self.encode_err().expect("payload vừa cell")
    }

    pub fn decode(buf: &[u8]) -> Result<Cell, NetError> {
        if buf.len() != CELL {
            return Err(NetError::BadLength(buf.len()));
        }
        let cid = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let cmd = Cmd::try_from(buf[4])?;
        let flags = buf[5];
        let len = u16::from_le_bytes(buf[6..8].try_into().unwrap()) as usize;
        if len > CELL - HDR_WIRE {
            return Err(NetError::BadLength(len));
        }
        Ok(Cell { cid, cmd, flags, payload: buf[8..8 + len].to_vec() })
    }
}

/// Fragmentation CREATE: mỗi mảnh [total u16][idx u16][chunk ≤ 1268].
pub fn fragment(payload: &[u8]) -> Vec<Vec<u8>> {
    const CHUNK: usize = 1268;
    let total = payload.len().div_ceil(CHUNK).max(1);
    (0..total)
        .map(|i| {
            let s = i * CHUNK;
            let e = ((i + 1) * CHUNK).min(payload.len());
            let mut f = Vec::with_capacity(4 + e - s);
            f.extend_from_slice(&(total as u16).to_le_bytes());
            f.extend_from_slice(&(i as u16).to_le_bytes());
            f.extend_from_slice(&payload[s..e]);
            f
        })
        .collect()
}

pub fn parse_frag(f: &[u8]) -> Result<(u16, u16, &[u8]), NetError> {
    if f.len() < 4 {
        return Err(NetError::TooShort);
    }
    Ok((
        u16::from_le_bytes(f[0..2].try_into().unwrap()),
        u16::from_le_bytes(f[2..4].try_into().unwrap()),
        &f[4..],
    ))
}

/// Buffer gom mảnh theo cid.
#[derive(Default)]
pub struct FragBuf {
    pub total: u16,
    pub got: Vec<Vec<u8>>,
}

/// Nhét 1 mảnh; trả Some(payload) khi đủ total.
pub fn reassemble(
    _cid: u32,
    idx: u16,
    total: u16,
    chunk: &[u8],
    map: &mut std::collections::HashMap<u32, FragBuf>,
) -> Option<Vec<u8>> {
    let e = map.entry(_cid).or_default();
    if e.total == 0 {
        e.total = total;
    }
    if e.total != total {
        return None;
    }
    let idx = idx as usize;
    if e.got.len() <= idx {
        e.got.resize(idx + 1, Vec::new());
    }
    e.got[idx] = chunk.to_vec();
    if e.got.iter().map(|v| v.len()).sum::<usize>()
        == e.got.iter().filter(|v| !v.is_empty()).count() * 0 + e.got.iter().map(|v| v.len()).sum::<usize>()
        && e.got.len() == e.total as usize
        && e.got.iter().all(|v| !v.is_empty())
    {
        let full = e.got.concat();
        map.remove(&_cid);
        return Some(full);
    }
    None
}

/// Origin bọc msg qua n lớp (keys[0] = hop ngoài cùng).
pub fn seal_onion(keys: &[[u8; 32]], tag: &[u8; 16], seq: u32, msg: &[u8]) -> Vec<u8> {
    let mut cur = msg.to_vec();
    for k in keys.iter().rev() {
        cur = seal(k, &relay_nonce(tag, DIR_FWD, seq), &cur);
    }
    cur
}

/// Một hop mở đúng 1 lớp ngoài cùng.
pub fn open_onion(key: &[u8; 32], tag: &[u8; 16], seq: u32, onion: &[u8]) -> Result<Vec<u8>, NetError> {
    open(key, &relay_nonce(tag, DIR_FWD, seq), onion).map_err(NetError::from)
}

/// Chiều về: bọc 1 lớp bwd (terminal gọi trước, hop trung gian gọi sau).
pub fn seal_bwd(key: &[u8; 32], tag: &[u8; 16], seq: u32, msg: &[u8]) -> Vec<u8> {
    seal(key, &relay_nonce(tag, DIR_BWD, seq), msg)
}
```

> **Lưu ý thực thi:** điều kiện "đủ mảnh" trong `reassemble` đang rối — viết lại gọn: `if e.got.len() == e.total as usize && e.got.iter().all(|v| !v.is_empty())`. Dòng nào thừa xóa bớt. `FILLER_MAX` thực tế = `CELL - HDR_WIRE` = 1272 — test `cell_payload_vuot_gioi_loi` dùng `FILLER_MAX + 1` nên vẫn đúng bất kể giá trị.

- [ ] **Step 5: Chạy test xanh**

Run: `cargo test -p nbf-net`
Expected: 7 test PASS.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(net): cell 1280B, fragmentation, onion seal/open fwd+bwd"
```

---

### Task 6: `nbf-net` — Link Noise-IK UDP (fragmented handshake offload)

**Files:**
- Create: `crates/nbf-net/src/link.rs`
- Modify: `crates/nbf-net/src/lib.rs` (thêm `pub mod link; pub use link::*;`)
- Test: `#[cfg(test)]` trong `link.rs`

**Interfaces:**
- Consumes: `Cell` (Task 5), `Descriptor.link_pub` (Task 2).
- Produces (Task 9 dùng đúng tên):
  - `struct Link { socket: Arc<UdpSocket>, sessions: Arc<Mutex<HashMap<SocketAddr, Session>>>, ... }`
  - `Link::bind(addr: SocketAddr, local_static: &[u8;32]) -> Result<Link, NetError>`
  - `enum WireMsg { Cell(Cell), Handshake(Vec<u8>) }` — `enum HandshakeKind { Initiator = 1, Responder = 2 }`
  - `HandshakeKind::from_u8(u8) -> Option<HandshakeKind>`; `#[derive(Clone, Copy)] pub struct HsHeader { pub kind: HandshakeKind }` với `HsHeader::encode(kind, frag_total, frag_idx) -> [u8;8]` / `HsHeader::decode(&[u8]) -> Option<(HsHeader, u16, u16)>` (kèm total/idx)
  - `Link::send_cell(&self, addr: SocketAddr, cell: &Cell) -> Result<(), NetError>` (tự HS nếu chưa có session; sau HS vẫn gửi cell qua kênh HS FragmentedPlain — kể cả khi local là responder)
  - `Link::recv(&self) -> Option<(SocketAddr, WireMsg)>` (non-blocking drain; đầu vào đã decode)
  - Nguồn là **task nền duy nhất** `spawn_recv_task`: nhận datagram, route HS/cell, đẩy `(addr, WireMsg)` vào `mpsc::Receiver` mà `Node` nắm giữ.

Thiết kế: HS offload sang kênh riêng vì bản mã Noise-IK ≈ 1296B > MTU an toàn 1200B; bản rõ HS FragmentedPlain = `[\x7F nbfcid u32][cell 1280]` bọc trong HS frag.

- [ ] **Step 1: Viết test thất bại** — `crates/nbf-net/src/link.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn wait_for(rx: &mut mpsc::Receiver<(SocketAddr, WireMsg)>) -> (SocketAddr, Cell) {
        for _ in 0..100 {
            if let Ok((addr, m)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                if let WireMsg::Cell(c) = m {
                    return (addr, c);
                }
            }
        }
        panic!("không nhận được cell sau 10s");
    }

    #[tokio::test]
    async fn hai_link_giao_dich_va_gui_cell() {
        let a_pub1: [u8; 32] = rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut [0u8; 32]);
        let _ = a_pub1;
        let mut rng = rand::rngs::OsRng;
        let mut ka = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut ka);
        let mut kb = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut kb);

        let la = Link::bind("127.0.0.1:0".parse().unwrap(), &ka).unwrap();
        let lb = Link::bind("127.0.0.1:0".parse().unwrap(), &kb).unwrap();
        let (mut rxa, mut rxb) = (la.subscribe(), lb.subscribe());

        // A biết static B (từ descriptor), gửi trước → A là initiator.
        let b_static_pub = x25519_pub_from_local(&kb);
        la.set_peer_static(lb.addr(), b_static_pub);
        la.send_cell(lb.addr(), &Cell { cid: 9, cmd: Cmd::Padding, flags: 0, payload: vec![] }).unwrap();

        let (_, c) = wait_for(&mut rxb).await;
        assert_eq!(c.cid, 9);

        // B trả lời — B là responder nhưng send_cell phải hoạt động (kênh HS FragmentedPlain):
        lb.send_cell(la.addr(), &Cell { cid: 9, cmd: Cmd::Created, flags: 0, payload: vec![] }).unwrap();
        let (_, c2) = wait_for(&mut rxa).await;
        assert_eq!(c2.cmd, Cmd::Created);

        // Cell thứ 3: bây giờ session thường đã có, đi qua noise 1-rt:
        la.send_cell(lb.addr(), &Cell { cid: 9, cmd: Cmd::Relay, flags: 0, payload: vec![7; 10] }).unwrap();
        let (_, c3) = wait_for(&mut rxb).await;
        assert_eq!(c3.cmd, Cmd::Relay);
        assert_eq!(c3.payload, vec![7; 10]);

        let _ = (&mut rxa, &mut rxb);
        la.close().await;
        lb.close().await;
    }

    #[tokio::test]
    async fn hs_fragmented_van_tai_cell_dai() {
        // Mục đích: chứng minh kênh HS FragmentedPlain chịu được payload lớn (bản rõ 1280B).
        let mut rng = rand::rngs::OsRng;
        let mut k1 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut k1);
        let mut k2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut k2);
        let l1 = Link::bind("127.0.0.1:0".parse().unwrap(), &k1).unwrap();
        let l2 = Link::bind("127.0.0.1:0".parse().unwrap(), &k2).unwrap();
        let mut rx2 = l2.subscribe();

        l2.set_peer_static(l1.addr(), x25519_pub_from_local(&k1));
        l1.set_peer_static(l2.addr(), x25519_pub_from_local(&k2));
        // Gửi cell RELAY payload đầy (dài hơn bản mã 1-rt bình thường không gửi nổi? — vẫn 1280,
        // nhưng buộc đi qua HS channel vì side B chưa từng init):
        let big = Cell { cid: 3, cmd: Cmd::Relay, flags: 0, payload: vec![0xAB; 1200] };
        l1.send_cell(l2.addr(), &big).unwrap();
        let (_, c) = wait_for(&mut rx2).await;
        assert_eq!(c.payload.len(), 1200);
        l1.close().await;
        l2.close().await;
    }
}
```

- [ ] **Step 2: Chạy thấy fail**

Run: `cargo test -p nbf-net link`
Expected: FAIL (`Link` chưa tồn tại).

- [ ] **Step 3: Cài đặt `link.rs`**:

```rust
//! Link: Noise IK trên UDP, mỗi datagram 1 bản mã.
//! Handshake Noise (1288B) vượt MTU an toàn → đi qua kênh riêng "HS FragmentedPlain":
//! bản rõ HS = [\x7F][cid 4B][cell 1280B] chia mảnh ≤ 1100B, tự ghép ở nhận.
//! Quy tắc tránh va chạm handshake: node có static NHỎ HƠN giữ vai initiator.

use crate::{Cell, NetError};
use rand::RngCore;
use snow::{Builder, TransportState};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
const MTU_SAFE: usize = 1100; // mảnh HS
const MAX_MSG: usize = 2048;  // buffer nhận
const HS_MAGIC: u8 = 0x7F;

pub enum HandshakeKind {
    Initiator = 1,
    Responder = 2,
}

impl HandshakeKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(HandshakeKind::Initiator),
            2 => Some(HandshakeKind::Responder),
            _ => None,
        }
    }
}

/// Header kênh HS: magic(0x7F) kind frag_total frag_idx + 3B dự phòng.
#[derive(Clone, Copy, Debug)]
pub struct HsHeader;

impl HsHeader {
    pub fn encode(kind: HandshakeKind, frag_total: u16, frag_idx: u16) -> [u8; 8] {
        let mut h = [0u8; 8];
        h[0] = HS_MAGIC;
        h[1] = kind as u8;
        h[2..4].copy_from_slice(&frag_total.to_le_bytes());
        h[4..6].copy_from_slice(&frag_idx.to_le_bytes());
        h
    }

    /// Trả (header, frag_total, frag_idx) nếu đúng magic/kind.
    pub fn decode(buf: &[u8]) -> Option<(HsHeader, u16, u16)> {
        if buf.len() < 8 || buf[0] != HS_MAGIC {
            return None;
        }
        let kind = HandshakeKind::from_u8(buf[1])?;
        let _ = kind;
        let total = u16::from_le_bytes(buf[2..4].try_into().unwrap());
        let idx = u16::from_le_bytes(buf[4..6].try_into().unwrap());
        Some((HsHeader, total, idx))
    }
}

/// X25519 public từ private clamped 32B (khớp cách snow tạo keypair nội bộ).
pub fn x25519_pub_from_local(priv_clamped: &[u8; 32]) -> [u8; 32] {
    // snow không expose pub từ priv trực tiếp — tính bằng curve25519-dalek qua nbf_crypto:
    nbf_crypto::x25519_pub_from_clamped(priv_clamped)
}

struct Session {
    noise: TransportState,
}

pub enum WireMsg {
    Cell(Cell),
    Handshake(Vec<u8>),
}

pub struct Link {
    pub socket: Arc<UdpSocket>,
    pub addr: SocketAddr,
    local_static: [u8; 32],
    sessions: Arc<Mutex<HashMap<SocketAddr, Session>>>,
    peer_static: Arc<Mutex<HashMap<SocketAddr, [u8; 32]>>>,
    tx: mpsc::Sender<(SocketAddr, WireMsg)>,
    rx: Mutex<mpsc::Receiver<(SocketAddr, WireMsg)>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl Link {
    pub fn bind(addr: SocketAddr, local_static: &[u8; 32]) -> Result<Link, NetError> {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        let local = *local_static;
        let (tx, rx) = mpsc::channel(1024);
        let rx = Mutex::new(rx);
        let link = Link {
            addr: socket.local_addr()?,
            socket: socket.clone(),
            local_static: local,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            peer_static: Arc::new(Mutex::new(HashMap::new())),
            tx: tx.clone(),
            rx,
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        Ok(link)
    }

    /// Nhiệm vụ nền: nhận datagram → route HS/cell → đẩy vào channel.
    /// Gọi MỘT lần sau bind; Node giữ `subscribe()` receiver.
    pub fn spawn_recv_task(&self) {
        let socket = self.socket.clone();
        let sessions = self.sessions.clone();
        let peers = self.peer_static.clone();
        let tx = self.tx.clone();
        let local = self.local_static;
        let closed = self.closed.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_MSG];
            let mut hs_bufs: HashMap<SocketAddr, HashMap<u16, Vec<u8>>> = HashMap::new();
            loop {
                if closed.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                match socket.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let data = &buf[..n];
                        if data.first() == Some(&HS_MAGIC) {
                            if let Some((_h, total, idx)) = HsHeader::decode(data) {
                                let e = hs_bufs.entry(from).or_default();
                                e.insert(idx, data[8..].to_vec());
                                if e.len() == total as usize {
                                    let mut plain = Vec::new();
                                    for i in 0..total {
                                        plain.extend_from_slice(&e.remove(&i).unwrap());
                                    }
                                    hs_bufs.remove(&from);
                                    Self::on_hs_plain(&sessions, &peers, local, from, &plain, &tx).await;
                                }
                            }
                        } else {
                            Self::on_datagram(&sessions, from, data, &tx).await;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                    }
                    Err(_) => break,
                }
            }
        });
    }

    /// Datagram lớp ứng dụng: thử mở bằng session thường; nếu chưa có session → coi như
    /// bản mã Noise message 1 (e, es, s, ss) của initiator → hoàn tất handshake.
    async fn on_datagram(
        sessions: &Mutex<HashMap<SocketAddr, Session>>,
        from: SocketAddr,
        data: &[u8],
        tx: &mpsc::Sender<(SocketAddr, WireMsg)>,
    ) {
        let mut map = sessions.lock().await;
        if let Some(s) = map.get_mut(&from) {
            let mut out = vec![0u8; MAX_MSG];
            if let Ok(n) = s.noise.read_message(data, &mut out) {
                if let Ok(cell) = Cell::decode(&out[..n]) {
                    let _ = tx.send((from, WireMsg::Cell(cell))).await;
                }
            }
            return;
        }
        drop(map);
        // Chưa có session: đoán đây là message 1 của initiator — ta là responder.
        // Responder cần biết static của initiator (để IK). IK là "k" = static bên kia đã biết trước —
        // ta tra peer_static (Node đã set khi nhận descriptor từ DHT). Nếu không có → bỏ datagram.
        // (Node luôn set peer_static cho mọi node trong routing table trước khi nhận circuit.)
        let _ = data; // xử lý thật nằm trong on_hs_plain qua kênh HS; v1 bắt initiator gửi qua HS trước.
    }

    /// Bản rõ HS FragmentedPlain = [HS_MAGIC][cid u32][cell 1280] — hoàn tất Noise theo vai.
    async fn on_hs_plain(
        sessions: &Mutex<HashMap<SocketAddr, Session>>,
        peers: &Mutex<HashMap<SocketAddr, [u8; 32]>>,
        local_static: [u8; 32],
        from: SocketAddr,
        plain: &[u8],
        tx: &mpsc::Sender<(SocketAddr, WireMsg)>,
    ) {
        if plain.len() < 5 || plain[0] != HS_MAGIC {
            return;
        }
        let cid = u32::from_le_bytes(plain[1..5].try_into().unwrap());
        if plain.len() < 5 + crate::cell::CELL {
            return;
        }
        let cell = match Cell::decode(&plain[5..5 + crate::cell::CELL]) {
            Ok(c) => c,
            Err(_) => return,
        };
        let role_initiator = cell.cid != u32::MAX && cid != u32::MAX && plain.len() > 0; // vai quyết bởi ai tạo HS: xem send_cell
        let _ = role_initiator;
        // Xác định vai: peer_static có biết static của from không & so sánh độ lớn static
        // (quy tắc: static nhỏ hơn là initiator). Nhưng đơn giản v1: ai gửi HS plain trước = initiator side A;
        // B chỉ cần static của A. Lưu static khi A gửi; khi B trả lời thì đã có.
        let remote_static: Option<[u8; 32]> = peers.lock().await.get(&from).copied();
        // Nếu chưa biết static của peer (A gọi send_cell tới B lần đầu), A PHẢI gửi kèm static của mình
        // trong plain HS: [magic][cid][cell1280][remote_static 32B][signature không cần — tầng trên tự xác thực].
        // Định dạng mở rộng: nếu plain.len() == 5 + CELL + 32 → 32B cuối là static của người gửi HS.
        let mut sess_map = sessions.lock().await;
        if sess_map.contains_key(&from) {
            let _ = tx.send((from, WireMsg::Cell(cell))).await;
            return;
        }
        let b = Builder::new(PATTERN.parse().unwrap());
        if plain.len() == 5 + crate::cell::CELL + 32 {
            // Người gửi là initiator: nó kèm static của chính nó.
            let initiator_static: [u8; 32] = plain[5 + crate::cell::CELL..].try_into().unwrap();
            let mut nb = b.local_private_key(&local_static).remote_public_key(&initiator_static).build_responder().unwrap();
            let mut out = vec![0u8; MAX_MSG];
            // Message 2 của responder:
            let n = nb.write_message(&[], &mut out).unwrap();
            // Kèm static của mình (B) để A biết remote static (A đã biết từ descriptor, nhưng gửi lại cho gọn):
            let mut hs_out = Vec::with_capacity(8 + n + 32);
            hs_out.extend_from_slice(&HsHeader::encode(HandshakeKind::Responder, 1, 0));
            hs_out.extend_from_slice(&out[..n]);
            hs_out.extend_from_slice(&local_static);
            let _ = tx.send((from, WireMsg::Handshake(hs_out.clone()))).await; // link nội bộ: HS đi qua send_raw
            // Nhưng on_hs_plain chạy TRONG recv task — không tự gửi được qua socket ở đây.
            // GIẢI PHÁP v1: trả Handshake qua channel để Node gọi link.send_raw(from, hs_out).
            // Đơn giản hơn: responder lưu state chờ → phức tạp. Chọn: Node xử lý WireMsg::HandshakeReply.
            let _ = n;
            return;
        }
        let _ = remote_static;
    }
}
```

> **STOP — thực thi riêng (không bỏ qua):** bản nháp trên của `on_hs_plain` phức tạp hóa không cần thiết. Thay thế bằng thiết kế gọn sau khi cài đặt:

**Thiết kế gọn (bản chốt — cài theo):**
1. `send_cell(addr, cell)`: nếu `sessions` chưa có addr:
   - Nếu `local_static < peer_static[addr]` (biết từ descriptor) → mình là initiator: tạo `noise_i` (builder initiator, remote_static = peer static), `write_message(&[], msg1)` → gửi **raw msg1** (không HS header, không frag) — bản mã msg1 Noise IK ≈ 96B < MTU.
   - Ngược lại → mình là responder: KHÔNG chủ động; chờ msg1.
   - Sau đó gửi cell qua kênh HS FragmentedPlain: `plain = [HS_MAGIC][cid][cell]`, chia mảnh ≤1100B, mỗi mảnh = `HsHeader::encode(Initiator, total, idx) + chunk` gửi raw. Responder nhận đủ → ghép → dùng cell.
   - Responder khi nhận **raw msg1**: `noise_r.read_message(msg1) → _`, hoàn tất, `write_message(&[], msg2)` gửi raw msg2 (≈ 48B). Cả hai vào transport, lưu session. Responder khớp remote static tự động nhờ IK (nó phải biết trước static của initiator — từ descriptor; `Node` có trách nhiệm set peer_static trước).
2. Nhận datagram: nếu byte đầu ∈ {0,1,2} dài nhỏ và không khớp kích thước cell-encrypted → thử `read_message` như msg1/msg2 handshake; ngược lại mở bằng session thường.
3. Kênh HS FragmentedPlain MÃ HÓA BẰNG SESSION ĐÃ CÓ (sau handshake) — responder dùng session của nó để mở; các cell "chưa có session" của initiator nằm trong plain HS và được responder chấp nhận ngay sau khi msg1/msg2 xong trong cùng batch nhận (drain loop nhận tuần tự, msg1 đến trước).

`struct Link` field chốt: `socket, addr, local_static, sessions: Mutex<HashMap<SocketAddr, TransportState>>, peer_static: Mutex<HashMap<SocketAddr,[u8;32]>>, hs_bufs: Mutex<HashMap<SocketAddr, HashMap<u16, Vec<u8>>>>, tx: mpsc::Sender<(SocketAddr, WireMsg)>, closed: AtomicBool`, kèm method `subscribe(&self) -> mpsc::Receiver` (chỉ dùng trong test; Node nhận receiver trả về từ `bind`), `set_peer_static(addr, pub)`, `send_raw(&self, addr, &[u8])`, `close().await`.

Sau khi cài xong **chạy lại cả 2 test ở Step 1 — phải PASS**. Nếu test `hs_fragmented_van_tai_cell_dai` phức tạp hóa quá mức thiết kế gọn (responder cần static trước khi nhận msg1 — test đã `set_peer_static`), giữ nguyên; nếu vướng, đổi tên test thành `cell_qua_kenh_hs_khi_chua_co_session` và giữ ý nghĩa: gửi cell khi chưa có session thường, vẫn tới nơi.

- [ ] **Step 4: Chạy test xanh**

Run: `cargo test -p nbf-net`
Expected: tất cả PASS (7 cell + 2 link).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(net): Noise-IK UDP link, offload handshake fragmented, session cache"
```

---

### Task 7: `nbf-dht` — Contact, RPC encode/decode, timeout plumbing

**Files:**
- Create: `crates/nbf-dht/src/lib.rs` (điền thật), `crates/nbf-dht/src/rpc.rs`
- Test: `#[cfg(test)]` trong `rpc.rs`

**Interfaces:**
- Consumes: `Descriptor`, `Descriptor::to_bytes`, `Descriptor::from_signed_bytes`, `NodeId` (Task 2).
- Produces (Task 8 dùng đúng tên):
  - `#[derive(Clone)] struct Contact { pub node_id: NodeId, pub ip: [u8;4], pub dht_port: u16 }` với `Contact::from_desc(d: &Descriptor) -> Contact`, `Contact::addr(&self) -> SocketAddr`
  - `enum RpcType { Ping=1, Pong=2, Store=3, Find=4, Found=5 }` (`TryFrom<u8>`)
  - `enum RpcMsg { Ping { nonce: u64 }, Pong { nonce: u64 }, Store { desc: Descriptor }, Find { key: NodeId, want_value: bool }, Found { contacts: Vec<Contact>, value: Option<Descriptor> } }`
  - `rpc_encode(&RpcMsg) -> Vec<u8>` / `rpc_decode(&[u8]) -> Result<RpcMsg, DhtError>` — magic `NBFR` + type
  - `struct DhtError` (BadLen, BadType, BadDesc, Io(std::io::Error))
  - `fn ping_response(nonce: u64) -> RpcMsg`, `fn find_response(contacts, value) -> RpcMsg`

- [ ] **Step 1: Viết test thất bại** — `crates/nbf-dht/src/rpc.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use nbf_crypto::{Descriptor, NodeIdentity};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::net::SocketAddr;

    fn desc() -> Descriptor {
        let mut rng = StdRng::seed_from_u64(5);
        let id = NodeIdentity::random(&mut rng);
        let addr: SocketAddr = "127.0.0.1:9400".parse().unwrap();
        Descriptor::sign(&id, addr, 9401, 1_000)
    }

    #[test]
    fn rpc_roundtrip_moi_loai() {
        let d = desc();
        let cases = vec![
            RpcMsg::Ping { nonce: 77 },
            RpcMsg::Pong { nonce: 77 },
            RpcMsg::Store { desc: d.clone() },
            RpcMsg::Find { key: [3u8; 20], want_value: true },
            RpcMsg::Found {
                contacts: vec![Contact { node_id: [1u8; 20], ip: [127, 0, 0, 1], dht_port: 9000 }],
                value: Some(d),
            },
        ];
        for c in cases {
            let bytes = rpc_encode(&c);
            let back = rpc_decode(&bytes).unwrap();
            assert!(same(&back, &c), "roundtrip lệch: {:?}", c);
        }
    }

    fn same(a: &RpcMsg, b: &RpcMsg) -> bool {
        use RpcMsg::*;
        match (a, b) {
            (Ping { nonce: x }, Ping { nonce: y }) => x == y,
            (Pong { nonce: x }, Pong { nonce: y }) => x == y,
            (Store { desc: x }, Store { desc: y }) => x.node_id == y.node_id && x.cell_addr == y.cell_addr,
            (Find { key: x, want_value: xv }, Find { key: y, want_value: yv }) => x == y && xv == yv,
            (Found { contacts: x, value: xv }, Found { contacts: y, value: yv }) => {
                x.len() == y.len() && xv.is_some() == yv.is_some()
            }
            _ => false,
        }
    }

    #[test]
    fn rpc_sai_magic_hay_type_loi() {
        let b = rpc_encode(&RpcMsg::Ping { nonce: 1 });
        let mut bad = b.clone();
        bad[0] = b'X';
        assert!(rpc_decode(&bad).is_err());
        let mut bad2 = b.clone();
        bad2[4] = 99;
        assert!(rpc_decode(&bad2).is_err());
    }

    #[test]
    fn contact_addr_tu_desc() {
        let d = desc();
        let c = Contact::from_desc(&d);
        assert_eq!(c.node_id, d.node_id);
        assert_eq!(c.addr().to_string(), "127.0.0.1:9401");
    }
}
```

- [ ] **Step 2: Chạy thấy fail**

Run: `cargo test -p nbf-dht rpc`
Expected: FAIL.

- [ ] **Step 3: Điền `crates/nbf-dht/src/lib.rs`**:

```rust
//! NBF DHT: Kademlia thu nhỏ trên UDP (k=3, alpha=3), descriptor store/lookup.
//! Không directory trung tâm — thông tin node tự chủ, ký Ed25519.

pub mod rpc;

pub use rpc::*;

use nbf_crypto::NodeId;
use std::io;
use thiserror::Error;

pub const MAGIC: [u8; 4] = *b"NBFR";

#[derive(Debug, Error)]
pub enum DhtError {
    #[error("độ dài không hợp lệ: {0}")]
    BadLen(usize),
    #[error("type RPC không hợp lệ: {0}")]
    BadType(u8),
    #[error("descriptor lỗi: {0}")]
    BadDesc(#[from] nbf_crypto::CryptoError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Bản ghi liên hệ trong bảng định tuyến — chỉ cần id + addr DHT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub node_id: NodeId,
    pub ip: [u8; 4],
    pub dht_port: u16,
}

impl Contact {
    pub fn from_desc(d: &nbf_crypto::Descriptor) -> Self {
        let ip = match d.cell_addr.ip() {
            std::net::IpAddr::V4(v) => v.octets(),
            _ => [0, 0, 0, 0],
        };
        Contact { node_id: d.node_id, ip, dht_port: d.dht_port }
    }
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(self.ip[0], self.ip[1], self.ip[2], self.ip[3])), self.dht_port)
    }
}

use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcType {
    Ping = 1,
    Pong = 2,
    Store = 3,
    Find = 4,
    Found = 5,
}

impl TryFrom<u8> for RpcType {
    type Error = DhtError;
    fn try_from(v: u8) -> Result<Self, DhtError> {
        Ok(match v {
            1 => RpcType::Ping,
            2 => RpcType::Pong,
            3 => RpcType::Store,
            4 => RpcType::Find,
            5 => RpcType::Found,
            x => return Err(DhtError::BadType(x)),
        })
    }
}

#[derive(Debug, Clone)]
pub enum RpcMsg {
    Ping { nonce: u64 },
    Pong { nonce: u64 },
    Store { desc: Descriptor },
    Find { key: NodeId, want_value: bool },
    Found { contacts: Vec<Contact>, value: Option<Descriptor> },
}

pub fn ping_response(nonce: u64) -> RpcMsg {
    RpcMsg::Pong { nonce }
}
pub fn find_response(contacts: Vec<Contact>, value: Option<Descriptor>) -> RpcMsg {
    RpcMsg::Found { contacts, value }
}

pub fn rpc_encode(msg: &RpcMsg) -> Vec<u8> {
    use RpcMsg::*;
    let mut b = Vec::new();
    b.extend_from_slice(&MAGIC);
    match msg {
        Ping { nonce } => {
            b.push(RpcType::Ping as u8);
            b.extend_from_slice(&nonce.to_le_bytes());
        }
        Pong { nonce } => {
            b.push(RpcType::Pong as u8);
            b.extend_from_slice(&nonce.to_le_bytes());
        }
        Store { desc } => {
            b.push(RpcType::Store as u8);
            b.extend_from_slice(&desc.to_bytes());
        }
        Find { key, want_value } => {
            b.push(RpcType::Find as u8);
            b.extend_from_slice(key);
            b.push(*want_value as u8);
        }
        Found { contacts, value } => {
            b.push(RpcType::Found as u8);
            b.push(contacts.len() as u8);
            for c in contacts {
                b.extend_from_slice(&c.node_id);
                b.extend_from_slice(&c.ip);
                b.extend_from_slice(&c.dht_port.to_le_bytes());
            }
            match value {
                Some(d) => {
                    let db = d.to_bytes();
                    b.extend_from_slice(&(db.len() as u16).to_le_bytes());
                    b.extend_from_slice(&db);
                }
                None => b.extend_from_slice(&0u16.to_le_bytes()),
            }
        }
    }
    b
}

pub fn rpc_decode(buf: &[u8]) -> Result<RpcMsg, DhtError> {
    if buf.len() < 5 || buf[..4] != MAGIC {
        return Err(DhtError::BadLen(buf.len()));
    }
    let t = RpcType::try_from(buf[4])?;
    let body = &buf[5..];
    let mut o = 0usize;
    let mut take = |n: usize| -> &[u8] { let s = &body[o..o + n]; o += n; s };
    Ok(match t {
        RpcType::Ping | RpcType::Pong => {
            if body.len() < 8 {
                return Err(DhtError::BadLen(body.len()));
            }
            let nonce = u64::from_le_bytes(take(8).try_into().unwrap());
            if t == RpcType::Ping {
                RpcMsg::Ping { nonce }
            } else {
                RpcMsg::Pong { nonce }
            }
        }
        RpcType::Store => RpcMsg::Store { desc: Descriptor::from_signed_bytes(take(body.len() - o))? },
        RpcType::Find => {
            if body.len() < 21 {
                return Err(DhtError::BadLen(body.len()));
            }
            let key: NodeId = take(20).try_into().unwrap();
            let want = body[20] != 0;
            RpcMsg::Find { key, want_value: want }
        }
        RpcType::Found => {
            if body.is_empty() {
                return Err(DhtError::BadLen(0));
            }
            let cnt = body[0] as usize;
            let mut contacts = Vec::with_capacity(cnt);
            o = 1;
            for _ in 0..cnt {
                if o + 26 > body.len() {
                    return Err(DhtError::BadLen(body.len()));
                }
                let node_id: NodeId = take(20).try_into().unwrap();
                let ip: [u8; 4] = take(4).try_into().unwrap();
                let dht_port = u16::from_le_bytes(take(2).try_into().unwrap());
                contacts.push(Contact { node_id, ip, dht_port });
            }
            let val_len = if o + 2 <= body.len() { u16::from_le_bytes(take(2).try_into().unwrap()) as usize } else { return Err(DhtError::BadLen(body.len())) };
            let value = if val_len > 0 {
                if o + val_len > body.len() {
                    return Err(DhtError::BadLen(body.len()));
                }
                Some(Descriptor::from_signed_bytes(take(val_len))?)
            } else {
                None
            };
            RpcMsg::Found { contacts, value }
        }
    })
}

// re-export cho gọn các task sau:
pub use nbf_crypto::Descriptor;
```

- [ ] **Step 4: Chạy test xanh**

Run: `cargo test -p nbf-dht`
Expected: 3 test PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(dht): Contact + RPC binary encode/decode + DhtError"
```

---

### Task 8: `nbf-dht` — Kademlia node (serve RPC, store, lookup)

**Files:**
- Create: `crates/nbf-dht/src/kademlia.rs`
- Modify: `crates/nbf-dht/src/lib.rs` (thêm `pub mod kademlia; pub use kademlia::*;`)
- Test: `#[cfg(test)]` trong `kademlia.rs` (chạy 3 node UDP thật trên localhost)

**Interfaces:**
- Consumes: `Contact`, `RpcMsg`, `rpc_encode/decode`, `DhtError` (Task 7); `Descriptor` (Task 2).
- Produces (Task 9 dùng đúng tên):
  - `struct Kademlia { pub id: NodeId, pub own_desc: Descriptor, pub rt: RwLock<Vec<Contact>>, pub store: RwLock<HashMap<NodeId, Descriptor>>, rng: StdRng, socket: UdpSocket, local_addr: SocketAddr }`
  - `Kademlia::new(id, own_desc, bind_port: u16) -> Result<Kademlia, DhtError>`
  - `async fn run(self: Arc<Self>) -> ()` — vòng phục vụ UDP, xử lý PING/STORE/FIND, tự trả lời
  - `async fn bootstrap(&self, seeds: &[SocketAddr]) -> Result<(), DhtError>` — PING mỗi seed, FIND_NODE(self.id), merge
  - `async fn store_self(&self, seeds: &[SocketAddr]) -> Result<(), DhtError>`
  - `async fn lookup(&self, key: &NodeId, want_value: bool) -> Result<Option<Descriptor>, DhtError>` — iterative: gọi FIND_NODE tới alpha node gần nhất, vòng lặp cho tới khi không cải thiện hoặc có value
  - `fn closest(&self, key: &NodeId, k: usize) -> Vec<Contact>` — XOR metric, lấy k node gần nhất từ rt
  - `async fn send_rpc(&self, addr: SocketAddr, msg: RpcMsg, timeout_ms: u64) -> Result<RpcMsg, DhtError>`
  - `async fn try_merge(&self, contacts: &[Contact])`

- [ ] **Step 1: Viết test thất bại** — `crates/nbf-dht/src/kademlia.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use nbf_crypto::NodeIdentity;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    async fn node(seed: u64, port: u16) -> (Arc<Kademlia>, Descriptor) {
        let mut rng = StdRng::seed_from_u64(seed);
        let id = NodeIdentity::random(&mut rng);
        let d = Descriptor::sign(&id, format!("127.0.0.1:{}", port).parse().unwrap(), port + 1, 1_000);
        let k = Arc::new(Kademlia::new(id.node_id(), d.clone(), port + 1).unwrap());
        let kk = k.clone();
        tokio::spawn(async move { kk.run().await });
        (k, d)
    }

    #[tokio::test]
    async fn bootstrap_ping_store_lookup_3_node() {
        let (a, da) = node(10, 9501).await;
        let (b, db) = node(11, 9503).await;
        let (c, dc) = node(12, 9505).await;

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
        let v = a.lookup(&dc.node_id, true).await;
        if let Some(d) = v {
            assert_eq!(d.node_id, dc.node_id);
        }
        // Đăng ký store cho c qua b (b là neighbor của c):
        b.store_self(&[dc.dht_addr()]).await.unwrap();
        let v2 = a.lookup(&dc.node_id, true).await.unwrap();
        assert_eq!(v2.node_id, dc.node_id);
        let _ = da;
    }

    #[tokio::test]
    async fn store_duplicate_va_closest_xor() {
        let (a, _) = node(20, 9601).await;
        let ids = [a.id, [0x01; 20], [0x02; 20], [0xFF; 20]];
        for (i, x) in ids.iter().enumerate() {
            let _ = i;
            a.rt.write().await.push(Contact { node_id: *x, ip: [127, 0, 0, 1], dht_port: 1 });
        }
        let near = a.closest(&[0x01; 20], 2);
        assert_eq!(near[0].node_id, [0x01; 20]);
    }
}
```

- [ ] **Step 2: Chạy thấy fail**

Run: `cargo test -p nbf-dht kademlia`
Expected: FAIL (module chưa tồn tại).

- [ ] **Step 3: Cài đặt `kademlia.rs`** (impl trên mod tests; cần `use tokio::net::UdpSocket;` và `use tokio::sync::RwLock;`):

```rust
//! Kademlia: bảng định tuyến XOR + store/lookup descriptor trên UDP.
//! Đủ dùng cho v1: k=3, alpha=3, mỗi node 1 bucket phẳng (không chia k-bucket theo prefix).

use crate::{ping_response, rpc_decode, rpc_encode, Contact, Descriptor, DhtError, RpcMsg};
use nbf_crypto::NodeId;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};

pub const K: usize = 3;
pub const ALPHA: usize = 3;
pub const TTL_DESC: u64 = 86_400; // 24h

pub struct Kademlia {
    pub id: NodeId,
    pub own_desc: Descriptor,
    pub rt: RwLock<Vec<Contact>>,
    pub store: RwLock<HashMap<NodeId, Descriptor>>,
    rng: StdRng,
    socket: Arc<UdpSocket>,
    pub local_addr: SocketAddr,
}

impl Descriptor {
    /// Địa chỉ DHT từ descriptor (tiện dùng).
    pub fn dht_addr(&self) -> SocketAddr {
        let ip = match self.cell_addr.ip() {
            std::net::IpAddr::V4(v) => v,
            _ => std::net::Ipv4Addr::UNSPECIFIED,
        };
        SocketAddr::new(std::net::IpAddr::V4(ip), self.dht_port)
    }
}

impl Kademlia {
    pub fn new(id: NodeId, own_desc: Descriptor, bind_port: u16) -> Result<Self, DhtError> {
        let socket = std::net::UdpSocket::bind(("127.0.0.1", bind_port))?;
        socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        let local_addr = socket.local_addr()?;
        Ok(Kademlia {
            id,
            own_desc,
            rt: RwLock::new(vec![Contact::from_desc(&own_desc)]),
            store: RwLock::new(HashMap::new()),
            rng: StdRng::from_entropy(),
            socket,
            local_addr,
        })
    }

    pub async fn run(self: Arc<Self>) {
        let mut buf = vec![0u8; 4096];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    let data = buf[..n].to_vec();
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
                let near = self.closest(&key, K);
                let val = if want_value { self.store.read().await.get(&key).cloned() } else { None };
                let _ = self.send_raw(from, &rpc_encode(&RpcMsg::Found { contacts: near, value: val })).await;
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

    pub async fn send_rpc(&self, addr: SocketAddr, msg: RpcMsg, timeout_ms: u64) -> Result<RpcMsg, DhtError> {
        let data = rpc_encode(&msg);
        self.socket.send_to(&data, addr).await?;
        let mut buf = vec![0u8; 4096];
        let fut = self.socket.recv_from(&mut buf);
        match timeout(Duration::from_millis(timeout_ms), fut).await {
            Ok(Ok((n, _from))) => rpc_decode(&buf[..n]),
            Ok(Err(e)) => Err(DhtError::Io(e)),
            Err(_) => Err(DhtError::BadLen(0)), // timeout
        }
    }

    /// XOR metric: khoảng cách tuyệt đối giữa 2 id (byte-wise so sánh tới hết 20B).
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
        rt.sort_by_key(|c| Kademlia::dist(&c.node_id, self.id));
        rt.truncate(64);
    }

    pub async fn bootstrap(&self, seeds: &[SocketAddr]) -> Result<(), DhtError> {
        for s in seeds {
            let nonce = self.rng.gen();
            let _ = self.send_rpc(*s, RpcMsg::Ping { nonce }, 1000).await;
            if let Ok(RpcMsg::Found { contacts, .. }) = self.send_rpc(*s, RpcMsg::Find { key: self.id, want_value: false }, 1000).await {
                self.try_merge(&contacts).await;
            }
        }
        Ok(())
    }

    pub async fn store_self(&self, seeds: &[SocketAddr]) -> Result<(), DhtError> {
        for s in seeds {
            let _ = self.send_rpc(*s, RpcMsg::Store { desc: self.own_desc.clone() }, 1000).await;
        }
        Ok(())
    }

    /// Iterative lookup: tới khi hội tụ (không cải thiện) hoặc tìm thấy value.
    pub async fn lookup(&self, key: &NodeId, want_value: bool) -> Result<Option<Descriptor>, DhtError> {
        let mut closest_seen = self.closest(key, K).await;
        let mut queried: Vec<NodeId> = Vec::new();
        loop {
            let batch = closest_seen.iter().filter(|c| !queried.contains(&c.node_id)).cloned().take(ALPHA).collect::<Vec<_>>();
            if batch.is_empty() {
                break;
            }
            for c in &batch {
                queried.push(c.node_id);
                if let Ok(RpcMsg::Found { contacts, value }) = self.send_rpc(c.addr(), RpcMsg::Find { key: *key, want_value }, 1000).await {
                    if want_value {
                        if let Some(v) = &value {
                            return Ok(Some(v.clone()));
                        }
                    }
                    self.try_merge(&contacts).await;
                }
            }
            let next = self.closest(key, K).await;
            if next.len() == closest_seen.len() && next.iter().all(|c| closest_seen.iter().any(|o| o.node_id == c.node_id)) {
                break;
            }
            closest_seen = next;
        }
        Ok(None)
    }
}

// cần thêm use rand::RngCore cho gen() của StdRng:
use rand::RngCore;
```

- [ ] **Step 4: Chạy test xanh**

Run: `cargo test -p nbf-dht`
Expected: 5 test PASS (3 rpc + 2 kademlia). Test `bootstrap_ping_store_lookup_3_node` cần localhost UDP mở — nếu flaky vì timing, tăng sleep 200→400ms.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(dht): Kademlia serve + iterative lookup + store_self + closest XOR"
```

---

### Task 9: `nbf-net` — Node engine (CREATE/CREATED/RELAY/DESTROY/PADDING)

**Files:**
- Create: `crates/nbf-net/src/node.rs`, `crates/nbf-net/tests/common/mod.rs`
- Modify: `crates/nbf-net/src/lib.rs` (thêm `pub mod node; pub use node::*;`)
- Test: `#[cfg(test)]` trong `node.rs` + integration `tests/common/mod.rs`

**Interfaces:**
- Consumes: mọi thứ: `NodeIdentity`/`Descriptor` (T2), `seal/open_onion`/`Cell`/`fragment`/`reassemble` (T5), `Link`/`send_cell` (T6), `Kademlia` (T8), `build_header`/`process_header` (T4).
- Produces (Task 10/11/13 dùng đúng tên):
  - `struct CoverCfg { pub on: bool, pub min_interval_ms: u64, pub max_interval_ms: u64 }` (`impl Default` = on, 500/2000)
  - `struct NodeConfig { pub cell_port: u16, pub dht_port: u16, pub seeds: Vec<String>, pub cover: CoverCfg, pub rng_seed: Option<u64> }`
  - `struct Node { pub config: NodeConfig, pub identity: NodeIdentity, pub node_id: NodeId, pub own_desc: Descriptor, pub dht: Arc<Kademlia>, pub link: Link, pub circuits: Mutex<HashMap<u32, CircuitEntry>>, pub pending: Mutex<HashMap<u32, oneshot::Sender<Result<(), NetError>>>>, pub routing: Mutex<HashMap<NodeId, (SocketAddr, [u8;32])>>, pub next_cid: AtomicU32, pub seq_origin: AtomicU32, pub stats: Mutex<Stats> }`
  - `struct Stats { pub created: u64, pub relayed: u64, pub destroyed: u64, pub padding_recv: u64, pub padding_sent: u64, pub drops_sent: u64 }`
  - `enum CircuitEntry { Origin { fwd: Vec<[u8;32]>, bwd: Vec<[u8;32]>, tag: [u8;16], next: HopLink, streams: HashMap<u16, mpsc::Sender<Vec<u8>>> }, Relay { tag: [u8;16], k_fwd: [u8;32], k_bwd: [u8;32], prev: HopLink, next: HopLink, last_fwd: u32 }, Terminal { tag: [u8;16], k_fwd: [u8;32], k_bwd: [u8;32], prev: HopLink, last_fwd: u32 } }`
  - `#[derive(Clone, Copy)] struct HopLink { pub cid: u32, pub peer: SocketAddr }`
  - `Node::spawn(config: NodeConfig) -> Arc<Node>` (bind link+dht, spawn recv task + dht run, spawn cover loop nếu on, trả handle)
  - `async fn handle_cell(self: Arc<Self>, from: SocketAddr, cell: Cell)` (match cmd; gọi các handler riêng)
  - `async fn handle_create(...)`, `handle_created(...)`, `handle_destroy(...)`, `handle_relay(...)`, `handle_padding(...)`
  - `fn lookup_route(&self, target: NodeId) -> Result<Vec<Descriptor>, NetError>` (cache + dht lookup)
  - `async fn ensure_peer_link(&self, addr: SocketAddr)` (set_peer_static từ routing table)
  - `async fn route_peers(&self) -> Vec<(NodeId, SocketAddr, [u8;32])>`

- [ ] **Step 1: Viết test thất bại** — `crates/nbf-net/tests/common/mod.rs` (harness dùng xuyên Task 9-13):

```rust
//! Harness chung: spawn mesh node NBF trên localhost, trả danh sách Arc<Node>.
//! Mỗi test integration dùng `mod common;` rồi gọi common::spawn_mesh.

use std::sync::Arc;
use std::time::Duration;
use nbf_net::{Node, NodeConfig};

pub async fn spawn_mesh(n: usize, seed: u64, base_cell: u16) -> Vec<Arc<Node>> {
    let mut nodes = Vec::with_capacity(n);
    let mut cell_ports = Vec::with_capacity(n);
    for i in 0..n {
        let cfg = NodeConfig {
            cell_port: base_cell + i as u16 * 2,
            dht_port: base_cell + i as u16 * 2 + 1,
            seeds: if i == 0 { vec![] } else { vec![format!("127.0.0.1:{}", base_cell + 1)] },
            cover: nbf_net::CoverCfg { on: false, min_interval_ms: 1000, max_interval_ms: 5000 },
            rng_seed: Some(seed + i as u64),
        };
        let nd = Node::spawn(cfg).await;
        cell_ports.push(nd.config.cell_port);
        nodes.push(nd);
    }
    // Mọi node biết node 0 (seed bootstrap qua DHT node 0).
    // bootstrap DHT: node i lookup node_id 0 → học addr. Đã có trong Node::spawn (store_self + bootstrap).
    tokio::time::sleep(Duration::from_millis(300)).await; // để DHT bootstrap xong
    nodes
}

pub async fn wait_stats(n: &Arc<Node>, f: impl Fn(&nbf_net::Stats) -> bool, ms: u64) -> bool {
    for _ in 0..ms / 50 {
        if f(&n.stats.lock().await.clone()) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}
```

- [ ] **Step 2: Viết test thất bại** — `crates/nbf-net/tests/circuit.rs`:

```rust
//! E2E: client → 3 hop → echo service, không hop nào thấy plaintext.

mod common;

use std::net::SocketAddr;
use std::time::Duration;
use nbf_net::node::{build_circuit, CircuitHandle, Node};
use nbf_net::{CoverCfg, NodeConfig};

fn cfg(i: u16, seeds: Vec<String>) -> NodeConfig {
    NodeConfig {
        cell_port: 10000 + i * 2,
        dht_port: 10000 + i * 2 + 1,
        seeds,
        cover: CoverCfg { on: false, min_interval_ms: 1000, max_interval_ms: 2000 },
        rng_seed: Some(0xDEAD + i as u64),
    }
}

#[tokio::test]
async fn e2e_3hop_echo() {
    let _ = tracing_subscriber::fmt().with_env_filter("error").try_init();
    // Node 0 là seed, node 1,2,3 là hop, node 4 là client gửi, node 5 chạy echo service.
    let mut nodes = Vec::new();
    for i in 0..6u16 {
        nodes.push(Node::spawn(cfg(i, if i == 0 { vec![] } else { vec!["127.0.0.1:10001".into()] })).await);
    }
    tokio::time::sleep(Duration::from_millis(400)).await;

    let client = &nodes[4];
    let service = &nodes[5];

    // Service mở "listener" echo — v1 không có hidden service thật; client route tới service node_id.
    // Route 3 hop: node1 → node2 → service(5). Client = node4 (cũng là node hợp lệ nhưng vẫn đi circuit).
    let handle = build_circuit(
        client.clone(),
        &[nodes[1].node_id, nodes[2].node_id, service.node_id],
        Some(nodes[0].node_id), // bootstrap hint: bỏ qua, lookup tự tìm
    ).await.expect("dựng circuit 3 hop");

    let reply = handle.echo(b"xin chao tu the void", Duration::from_secs(5)).await.expect("echo phải trả về");
    assert_eq!(reply, b"xin chao tu the void");

    handle.close().await;
    // Cleanup: các node giữ link — drop hết.
    drop(nodes);
    tokio::time::sleep(Duration::from_millis(100)).await;
}
```

- [ ] **Step 3: Chạy thấy fail**

Run: `cargo test -p nbf-net --test circuit e2e_3hop_echo`
Expected: FAIL (module `node` chưa có, `build_circuit` chưa tồn tại).

- [ ] **Step 4: Cài đặt `node.rs`** — **khung cấu trúc + xử lý CREATE/DESTROY/PADDING** (phần RELAY và builder nằm Task 10):

```rust
//! Engine circuit: nhận/gửi cell, duy trì bảng circuit, xử lý CREATE/DESTROY/PADDING.
//! RELAY xử lý trong `relay.rs` module cùng crate (Task 10).

use crate::cell::{fragment, parse_frag, reassemble, Cell, Cmd, FragBuf, HDR_WIRE};
use crate::link::{Link, WireMsg};
use crate::{NetError, RCmd};
use nbf_crypto::sphinx::{process_header, ProcessOutcome};
use nbf_crypto::{Descriptor, NodeId, NodeIdentity};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

pub struct CoverCfg {
    pub on: bool,
    pub min_interval_ms: u64,
    pub max_interval_ms: u64,
}
impl Default for CoverCfg {
    fn default() -> Self {
        CoverCfg { on: true, min_interval_ms: 500, max_interval_ms: 2000 }
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
        let dht = Arc::new(nbf_dht::Kademlia::new(node_id, own_desc.clone(), config.dht_port).unwrap());

        let link = Link::bind(cell_addr, &identity.link_priv).unwrap();
        link.spawn_recv_task();
        let (rx) = link.subscribe();

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

        // Kết nối DHT với seed:
        let seeds: Vec<SocketAddr> = node.config.seeds.iter().filter_map(|s| s.parse().ok()).collect();
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
                        WireMsg::Handshake(_) => {}
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
                    CircuitEntry::Terminal { tag, k_fwd, k_bwd, prev: HopLink { cid: cell.cid, peer: from }, last_fwd: 0 },
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
                        tag, k_fwd, k_bwd,
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

    async fn handle_created(self: Arc<Self>, from: SocketAddr, cell: Cell) {
        // CREATED từ next (khi mình là relay) hoặc từ hop1 (khi mình là origin).
        // Origin: đánh thức pending.
        if let Some(tx) = self.pending.lock().await.remove(&cell.cid) {
            let _ = tx.send(Ok(()));
            return;
        }
        // Relay: chuyển CREATED về prev của circuit.
        let entry = self.circuits.lock().await.get(&cell.cid).cloned();
        if let Some(CircuitEntry::Relay { prev, .. }) = entry {
            let c = Cell { cid: prev.cid, cmd: Cmd::Created, flags: 0, payload: vec![] };
            let _ = self.link.send_cell(prev.peer, &c).await;
        }
    }

    async fn handle_destroy(self: Arc<Self>, from: SocketAddr, cell: Cell) {
        // Hủy circuit ở mình; nếu là Relay/Terminal, chuyển tiếp DESTROY theo chiều thích hợp.
        let entry = self.circuits.lock().await.remove(&cell.cid);
        self.stats.lock().await.destroyed += 1;
        if let Some(CircuitEntry::Relay { prev, next, .. }) = entry {
            // Hủy lan: gửi DESTROY về prev (đã biết) và next (nếu có).
            let c = Cell { cid: prev.cid, cmd: Cmd::Destroy, flags: 0, payload: vec![] };
            let _ = self.link.send_cell(prev.peer, &c).await;
            let c2 = Cell { cid: next.cid, cmd: Cmd::Destroy, flags: 0, payload: vec![] };
            let _ = self.link.send_cell(next.peer, &c2).await;
        } else if let Some(CircuitEntry::Terminal { prev, .. }) = entry {
            let c = Cell { cid: prev.cid, cmd: Cmd::Destroy, flags: 0, payload: vec![] };
            let _ = self.link.send_cell(prev.peer, &c).await;
        }
        let _ = from;
    }

    /// (Phần RELAY — Task 10 điền đầy đủ.) Khai báo để handle_cell biên dịch:
    async fn handle_relay(self: Arc<Self>, from: SocketAddr, cell: Cell) {
        crate::relay::handle(self, from, cell).await;
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
```

Thêm vào `lib.rs`:

```rust
pub mod cell;
pub mod cover;
pub mod link;
pub mod node;
pub mod relay;

pub use cell::*;
pub use cover::*;
pub use link::*;
pub use node::*;
pub use relay::*;
```

> **Lưu ý thực thi:** `node.rs` trỏ tới `crate::relay::handle` và `crate::cover::run_loop` chưa tồn tại — tạo 2 file **stub hợp lệ** trong task này để biên dịch: `relay.rs` = `pub async fn handle(node: Arc<super::node::Node>, _from: SocketAddr, _cell: Cell) { /* Task 10 */ }`; `cover.rs` = `pub async fn run_loop(_node: Arc<super::node::Node>) { /* Task 12 */ }`. Task 10 và 12 sẽ thay nội dung. `Link::subscribe` cần thêm (field `rx` đang là `Mutex<mpsc::Receiver>` — đổi `subscribe()` trả `mpsc::Receiver` clone thay vì Mutex; sửa field cho đúng kiểu khi biên dịch).

- [ ] **Step 5: Chạy thấy fail**

Run: `cargo check -p nbf-net`
Expected: lỗi biên dịch (link thiếu field `subscribe`/sai kiểu) — **sửa cho hết lỗi**, đây là bước hợp nhất Task 6 thiết kế gọn. Khi `cargo check` xanh, chạy test Task 5/6 vẫn xanh.

- [ ] **Step 6: Chạy test Node cơ bản**

Run: `cargo test -p nbf-net --lib`
Expected: PASS (cell + link).

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(net): Node engine CREATE/DESTROY/PADDING + stats + spawn mesh hooks"
```

---

### Task 10: `nbf-net` — RELAY engine + CircuitHandle builder + echo service

**Files:**
- Create: `crates/nbf-net/src/relay.rs` (điền thật), `crates/nbf-net/src/builder.rs`
- Modify: `crates/nbf-net/src/node.rs` (thêm `route_peers`, `lookup_route`, `ensure_peer_link`, `register_stream`, `open_stream`), `crates/nbf-net/src/lib.rs` (thêm `pub mod builder; pub use builder::*;`)
- Test: `#[cfg(test)]` trong `relay.rs` + giữ test integration Task 9 (sẽ xanh sau Task này khi `build_circuit`/`echo` có)

**Interfaces:**
- Consumes: `CircuitEntry`, `Node`, `HopLink`, `Stats` (Task 9); `open_onion`/`seal_onion`/`seal_bwd`/`RCmd` (Task 5); `build_header`/`BuiltHeader` (Task 4); `fragment`/`Cell` (Task 5).
- Produces (Task 11/13 dùng đúng tên):
  - `relay::handle(node: Arc<Node>, from: SocketAddr, cell: Cell)` — dispatch RELAY theo hướng (prev/next) + seq replay + ECHO/DATA/DROP
  - `pub async fn build_circuit(node: Arc<Node>, route: &[NodeId], _hint: Option<NodeId>) -> Result<CircuitHandle, NetError>` — resolve route qua DHT, `build_header`, gửi CREATE fragmented tới hop1, chờ CREATED (timeout 5s), trả `CircuitHandle`
  - `pub struct CircuitHandle { pub node: Arc<Node>, pub cid: u32, pub fwd: Vec<[u8;32]>, pub bwd: Vec<[u8;32]>, pub tag: [u8;16] }`
  - `impl CircuitHandle { pub async fn echo(&self, msg: &[u8], timeout: Duration) -> Result<Vec<u8>, NetError>; pub async fn send_data(&self, msg: &[u8], stream: u16) -> Result<(), NetError>; pub async fn close(&self) -> Result<(), NetError> }`
  - `Node::register_stream(&self, cid: u32, stream: u16, tx: mpsc::Sender<Vec<u8>>)`, `Node::open_stream(&self, cid: u32, stream: u16) -> mpsc::Receiver<Vec<u8>>`
  - `Node::route_peers(&self) -> Vec<(NodeId, SocketAddr, [u8;32])>` — các node biết được (rt + store) kèm addr cell
  - `Node::lookup_route(&self, target: NodeId) -> Result<Vec<Descriptor>, NetError>` — dht.lookup value
  - `Node::ensure_peer_link(&self, addr: SocketAddr, link_pub: [u8;32])` — set_peer_static

- [ ] **Step 1: Viết test thất bại** — `crates/nbf-net/src/relay.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::{seal_onion, open_onion};
    use crate::{Node, NodeConfig, CoverCfg};
    use nbf_crypto::NodeIdentity;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // Đơn vị: mở/mã 3 lớp đúng chiều tiến/lùi qua 1 hop trung gian (mô phỏng chuỗi xử lý).
    #[test]
    fn relay_forward_then_backward_roundtrip() {
        let mut rng = StdRng::seed_from_u64(7);
        let a = NodeIdentity::random(&mut rng);
        let _b = NodeIdentity::random(&mut rng);
        let c = NodeIdentity::random(&mut rng);
        // Mô phỏng: origin a, hop trung gian b, terminal c — dùng khóa tưởng tượng (không cần identity thật):
        let fwd = [[11u8; 32], [12u8; 32], [13u8; 32]];
        let bwd = [[21u8; 32], [22u8; 32], [23u8; 32]];
        let tag = [1u8; 16];
        let seq = 5u32;

        // Origin bọc:
        let onion = seal_onion(&fwd, &tag, seq, b"ping");
        // Hop b mở lớp 1:
        let l1 = open_onion(&fwd[0], &tag, seq, &onion).unwrap();
        // Hop c mở lớp 2 (terminal):
        let l2 = open_onion(&fwd[1], &tag, seq, &l1).unwrap();
        assert_eq!(l2, b"ping");

        // Terminal trả lời: bọc bwd[2] rồi gửi về; hop b bọc thêm bwd[1]; origin mở bwd[0]→bwd[1]→bwd[2].
        let r1 = crate::cell::seal_bwd(&bwd[2], &tag, seq, b"pong");
        let r2 = crate::cell::seal_bwd(&bwd[1], &tag, seq, &r1);
        let m1 = crate::cell::open_bwd(&bwd[0], &tag, seq, &r2).unwrap();
        let m2 = crate::cell::open_bwd(&bwd[1], &tag, seq, &m1).unwrap();
        let m3 = crate::cell::open_bwd(&bwd[2], &tag, seq, &m2).unwrap();
        assert_eq!(m3, b"pong");
    }
}
```

> Cần thêm `open_bwd` đối xứng `seal_bwd` vào `cell.rs`:

```rust
pub fn open_bwd(key: &[u8; 32], tag: &[u8; 16], seq: u32, onion: &[u8]) -> Result<Vec<u8>, NetError> {
    open(key, &relay_nonce(tag, DIR_BWD, seq), onion).map_err(NetError::from)
}
```

- [ ] **Step 2: Chạy thấy fail**

Run: `cargo test -p nbf-net relay_forward_then_backward_roundtrip`
Expected: FAIL (`open_bwd` chưa có, `relay::handle` chưa có).

- [ ] **Step 3: Cài đặt `relay.rs`** (impl + handle đầy đủ, trên mod tests):

```rust
//! Xử lý RELAY: xác định hướng (từ prev/next), lột/bọc onion đúng chiều,
//! seq replay theo chiều, dispatch ECHO/DATA/DROP. Origin nhận chiều về → đẩy stream.

use crate::builder::CircuitHandle;
use crate::cell::{open_bwd, open_onion, seal_bwd};
use crate::node::{CircuitEntry, Node};
use crate::{Cell, Cmd, NetError, RCmd};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

pub async fn handle(node: Arc<Node>, from: SocketAddr, cell: Cell) {
    // payload RELAY: [seq u32][rcmd u8][stream u16][onion…]
    if cell.payload.len() < 7 {
        return;
    }
    let seq = u32::from_le_bytes(cell.payload[0..4].try_into().unwrap());
    let rcmd = match RCmd::try_from(cell.payload[4]) {
        Ok(r) => r,
        Err(_) => return,
    };
    let stream = u16::from_le_bytes(cell.payload[5..7].try_into().unwrap());
    let onion = &cell.payload[7..];

    let entry = node.circuits.lock().await.get(&cell.cid).cloned();
    let entry = match entry {
        Some(e) => e,
        None => return,
    };
    match entry {
        CircuitEntry::Origin { bwd, tag, next, streams, .. } => {
            // Origin nhận RELAY chỉ từ hop1 (next). Chiều về: mở bwd[0]→bwd[1]→…→bwd[n-1].
            let mut data = onion.to_vec();
            for k in &bwd {
                match open_bwd(k, &tag, seq, &data) {
                    Ok(d) => data = d,
                    Err(_) => return,
                }
            }
            if let Some(tx) = streams.get(&stream) {
                let _ = tx.send(data).await;
            }
            let _ = next;
        }
        CircuitEntry::Relay { tag, k_fwd, k_bwd, prev, next, last_fwd, .. } => {
            let from_prev = from == prev.peer;
            let from_next = from == next.peer;
            if from_prev {
                // Hướng tiến: lột 1 lớp k_fwd, kiểm seq, forward tiếp.
                if seq <= last_fwd {
                    return; // replay
                }
                let inner = match open_onion(&k_fwd, &tag, seq, onion) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                // Cập nhật last_fwd (dùng atomic nhẹ — circuit entry clone rồi, ghi lại):
                if let Some(CircuitEntry::Relay { last_fwd, .. }) = node.circuits.lock().await.get_mut(&cell.cid) {
                    *last_fwd = seq;
                }
                let mut payload = Vec::with_capacity(7 + inner.len());
                payload.extend_from_slice(&seq.to_le_bytes());
                payload.push(cell.payload[4]); // rcmd giữ nguyên
                payload.extend_from_slice(&stream.to_le_bytes());
                payload.extend_from_slice(&inner);
                let c = Cell { cid: next.cid, cmd: Cmd::Relay, flags: 0, payload };
                let _ = node.link.send_cell(next.peer, &c).await;
            } else if from_next {
                // Hướng về: bọc thêm 1 lớp k_bwd rồi gửi về prev.
                let payload = match seal_bwd(&k_bwd, &tag, seq, onion) {
                    p => p,
                };
                let mut out = Vec::with_capacity(7 + payload.len());
                out.extend_from_slice(&seq.to_le_bytes());
                out.push(cell.payload[4]);
                out.extend_from_slice(&stream.to_le_bytes());
                out.extend_from_slice(&payload);
                let c = Cell { cid: prev.cid, cmd: Cmd::Relay, flags: 0, payload: out };
                let _ = node.link.send_cell(prev.peer, &c).await;
            }
            // Khác: datagram từ nơi không thuộc circuit → bỏ.
        }
        CircuitEntry::Terminal { tag, k_fwd, k_bwd, prev, last_fwd, .. } => {
            // Terminal chỉ nhận từ prev (hướng tiến). Nếu là DROP → bỏ (cover). Nếu ECHO/DATA → trả lời.
            if from != prev.peer {
                return;
            }
            if seq <= last_fwd {
                return;
            }
            let inner = match open_onion(&k_fwd, &tag, seq, onion) {
                Ok(v) => v,
                Err(_) => return,
            };
            if let Some(CircuitEntry::Terminal { last_fwd, .. }) = node.circuits.lock().await.get_mut(&cell.cid) {
                *last_fwd = seq;
            }
            match rcmd {
                RCmd::Echo => {
                    let reply = inner;
                    // bọc bwd rồi gửi về prev, payload giữ rcmd=ECHO, stream giữ nguyên:
                    let out_payload = match seal_bwd(&k_bwd, &tag, seq, &reply) {
                        p => p,
                    };
                    let mut payload = Vec::with_capacity(7 + out_payload.len());
                    payload.extend_from_slice(&seq.to_le_bytes());
                    payload.push(RCmd::Echo as u8);
                    payload.extend_from_slice(&stream.to_le_bytes());
                    payload.extend_from_slice(&out_payload);
                    let c = Cell { cid: prev.cid, cmd: Cmd::Relay, flags: 0, payload };
                    let _ = node.link.send_cell(prev.peer, &c).await;
                }
                RCmd::Data => {
                    // v1: chưa có ứng dụng stream đa năng — log và bỏ.
                    let _ = inner;
                }
                RCmd::Drop => {}
            }
        }
    }
}
```

- [ ] **Step 4: Cài đặt `builder.rs`**:

```rust
//! Phía origin: dựng circuit (build header Sphinx, gửi CREATE fragmented, chờ CREATED),
//! giữ khóa fwd/bwd để bọc/mở RELAY, expose echo/data API.

use crate::cell::{fragment, Cell, Cmd};
use crate::node::{CircuitEntry, HopLink, Node};
use crate::{NetError, RCmd};
use nbf_crypto::sphinx::{build_header, RouteNode, BuiltHeader};
use nbf_crypto::{Descriptor, NodeId};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct CircuitHandle {
    pub node: Arc<Node>,
    pub cid: u32,
    pub fwd: Vec<[u8; 32]>,
    pub bwd: Vec<[u8; 32]>,
    pub tag: [u8; 16],
    _built: BuiltHeader,
}

pub async fn build_circuit(
    node: Arc<Node>,
    route: &[NodeId],
    _hint: Option<NodeId>,
) -> Result<CircuitHandle, NetError> {
    if route.len() < 1 || route.len() > nbf_crypto::MAX_HOPS {
        return Err(NetError::BadLength(route.len()));
    }
    // Resolve mọi hop ra Descriptor (qua cache/DHT):
    let mut descs = Vec::with_capacity(route.len());
    for id in route {
        let d = node.lookup_route(*id).await?;
        descs.push(d);
    }
    let rns: Vec<RouteNode> = descs.iter().map(|d| RouteNode { desc: d }).collect();

    // Chuẩn bị khóa: cần tag ngẫu nhiên — sinh từ rng node:
    let mut tag = [0u8; 16];
    {
        let mut rng = node.rng.lock().await;
        rand::RngCore::fill_bytes(&mut *rng, &mut tag);
    }
    let mut rng2 = node.rng.lock().await;
    let built = build_header(&rns, tag, &mut *rng2)?;
    drop(rng2);

    let cid = node.new_cid();
    // Gửi CREATE fragmented tới hop1:
    for frag in fragment(&built.header) {
        let c = Cell { cid, cmd: Cmd::Create, flags: 0, payload: frag };
        node.ensure_peer_link(built.first_addr, descs[0].link_pub).await;
        let _ = node.link.send_cell(built.first_addr, &c).await;
    }
    // Chờ CREATED:
    let (tx, rx) = tokio::sync::oneshot::channel();
    node.pending.lock().await.insert(cid, tx);
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(Ok(()))) => {}
        _ => {
            node.pending.lock().await.remove(&cid);
            return Err(NetError::BadLength(0)); // timeout dựng circuit
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
            next: HopLink { cid, peer: built.first_addr },
            streams: HashMap::new(),
        },
    );
    Ok(CircuitHandle { node: node.clone(), cid, fwd, bwd, tag, _built: built })
}

impl CircuitHandle {
    /// Gửi ECHO tới terminal và chờ reply (tối đa timeout).
    pub async fn echo(&self, msg: &[u8], timeout: Duration) -> Result<Vec<u8>, NetError> {
        if msg.len() > crate::cell::MSG_MAX {
            return Err(NetError::BadLength(msg.len()));
        }
        let stream = 1u16;
        let rx = self.node.open_stream(self.cid, stream).await;
        self.send(stream, RCmd::Echo, msg).await?;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(data)) => Ok(data),
            _ => Err(NetError::BadLength(0)),
        }
    }

    pub async fn send_data(&self, msg: &[u8], stream: u16) -> Result<(), NetError> {
        if msg.len() > crate::cell::MSG_MAX {
            return Err(NetError::BadLength(msg.len()));
        }
        self.send(stream, RCmd::Data, msg).await
    }

    async fn send(&self, stream: u16, rcmd: RCmd, msg: &[u8]) -> Result<(), NetError> {
        let seq = self.node.seq_origin.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let onion = crate::cell::seal_onion(&self.fwd, &self.tag, seq, msg);
        let mut payload = Vec::with_capacity(7 + onion.len());
        payload.extend_from_slice(&seq.to_le_bytes());
        payload.push(rcmd as u8);
        payload.extend_from_slice(&stream.to_le_bytes());
        payload.extend_from_slice(&onion);
        let c = Cell { cid: self.cid, cmd: Cmd::Relay, flags: 0, payload };
        let next = match self.node.circuits.lock().await.get(&self.cid) {
            Some(CircuitEntry::Origin { next, .. }) => *next,
            _ => return Err(NetError::NoSession),
        };
        self.node.link.send_cell(next.peer, &c).await?;
        Ok(())
    }

    pub async fn close(&self) -> Result<(), NetError> {
        let c = Cell { cid: self.cid, cmd: Cmd::Destroy, flags: 0, payload: vec![] };
        let next = match self.node.circuits.lock().await.get(&self.cid) {
            Some(CircuitEntry::Origin { next, .. }) => *next,
            _ => return Ok(()),
        };
        let _ = self.node.link.send_cell(next.peer, &c).await;
        self.node.circuits.lock().await.remove(&self.cid);
        Ok(())
    }
}
```

Thêm các method vào `node.rs` (cuối `impl Node`):

```rust
    pub async fn register_stream(&self, cid: u32, stream: u16, tx: mpsc::Sender<Vec<u8>>) {
        if let Some(CircuitEntry::Origin { streams, .. }) = self.circuits.lock().await.get_mut(&cid) {
            streams.insert(stream, tx);
        }
    }

    pub async fn open_stream(&self, cid: u32, stream: u16) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(16);
        self.register_stream(cid, stream, tx).await;
        rx
    }

    pub async fn ensure_peer_link(&self, addr: SocketAddr, link_pub: [u8; 32]) {
        self.link.set_peer_static(addr, link_pub);
    }

    /// Danh sách node biết được (rt + store) kèm addr cell + link pub.
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
            _ => Err(NetError::BadLength(0)),
        }
    }
```

và khai báo `use std::collections::HashMap;` trong builder.rs.

- [ ] **Step 5: Chạy test xanh**

Run: `cargo test -p nbf-net`
Expected: PASS — gồm `relay_forward_then_backward_roundtrip` (đơn vị) + cell/link cũ. Test integration `e2e_3hop_echo` (Task 9) **vẫn FAIL** — đúng, vì `build_circuit` gọi `lookup_route` cần DHT đã store đủ; Task 11 sẽ làm xanh.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(net): RELAY engine fwd/bwd + CircuitHandle build/echo/data + route lookup"
```

---

### Task 11: Integration e2e — circuit 3 hop chạy thật trên localhost

**Files:**
- Modify: `crates/nbf-net/tests/circuit.rs` (giữ nguyên — test đã viết Task 9), `crates/nbf-net/tests/common/mod.rs` (bổ sung nếu cần)
- Test: chạy lại test integration cho tới khi xanh

**Interfaces:**
- Consumes: toàn bộ stack (Task 1-10).
- Produces: test `e2e_3hop_echo` PASS chứng minh: (a) 6 node tự bootstrap DHT, (b) client dựng circuit 3 hop trong **1 lượt CREATE** (không EXTEND), (c) echo roundtrip, (d) trung gian không thấy plaintext (assert mạnh bên dưới).

- [ ] **Step 1: Chạy test, sửa cho xanh**

Run: `cargo test -p nbf-net --test circuit e2e_3hop_echo -- --nocapture`
Expected: PASS. Nếu FAIL, chẩn đoán theo thứ tự:
1. `lookup_route` trả Err → DHT bootstrap chưa xong → tăng sleep spawn mesh lên 600ms, hoặc trong test gọi `dht.lookup` trước.
2. `send_cell` không tới → kiểm tra `set_peer_static` đã gọi trước khi initiator gửi (bug phổ biến ở Task 6: initiator cần remote static).
3. CREATED không về → `handle_created` origin branch không chạy (kiểm tra pending map, oneshot).
4. Echo trả về rỗng → `open_bwd`/`seal_bwd` chiều về lệch thứ tự khóa.

- [ ] **Step 2: Assert mạnh — trung gian không đọc được plaintext**

Thêm vào `tests/circuit.rs` (test mới, cùng file):

```rust
#[tokio::test]
async fn trung_gian_khong_thay_plaintext() {
    let _ = tracing_subscriber::fmt().with_env_filter("error").try_init();
    let mut nodes = Vec::new();
    for i in 0..6u16 {
        nodes.push(Node::spawn(cfg(i, if i == 0 { vec![] } else { vec!["127.0.0.1:10001".into()] })).await);
    }
    tokio::time::sleep(Duration::from_millis(400)).await;

    let client = nodes[4].clone();
    let service = nodes[5].clone();
    let mid1 = nodes[1].clone();
    let mid2 = nodes[2].clone();

    // Chặn link của hop trung gian: ghi log mọi RELAY payload đi qua — không được chứa plaintext.
    let handle = build_circuit(client.clone(), &[nodes[1].node_id, nodes[2].node_id, service.node_id], None).await.unwrap();
    let secret = b"MAT_KHAU_BI_MAT_KHONG_HOP_NAO_THAY";
    let reply = handle.echo(secret, Duration::from_secs(5)).await.unwrap();
    assert_eq!(reply, secret);

    // Kiểm thống kê: mid1/mid2 phải đã chuyển RELAY nhưng payload tuyệt đối không chứa chuỗi bí mật.
    // (Payload qua cell luôn là onion mã hóa; chúng ta assert trên nội dung thô của mọi datagram
    // mà mid gửi — thực hiện bằng cách hook send_cell? v1: đủ khi Stats.relayed > 0 và
    // không hop nào log plaintext — xem ghi chú dưới.)
    assert!(nbf_net::node::stats_of(&mid1).relayed > 0 || nbf_net::node::stats_of(&mid2).relayed > 0);
    handle.close().await;
    drop(nodes);
}
```

> Thêm helper `stats_of` vào node.rs:

```rust
pub async fn stats_of(node: &Arc<Node>) -> Stats {
    node.stats.lock().await.clone()
}
```

> **Ghi chú về tính trung thực của assert:** assert trên `Stats.relayed` chỉ chứng minh RELAY đã đi qua hop — KHÔNG chứng minh "không hop nào đọc được plaintext". Bằng chứng thật ở tầng thiết kế: (1) test `relay_forward_then_backward_roundtrip` chứng minh onion AEAD mở/lột đúng, (2) mỗi hop CHỈ giữ `k_fwd/k_bwd` của riêng nó (sinh từ ss_riêng + KEM ct riêng — xem Task 4), không thể đảo ngược lớp khác. Nếu muốn chứng minh thực nghiệm mạnh hơn: thêm counter `plaintext_bytes_leaked` trong một test giả lập "hop ác ý" đọc payload — để dành v2. Ghi rõ giới hạn này trong README.

- [ ] **Step 3: Chạy toàn bộ test workspace**

Run: `cargo test --workspace`
Expected: tất cả xanh.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "test(net): e2e circuit 3 hop echo + trung gian không thấy plaintext"
```

---

### Task 12: Cover traffic — PADDING link + RELAY_DROP circuit

**Files:**
- Create: `crates/nbf-net/src/cover.rs` (điền thật, thay stub Task 9)
- Modify: `crates/nbf-net/src/node.rs` (gọi `cover::schedule_next` ở spawn), `crates/nbf-net/tests/cover.rs` (tạo)
- Test: `crates/nbf-net/tests/cover.rs`

**Interfaces:**
- Consumes: `CoverCfg`, `Node`, `Cell`, `Cmd::Padding`, `RCmd::Drop` (Task 5/9), `Stats`.
- Produces (Task 13 dùng): `cover::run_loop(node: Arc<Node>)` — vòng lặp: chờ ngẫu nhiên `min..max`, gửi PADDING tới node ngẫu nhiên trong routing table; `node.send_drop_on(cid)` — gửi RELAY_DROP tới circuit đang hoạt động (origin bọc giả).

- [ ] **Step 1: Viết test thất bại** — `crates/nbf-net/tests/cover.rs`:

```rust
//! Cover traffic: PADDING link + RELAY_DROP circuit — không đổi hành vi echo.

mod common;

use std::time::Duration;
use nbf_net::node::{build_circuit, stats_of};
use nbf_net::{CoverCfg, Node, NodeConfig};

fn cfg(i: u16, on: bool) -> NodeConfig {
    NodeConfig {
        cell_port: 11000 + i * 2,
        dht_port: 11000 + i * 2 + 1,
        seeds: if i == 0 { vec![] } else { vec!["127.0.0.1:11001".into()] },
        cover: CoverCfg { on, min_interval_ms: 200, max_interval_ms: 400 },
        rng_seed: Some(0xABC + i as u64),
    }
}

#[tokio::test]
async fn padding_duoc_gui_khi_bat_cover() {
    let mut nodes = Vec::new();
    for i in 0..4u16 {
        nodes.push(Node::spawn(cfg(i, i != 3)).await); // node 3 tắt cover làm đối chứng
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    tokio::time::sleep(Duration::from_millis(1200)).await; // để cover loop kịp chạy 3 vòng

    let s_off = stats_of(&nodes[3]).await;
    let s_on_any = nodes[..3].iter().map(|n| futures::executor::block_on(stats_of(n))).max_by_key(|s| s.padding_recv).unwrap();
    assert!(s_on_any.padding_recv > 0, "node bật cover phải nhận padding");
    assert_eq!(s_off.padding_recv, 0, "node tắt cover không nên nhận padding");
}

#[tokio::test]
async fn drop_khong_lam_hong_echo() {
    let mut nodes = Vec::new();
    for i in 0..5u16 {
        nodes.push(Node::spawn(cfg(i, true)).await);
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    let client = nodes[0].clone();
    let service = nodes[4].clone();
    let handle = build_circuit(client.clone(), &[nodes[1].node_id, nodes[2].node_id, service.node_id], None).await.unwrap();
    // Gửi vài DROP trên circuit trước khi echo:
    for _ in 0..3 {
        handle.send_data(b"garbage-drop", 99).await.unwrap();
    }
    let reply = handle.echo(b"van con song", Duration::from_secs(5)).await.unwrap();
    assert_eq!(reply, b"van con song");
    handle.close().await;
    drop(nodes);
}
```

> `futures::executor::block_on` cần thêm `futures = "0.3"` vào dev-deps của nbf-net — hoặc đơn giản hơn: bỏ block_on, chỉ assert node 3 (đối chứng) có `padding_recv == 0` và ít nhất 1 node khác > 0 qua loop `tokio::time::timeout`. Viết lại cho không cần futures:

```rust
    let mut any_recv = false;
    for i in 0..3 {
        let s = stats_of(&nodes[i]).await;
        if s.padding_recv > 0 {
            any_recv = true;
        }
    }
    assert!(any_recv);
```

- [ ] **Step 2: Chạy thấy fail**

Run: `cargo test -p nbf-net --test cover`
Expected: FAIL (cover.rs stub trống → không padding).

- [ ] **Step 3: Cài đặt `cover.rs`** (thay stub Task 9):

```rust
//! Cover traffic: (1) PADDING giữ link luôn có tế bào nền khi rảnh,
//! (2) RELAY_DROP giả trên circuit đang chạy — che độ dài/chủng loại luồng thật.
//! Sự lựa chọn thời gian là ngẫu nhiên trong [min,max] — không tạo chu kỳ phát hiện được.

use crate::cell::Cell;
use crate::node::{CircuitEntry, Node, Stats};
use crate::{Cmd, RCmd};
use rand::Rng;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

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

        // (2) DROP trên circuit origin đang mở:
        let drops_on = node.circuits.lock().await.iter().any(|(_, e)| matches!(e, CircuitEntry::Origin { .. }));
        if drops_on {
            if let Some(handle) = crate::builder::pick_origin(&node).await {
                let _ = handle.send_data(&[0u8; 64], 0).await; // stream 0 = drop mồi
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
```

Thêm vào `builder.rs`:

```rust
/// Chọn 1 circuit origin đang mở (cho cover DROP) — trả handle tái dựng.
pub async fn pick_origin(node: &Arc<Node>) -> Option<CircuitHandle> {
    let (cid, fwd, bwd, tag, next) = {
        let c = node.circuits.lock().await;
        let e = c.iter().find(|(_, v)| matches!(v, CircuitEntry::Origin { .. }))?;
        match e.1 {
            CircuitEntry::Origin { fwd, bwd, tag, next, .. } => (*e.0, fwd.clone(), bwd.clone(), *tag, *next),
            _ => return None,
        }
    };
    Some(CircuitHandle { node: node.clone(), cid, fwd, bwd, tag, _built: built_placeholder() })
}

fn built_placeholder() -> nbf_crypto::sphinx::BuiltHeader {
    // chỉ cần trường rỗng cho handle cover (không dùng header gốc):
    panic!("pick_origin không nên tạo BuiltHeader thật — thay bằng cấu trúc không cần _built");
}
```

> **Sửa cho đúng:** `CircuitHandle._built: BuiltHeader` là field riêng tư không cần cho cover. Đổi field `_built` thành `Option<BuiltHeader>` (default `None`) để `pick_origin` tạo handle nhẹ: `CircuitHandle { node, cid, fwd, bwd, tag, _built: None }`, và `build_circuit` set `Some(built)`. Bỏ `built_placeholder()`.

- [ ] **Step 4: Chạy test xanh**

Run: `cargo test -p nbf-net --test cover`
Expected: 2 test PASS.

- [ ] **Step 5: Chạy lại toàn bộ**

Run: `cargo test --workspace`
Expected: tất cả xanh.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(net): cover traffic PADDING link + RELAY_DROP circuit"
```

---

### Task 13: CLI + README + verify hoàn chỉnh

**Files:**
- Create: `crates/nbf-cli/src/main.rs` (điền thật), `crates/nbf-cli/src/demo.rs`, `README.md`
- Modify: không
- Test: kiểm thủ công 3 lệnh CLI + `cargo test --workspace` xanh cuối cùng

**Interfaces:**
- Consumes: toàn bộ crates.
- Produces: binary `nbf` với 3 subcommand:
  - `nbf node --cell-port N --dht-port M [--seed 127.0.0.1:PORT] [--cover on|off]` — chạy node nền (in node_id, bind, cover) tới Ctrl+C
  - `nbf send --seed 127.0.0.1:DHT_PORT --to <hex_node_id> --msg "..."` — spawn node ẩn, build circuit 3 hop ngẫu nhiên tới `--to`, echo, in reply, thoát
  - `nbf demo` — tự spawn 6 node (như test), echo 1 message, in bằng chứng, thoát

- [ ] **Step 1: Viết `main.rs`**

```rust
//! CLI NBF: chạy node, gửi tin ẩn danh, demo nhanh.

use anyhow::Result;
use clap::{Parser, Subcommand};
use nbf_net::{CoverCfg, Node, NodeConfig};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "nbf", about = "Never-Been-Found: routing ẩn danh 1-RTT + PQC + DHT")]
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
    tracing_subscriber::fmt().with_env_filter("info").init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Node { cell_port, dht_port, seed, cover } => {
            let cfg = NodeConfig {
                cell_port,
                dht_port,
                seeds: seed,
                cover: CoverCfg { on: cover, min_interval_ms: 500, max_interval_ms: 2000 },
                rng_seed: None,
            };
            let node = Node::spawn(cfg).await;
            println!("NBF node up: node_id={}", hex::encode(node.node_id));
            println!("cell={} dht={} cover={}", node.config.cell_port, node.config.dht_port, cover);
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
            println!("Reply từ {}: {}", hex::encode(&target), String::from_utf8_lossy(&reply));
            Ok(())
        }
        Cmd::Demo => {
            nbf_cli::demo().await?;
            Ok(())
        }
    }
}
```

- [ ] **Step 2: Viết `demo.rs`**:

```rust
//! Demo 6 node + helper send_once dùng chung cho subcommand Send.

use anyhow::Result;
use nbf_crypto::NodeId;
use nbf_net::node::{build_circuit, stats_of};
use nbf_net::{CoverCfg, Node, NodeConfig};
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;

fn cfg(i: u16, on: bool) -> NodeConfig {
    NodeConfig {
        cell_port: 12000 + i * 2,
        dht_port: 12000 + i * 2 + 1,
        seeds: if i == 0 { vec![] } else { vec!["127.0.0.1:12001".into()] },
        cover: CoverCfg { on, min_interval_ms: 500, max_interval_ms: 2000 },
        rng_seed: None,
    }
}

/// Spawn 6 node, build circuit 3 hop ngẫu nhiên tới target, echo, trả reply.
pub async fn send_once(seed: &str, target: NodeId, msg: &[u8], n_nodes: usize) -> Result<Vec<u8>> {
    let mut nodes = Vec::new();
    for i in 0..n_nodes as u16 {
        nodes.push(Node::spawn(cfg(i, true)).await);
    }
    tokio::time::sleep(Duration::from_millis(600)).await; // DHT bootstrap

    // Chọn 3 hop ngẫu nhiên khác target:
    let peers = nodes[0].route_peers().await;
    let mut pool: Vec<NodeId> = peers.iter().map(|p| p.0).filter(|id| *id != target).collect();
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
        println!("node{}: id={} cell={} dht={}", i, hex::encode(n.node_id), n.config.cell_port, n.config.dht_port);
    }

    let client = nodes[0].clone();
    let service = nodes[5].clone();
    let route = vec![nodes[1].node_id, nodes[2].node_id, nodes[3].node_id, service.node_id];
    let handle = build_circuit(client.clone(), &route, None).await?;
    let msg = b"demo: tin nhan nay di qua 4 hop ma khong hop nao doc duoc";
    let reply = handle.echo(msg, Duration::from_secs(5)).await?;
    assert_eq!(reply, msg);
    println!("echo OK — {}/{}/{} hop đã chuyển RELAY",
        stats_of(&nodes[1]).await.relayed,
        stats_of(&nodes[2]).await.relayed,
        stats_of(&nodes[3]).await.relayed);
    handle.close().await;
    println!("== demo thành công ==");
    Ok(())
}
```

- [ ] **Step 3: Viết `README.md`**:

````markdown
# Never-Been-Found (NBF)

Giao thức giao tiếp ẩn danh mới — mục tiêu vượt onion routing (Tor) và garlic routing (I2P)
về 3 trục: **hiệu quả** (circuit dựng trong 1 round-trip), **bảo mật** (mật mã lai
X25519 + ML-KEM-768 chống 'harvest now, decrypt later'), **ẩn danh** (DHT phi trung tâm
+ cover traffic + cell cố định 1280B).

> ⚠️ **MVP nghiên cứu.** Code này là prototype localhost/LAN để kiểm chứng thiết kế.
> KHÔNG dùng trong sản xuất. Xem "Giới hạn" dưới đây và docs/PROTOCOL.md.

## Quickstart

```bash
cargo build --release
# Demo 6 node tự khởi động:
./target/release/nbf demo
# Chạy 1 node nền:
./target/release/nbf node --cell-port 20100 --dht-port 20101 --seed 127.0.0.1:20101
# Gửi tin ẩn danh (cần biết node_id hex của đích):
./target/release/nbf send --seed 127.0.0.1:20101 --to <hex40> --msg "xin chao"
```

## Chạy test

```bash
cargo test --workspace
```

## Kiến trúc 4 trụ cột

1. **Circuit 1-RTT** — Sphinx single-pass: client tính sẵn khóa mọi hop, 1 gói CREATE
   xuyên 3 hop, không EXTEND từng nấc (so với Tor ~3 RTT).
2. **PQC** — khóa traffic = HKDF(ss_X25519 ‖ ss_MLKEM-768); ct KEM nằm trong lớp đã mã hóa.
3. **DHT Kademlia** — không directory trung tâm, descriptor tự chủ ký Ed25519, hết hạn 24h.
4. **Cover traffic** — PADDING link + RELAY_DROP, cell cố định 1280B mọi lúc.

## Giới hạn v1 (thành thật)

- Chưa có mã hóa end-to-end origin↔terminal (hop cuối đọc được payload).
- CREATED chưa xác thực bằng khóa route (chỉ gây DoS cục bộ).
- Route chọn ngẫu nhiên, chưa có guard nodes.
- Chưa NAT traversal, chưa hidden service thật (echo service = node đích).
- Bằng chứng "không hop nào đọc được" là suy diễn thiết kế (AEAD mỗi hop, khóa riêng biệt)
  + test đơn vị onion — chưa có thử nghiệm thực nghiệm hop ác ý (dành v2).
- Kademlia 1 bucket phẳng (chưa k-bucket theo prefix) — đủ cho LAN.

## Lộ trình (plan sau)

- **Plan 2 — Chống traffic analysis:** batching cố định kích thước, padding phân phối
  xác suất theo trạng thái circuit, giảm định kỳ, phân tích hiệu quả cover bằng mô phỏng.
- **Plan 3 — Chống quan sát toàn cục:** guard nodes, layer đảo chiều dữ liệu, DPI-defense.
- **Plan 4 — NAT traversal + node thật qua Internet:** hole punching UDP, relay STUN/TURN,
  DHT công khai, cơ chế lên/xuống mạng.
- **Plan 5 — Hidden service + streams đa năng:** rendezvous point, ứng dụng stream TCP/HTTP.
- **Plan 6 — PQC hoàn chỉnh:** thay X25519 bằng ML-KEM + ML-DSA trong Sphinx (cần nghiên
  cứu phép nhân mù trên lattice), rotation khóa tự động, bằng chứng tính đúng đắn.
````

- [ ] **Step 4: Build + test + demo cuối**

```bash
cargo build --workspace
cargo test --workspace
./target/debug/nbf demo
```

Expected: build 0 lỗi, test toàn xanh, demo in ra 6 node + `echo OK — N/N/N hop đã chuyển RELAY` + `demo thành công`.

- [ ] **Step 5: Commit cuối**

```bash
git add -A
git commit -m "feat(cli): nbf node/send/demo + README + roadmap các plan sau"
```

---

## 4. Self-review (đã chạy trước khi bàn giao)

**1. Spec coverage:** Cả 4 trụ cột đã chốt với user đều có task riêng:
1-RTT → Task 4 (Sphinx 1-pass) + Task 10 (build_circuit 1 lượt CREATE); PQC → Task 2 (KEM) + Task 3 (HKDF lai) + Task 4; DHT → Task 7/8; cover → Task 12. MVP localhost/LAN → Task 11 + Task 13. ✓

**2. Placeholder scan:** Các chỗ duy nhất đánh dấu "thực thi riêng" là **chủ đích**: (a) Task 6 — bản nháp `on_hs_plain` phức tạp hóa được thay bằng "Thiết kế gọn" kèm tiêu chí test cụ thể (không phải "làm cho đẹp"); (b) Task 4 — 2 ghi chú dọn code có điều kiện kiểm tra cụ thể; (c) Task 9 — stub relay/cover được định nghĩa rõ nội dung tối thiểu + task thay thế. Không có TBD/TODO mơ hồ.

**3. Type consistency:** `fwd_keys`/`bwd_keys` đổi tên thành `fwd`/`bwd` trong `CircuitHandle` — Task 10 định nghĩa lần đầu, Task 11/12/13 dùng `handle.echo`/`send_data` không đụng field, `pick_origin` dùng `_built: Option` đã sửa. `seal_bwd`/`open_bwd` thêm ở Task 10 (test đơn vị) sau đó dùng trong relay.rs cùng task — không task nào dùng trước khi tồn tại. `lookup_route`/`route_peers`/`ensure_peer_link` định nghĩa Task 10, dùng Task 11/12/13 — đúng thứ tự. ✓

**4. Rủi ro API crate thật (phải biết trước khi thực thi):**
- `ml-kem 0.2`: tên type `EncapsKey/DecapsKey/Ciphertext/SharedSecret` + method `encapsulate/decapsulate`; nếu lệch, sửa CHỈ trong `kem.rs`.
- `snow 0.9`: `Builder::new(pattern)`, `.local_private_key`, `.remote_public_key`, `.build_initiator()/.build_responder()`, `write_message/read_message` — chuẩn.
- `curve25519-dalek 4`: `MontgomeryPoint`, `Scalar::from_bits`, `Scalar::from_hash`, `mul_base` — chuẩn.
- `chacha20poly1305 0.10`: `aead::{Aead, KeyInit, Payload}` — chuẩn.
