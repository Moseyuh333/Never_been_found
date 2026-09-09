# Never-Been-Found (NBF)

Giao thức giao tiếp ẩn danh mới — mục tiêu vượt onion routing (Tor) và garlic routing (I2P)
về 3 trục: **hiệu quả** (circuit dựng trong 1 round-trip), **bảo mật** (mật mã lai
X25519 + ML-KEM-768 chống "harvest now, decrypt later"), **ẩn danh** (DHT phi trung tâm
+ cover traffic + cell cố định 1280B).

> ⚠️ **MVP nghiên cứu.** Code này là prototype localhost/LAN để kiểm chứng thiết kế.
> KHÔNG dùng trong sản xuất. Xem "Giới hạn" dưới đây và `docs/PROTOCOL.md`.

## Quickstart

```bash
cargo build --release
# Demo 6 node tự khởi động:
./target/release/nbf demo
# Chạy 1 node nền:
./target/release/nbf node --cell-port 20100 --dht-port 20101
# Gửi tin ẩn danh (tự spawn node + circuit 3 hop ngẫu nhiên):
./target/release/nbf send --seed 127.0.0.1:20101 --to <hex 40 ký tự> --msg "xin chao"
```

## Kiến trúc

| Crate | Nội dung |
|---|---|
| `nbf-crypto` | ML-KEM-768 + X25519 hybrid, HKDF, Sphinx 1-RTT header, replay guard |
| `nbf-dht` | RPC wire (magic `NBFR`) + Kademlia UDP (bootstrap/store/iterative lookup) |
| `nbf-net` | Cell 1280B + fragmentation, Noise-IK link, Node engine (CREATE/CREATED/RELAY/DESTROY/PADDING), cover traffic |
| `nbf-cli` | Binary `nbf` (node/send/demo) |

## Bảo đảm ẩn danh (mức MVP)

- **Cell cố định 1280B** — không rò kích thước message.
- **Cover traffic** — PADDING trên link khi rảnh + DROP mồi trên circuit.
- **Sphinx 1-lượt** — mỗi hop chỉ biết prev/next; không ai thấy full route.
- **Mật mã lai** — X25519 + ML-KEM-768: an toàn cả pre- và post-quantum.

### Giới hạn (ghi rõ — trung thực về phạm vi)

- Test `trung_gian_khong_thay_plaintext` assert `Stats.relayed > 0` — chứng minh RELAY
  đi qua hop, KHÔNG chứng minh trực tiếp "hop không đọc được plaintext". Bằng chứng nằm
  ở tầng thiết kế: mỗi hop chỉ giữ `k_fwd/k_bwd` sinh từ shared secret riêng của nó
  (test AEAD `relay_forward_then_backward_roundtrip` chứng minh onion mở đúng).
- Tầng link Noise-IK với fallback cell rõ cho MVP localhost/LAN — mạng lộ phải bật
  session Noise bắt buộc (v2).
- Chưa có: defragment window chống timing analysis tinh vi, bandwidth limit,
  authentication giữa user circuits, giao diện streaming đa năng.

## Chạy test

```bash
cargo test --workspace   # 27+ test: crypto 16, dht 1, net lib 6+2, e2e 6-node 2, cover 2
cargo test -p nbf-net --test circuit -- --nocapture   # e2e 6 node thật
```

## License

Dual-licensed: [MIT](LICENSE-MIT) hoặc [Apache-2.0](LICENSE-APACHE) — tùy chọn.
