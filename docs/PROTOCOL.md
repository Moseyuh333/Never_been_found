# NBF Wire Protocol v1

Mọi số nguyên little-endian. Cell = datagram UDP trước mã hóa link, đúng 1280 byte.

## 1. Cell
[cid u32][cmd u8][flags u8=0][len u16][payload len byte][zero-pad 1280]
cmd: 1 CREATE, 2 CREATED, 3 DESTROY, 4 RELAY, 5 PADDING.

## 2. Fragmentation (CREATE/CREATED dài)
payload = [total u16][idx u16][chunk ≤ 1268]. Receiver gom theo cid đến đủ `total` mảnh.

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
