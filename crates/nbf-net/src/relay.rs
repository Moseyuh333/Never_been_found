//! Xử lý RELAY: xác định hướng (từ prev/next), lột/bọc onion đúng chiều,
//! seq replay theo chiều, dispatch ECHO/DATA/DROP. Origin nhận chiều về → đẩy stream.
//! (Task 10 điền đầy đủ — hiện là stub để node.rs biên dịch.)

use crate::node::Node;
use crate::Cell;
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn handle(_node: Arc<Node>, _from: SocketAddr, _cell: Cell) {
    // TODO Task 10: dispatch theo hướng prev/next + seq replay + ECHO/DATA/DROP.
}
