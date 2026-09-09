//! Cover traffic: PADDING định kỳ + RELAY DROP (Task 12 điền thật).

use crate::cell::{padding_payload, Cell, Cmd};
use crate::node::Node;
use std::sync::Arc;

pub async fn run_loop(_node: Arc<Node>) {
    // TODO Task 12: PADDING định kỳ + RELAY DROP.
    let _ = (padding_payload, Cmd::Padding as u8);
}
