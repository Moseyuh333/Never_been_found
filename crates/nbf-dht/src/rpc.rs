//! RPC Kademlia encode/decode + Contact + DhtError.
//! Wire format: magic "NBFR" (4B) + type (1B) + body. Giữ nhị phân gọn, không JSON
//! (chống phân tích, hiệu quả trên UDP).

use nbf_crypto::{Descriptor, NodeId};
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub node_id: NodeId,
    pub ip: [u8; 4],
    pub dht_port: u16,
}

impl Contact {
    pub fn from_desc(d: &Descriptor) -> Contact {
        let ip = match d.cell_addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            _ => [127, 0, 0, 1],
        };
        Contact { node_id: d.node_id, ip, dht_port: d.dht_port }
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::new(self.ip[0], self.ip[1], self.ip[2], self.ip[3]).into(), self.dht_port)
    }
}

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
        match v {
            1 => Ok(RpcType::Ping),
            2 => Ok(RpcType::Pong),
            3 => Ok(RpcType::Store),
            4 => Ok(RpcType::Find),
            5 => Ok(RpcType::Found),
            _ => Err(DhtError::BadType(v)),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RpcMsg {
    Ping { nonce: u64 },
    Pong { nonce: u64 },
    Store { desc: Descriptor },
    Find { key: NodeId, want_value: bool },
    Found { contacts: Vec<Contact>, value: Option<Descriptor> },
}

const MAGIC: [u8; 4] = *b"NBFR";

#[derive(Debug, thiserror::Error)]
pub enum DhtError {
    #[error("RPC sai độ dài: {0}")]
    BadLen(usize),
    #[error("RPC sai loại: {0}")]
    BadType(u8),
    #[error("descriptor sai: {0}")]
    BadDesc(String),
    #[error("I/O: {0}")]
    Io(std::io::Error),
}

/// Mã hóa RPC message thành bytes (magic + type + body).
pub fn rpc_encode(msg: &RpcMsg) -> Vec<u8> {
    use RpcMsg::*;
    let (t, mut body) = match msg {
        Ping { nonce } => (RpcType::Ping, nonce.to_le_bytes().to_vec()),
        Pong { nonce } => (RpcType::Pong, nonce.to_le_bytes().to_vec()),
        Store { desc } => (RpcType::Store, desc.to_bytes()),
        Find { key, want_value } => {
            let mut b = Vec::with_capacity(21);
            b.extend_from_slice(key);
            b.push(*want_value as u8);
            (RpcType::Find, b)
        }
        Found { contacts, value } => {
            let mut b = Vec::new();
            b.extend_from_slice(&(contacts.len() as u16).to_le_bytes());
            for c in contacts {
                b.extend_from_slice(&c.node_id);
                b.extend_from_slice(&c.ip);
                b.extend_from_slice(&c.dht_port.to_le_bytes());
            }
            b.push(value.is_some() as u8);
            if let Some(v) = value {
                b.extend_from_slice(&v.to_bytes());
            }
            (RpcType::Found, b)
        }
    };
    let mut out = Vec::with_capacity(5 + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(t as u8);
    out.append(&mut body);
    out
}

/// Giải mã RPC message từ bytes. Trả lỗi nếu sai magic/type/độ dài.
pub fn rpc_decode(data: &[u8]) -> Result<RpcMsg, DhtError> {
    if data.len() < 5 {
        return Err(DhtError::BadLen(data.len()));
    }
    if data[..4] != MAGIC {
        return Err(DhtError::BadType(data[4]));
    }
    let t = RpcType::try_from(data[4])?;
    let body = &data[5..];
    match t {
        RpcType::Ping => {
            if body.len() != 8 {
                return Err(DhtError::BadLen(body.len()));
            }
            Ok(RpcMsg::Ping { nonce: u64::from_le_bytes(body.try_into().unwrap()) })
        }
        RpcType::Pong => {
            if body.len() != 8 {
                return Err(DhtError::BadLen(body.len()));
            }
            Ok(RpcMsg::Pong { nonce: u64::from_le_bytes(body.try_into().unwrap()) })
        }
        RpcType::Store => Ok(RpcMsg::Store { desc: Descriptor::from_signed_bytes(body).map_err(|e| DhtError::BadDesc(e.to_string()))? }),
        RpcType::Find => {
            if body.len() < 21 {
                return Err(DhtError::BadLen(body.len()));
            }
            let key: NodeId = body[..20].try_into().unwrap();
            let want_value = body[20] != 0;
            Ok(RpcMsg::Find { key, want_value })
        }
        RpcType::Found => {
            if body.len() < 3 {
                return Err(DhtError::BadLen(body.len()));
            }
            let n = u16::from_le_bytes([body[0], body[1]]) as usize;
            let mut o = 2;
            let mut contacts = Vec::with_capacity(n);
            for _ in 0..n {
                if body.len() < o + 26 {
                    return Err(DhtError::BadLen(body.len()));
                }
                let node_id: NodeId = body[o..o + 20].try_into().unwrap();
                let ip: [u8; 4] = body[o + 20..o + 24].try_into().unwrap();
                let dht_port = u16::from_le_bytes([body[o + 24], body[o + 25]]);
                contacts.push(Contact { node_id, ip, dht_port });
                o += 26;
            }
            if o >= body.len() {
                return Err(DhtError::BadLen(body.len()));
            }
            let has_value = body[o] != 0;
            o += 1;
            let value = if has_value {
                if body.len() < o + 1385 {
                    return Err(DhtError::BadLen(body.len()));
                }
                Some(Descriptor::from_signed_bytes(&body[o..o + 1385]).map_err(|e| DhtError::BadDesc(e.to_string()))?)
            } else {
                None
            };
            Ok(RpcMsg::Found { contacts, value })
        }
    }
}

/// Tiện ích: response ping.
pub fn ping_response(nonce: u64) -> RpcMsg {
    RpcMsg::Pong { nonce }
}

/// Tiện ích: response find.
pub fn find_response(contacts: Vec<Contact>, value: Option<Descriptor>) -> RpcMsg {
    RpcMsg::Found { contacts, value }
}