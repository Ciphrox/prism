use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TunnelPacket {
    pub seq: u64,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ControlMessage {
    ClientPairHello {
        msg: Vec<u8>,
    },

    ServerPairHello {
        msg: Vec<u8>,
    },

    PairRequest {
        client_name: String,
        client_cert_der: Vec<u8>,
        mac: Vec<u8>,
    },

    PairAccept {
        server_cert_der: Vec<u8>,
        assigned_ip: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        mac: Vec<u8>,
    },

    PairReject {
        reason: String,
    },
}
