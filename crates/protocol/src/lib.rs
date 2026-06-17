use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct TunnelPacket {
    pub seq: u64,
    pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum ControlMessage {
    PairRequest {
        pin: String,
        client_name: String,
        client_cert_der: Vec<u8>,
    },
    PairAccept {
        server_cert_der: Vec<u8>,
        assigned_ip: Ipv4Addr,
        subnet_mask: Ipv4Addr,
    },

    PairReject {
        // TODO: update properly later
        reason: String,
    },
    SessionReady {
        assigned_ip: Ipv4Addr,
        subnet_mask: Ipv4Addr,
    },
}
