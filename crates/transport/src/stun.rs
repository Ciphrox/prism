use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

use anyhow::Result;
use socket2::SockRef;
use stunclient::StunClient;

pub struct StunResult {
    pub socket: UdpSocket,
    pub public: SocketAddr,
}

pub async fn stun_query() -> Result<StunResult> {
    let (socket, public) = tokio::task::spawn_blocking(|| -> Result<(UdpSocket, SocketAddr)> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let mark = 0xC0DE007;
        SockRef::from(&socket).set_mark(mark)?;

        let stun_addr = "stun.l.google.com:19302"
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to resolve STUN server"))?;

        let client = StunClient::new(stun_addr);
        let public = client
            .query_external_address(&socket)
            .map_err(|e| anyhow::anyhow!("STUN: {e}"))?;

        Ok((socket, public))
    })
    .await??;
    Ok(StunResult { socket, public })
}

pub fn udp_poke(socket: &std::net::UdpSocket, addr: SocketAddr) -> Result<()> {
    socket.send_to(&[0u8], addr)?;
    Ok(())
}
