use anyhow::Result;

use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig, default_runtime};
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};

pub struct Client {
    endpoint: Endpoint,
}
impl Client {
    pub fn new() -> Result<Self> {
        Ok(Self {
            endpoint: Endpoint::client("[::]:0".parse()?)?,
        })
    }

    pub fn from_std_socket(socket: StdUdpSocket) -> Result<Self> {
        let rt = default_runtime().ok_or_else(|| anyhow::anyhow!("No runtime"))?;
        let wrapped = rt.wrap_udp_socket(socket)?;
        let endpoint =
            Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, wrapped, rt)?;

        Ok(Self { endpoint })
    }

    pub async fn connect(&mut self, server_addr: &str, config: ClientConfig) -> Result<Connection> {
        self.endpoint.set_default_client_config(config);

        let addr = server_addr.parse()?;
        let connection = self.endpoint.connect(addr, "prism")?.await?;

        Ok(connection)
    }
}

pub struct Server {
    pub endpoint: Endpoint,
}
impl Server {
    pub fn bind(addr: &str, config: ServerConfig) -> Result<Self> {
        Ok(Self {
            endpoint: Endpoint::server(config, addr.parse()?)?,
        })
    }

    pub fn from_std_socket(socket: StdUdpSocket, config: ServerConfig) -> Result<Self> {
        let rt = default_runtime().ok_or_else(|| anyhow::anyhow!("No runtime"))?;
        let wrapped = rt.wrap_udp_socket(socket)?;
        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(config),
            wrapped,
            rt,
        )?;

        Ok(Self { endpoint })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    pub async fn accept(&self) -> Result<(Connection, SocketAddr)> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("Server dropped"))?;
        let connecting = incoming.accept()?;
        let remote_addr = connecting.remote_address();
        let connection = connecting.await?;

        Ok((connection, remote_addr))
    }
}
