use anyhow::Result;

use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use std::net::SocketAddr;

pub struct Client {
    endpoint: Endpoint,
}
impl Client {
    pub fn new() -> Result<Self> {
        Ok(Self {
            endpoint: Endpoint::client("[::]:0".parse()?)?,
        })
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
