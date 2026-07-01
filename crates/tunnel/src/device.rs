use std::net::Ipv4Addr;

use tokio_tun::Tun;

pub struct TunDevice {
    inner: Tun,
}

impl TunDevice {
    pub async fn open(cfg: &TunConfig) -> anyhow::Result<Self> {
        let name = cfg.name.clone();
        let ip = cfg.ip;
        let netmask = cfg.netmask;
        let mtu = cfg.mtu;

        let mut tun_vec = tokio::task::spawn_blocking(move || {
            Tun::builder()
                .name(&name)
                .address(ip)
                .netmask(netmask)
                .mtu(mtu as i32)
                .up()
                .build()
        })
        .await
        .map_err(|e| anyhow::anyhow!("TUN builder task failed: {}", e))??;

        let tun = tun_vec
            .pop()
            .ok_or_else(|| anyhow::anyhow!("no Tun Device Created"))?;

        Ok(Self { inner: tun })
    }

    pub async fn read(&self, buf: &mut [u8]) -> anyhow::Result<usize> {
        Ok(self.inner.recv(buf).await?)
    }

    pub async fn write(&self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.inner.send_all(buf).await?;
        Ok(())
    }

    pub fn name(&self) -> &str {
        self.inner.name()
    }
}

pub struct TunConfig {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "prism0".to_string(),
            ip: Ipv4Addr::new(100, 64, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1100,
        }
    }
}
