use anyhow::Result;
use network::routes::PolicyRoute;
use protocol::wire::ControlMessage;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use transport::{
    auth::{create_client_config, create_insecure_client_config},
    connection::Client,
    crypto::{load_or_generate_identity, load_server_cert, save_trusted_cert},
    pairing::{client_pair, recv_msg, send_msg},
    stun::stun_query,
};
use tunnel::device::{TunConfig, TunDevice};

pub async fn pair(server: &str, pin: &str, config_dir: &Path) -> Result<()> {
    let client_name = hostname::get()?.to_string_lossy().to_string();
    let (cert, key) = load_or_generate_identity(config_dir, &client_name)?;

    let stun = stun_query().await?;
    let public_ip = match stun.public.ip() {
        IpAddr::V4(ip) => ip,
        _ => anyhow::bail!("STUN return a non-IPv4 address"),
    };

    let signal_cfg = create_insecure_client_config(cert.clone(), key.clone())?;
    let mut signal_client = Client::new()?;

    let conn = signal_client.connect(server, signal_cfg).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send_msg(
        &mut send,
        &ControlMessage::ClientPublicAddr {
            ip: public_ip,
            port: stun.public.port(),
        },
    )
    .await?;

    let server_public = match recv_msg(&mut recv).await? {
        ControlMessage::ServerPublicAddr { ip, port } => SocketAddr::new(ip.into(), port),
        _ => anyhow::bail!("Expected ServerPublicAddr"),
    };
    send.finish()?;
    drop(conn);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let direct_config = create_insecure_client_config(cert.clone(), key)?;

    let mut direct_client = Client::from_std_socket(stun.socket)?;
    let conn = direct_client
        .connect(&server_public.to_string(), direct_config)
        .await?;

    let (mut send, mut recv) = conn.open_bi().await?;
    let (server_name, server_cert) =
        client_pair(&mut send, &mut recv, pin, &client_name, &cert).await?;
    send.finish()?;

    let certs_dir = config_dir.join("trusted_servers");
    save_trusted_cert(&certs_dir, &server_name, &server_cert)?;
    println!("Paired with {} — server cert saved", server);

    Ok(())
}

pub async fn connect(config_dir: &Path, server_name: &str, server_addr: &str) -> Result<()> {
    let client_name = hostname::get()?.to_string_lossy().to_string();
    let (client_cert, client_key) = load_or_generate_identity(config_dir, &client_name)?;

    let server_cert = load_server_cert(config_dir, server_name)?;
    let client_config =
        create_client_config(client_cert.clone(), client_key.clone(), server_cert.clone())?;

    let stun = stun_query().await?;
    let public_ip = match stun.public.ip() {
        IpAddr::V4(ip) => ip,
        _ => anyhow::bail!("STUN returned a non-IPv4 address"),
    };

    let signal_cfg = create_client_config(client_cert.clone(), client_key.clone(), server_cert)?;

    let mut signal_client = Client::new()?;
    let conn = signal_client.connect(server_addr, signal_cfg).await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    println!("Signal Connection Established");

    send_msg(
        &mut send,
        &ControlMessage::ClientPublicAddr {
            ip: public_ip,
            port: stun.public.port(),
        },
    )
    .await?;
    let server_public = match recv_msg(&mut recv).await? {
        ControlMessage::ServerPublicAddr { ip, port } => SocketAddr::new(ip.into(), port),
        _ => anyhow::bail!("Expected ServerPublicAddr"),
    };

    send.finish()?;
    drop(conn);

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut client = Client::from_std_socket(stun.socket)?;
    let conn = client
        .connect(&server_public.to_string(), client_config)
        .await?;

    let client_ip = Ipv4Addr::new(100, 64, 0, 2);
    let tun = Arc::new(
        TunDevice::open(&TunConfig {
            ip: client_ip,
            ..Default::default()
        })
        .await?,
    );
    let _routes = PolicyRoute::install("prism0").await?;

    println!("Connected to {} —  tunnel established", server_public);

    let tun_to_server = tokio::spawn({
        let tun = tun.clone();
        let conn = conn.clone();
        async move {
            let mut buf = vec![0u8; 1400];
            loop {
                let n = tun.read(&mut buf).await?;
                if let Err(e) = conn.send_datagram(buf[..n].to_vec().into()) {
                    eprintln!("dropped packet ({n} bytes): {e}");
                    continue;
                }
            }

            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        }
    });

    let server_to_tun = tokio::spawn({
        let tun = tun.clone();
        let conn = conn.clone();

        async move {
            loop {
                let mut data = match conn.read_datagram().await {
                    Ok(d) => d.to_vec(),
                    Err(e) => {
                        eprintln!("read_datagram failed: {e}");
                        break;
                    }
                };
                if let Err(e) = tun.write(&mut data).await {
                    eprintln!("tun write failed: {e}");
                    continue;
                }
            }
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down...");
        }
        res = tun_to_server => {
            println!("tun_to_server ended: {:?}", res);
            anyhow::bail!("tun_to_server error");
        }
        res = server_to_tun => {
            println!("server_to_tun ended: {:?}", res);
            anyhow::bail!("server_to_tun error");
        }
    }
    Ok(())
}
