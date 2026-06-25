use anyhow::Result;
use protocol::wire::ControlMessage;
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
};
use transport::{
    auth::{create_insecure_server_config, create_server_config},
    connection::Server,
    crypto::{load_or_generate_identity, load_trusted_certs, save_trusted_cert},
    pairing::{PairingState, recv_msg, send_msg, server_pair},
    stun::{stun_query, udp_poke},
};
use tunnel::device::{TunConfig, TunDevice};

pub async fn pair(listen: &str, config_dir: &Path, name: Option<String>) -> Result<()> {
    let pairing = PairingState::new();
    println!("PIN: {}", pairing.pin());

    let server_name = match name {
        Some(n) => n,
        None => hostname::get()?.to_string_lossy().to_string(),
    };

    let (cert, key) = load_or_generate_identity(config_dir, &server_name)?;

    let stun = stun_query().await?;
    let public_ip = match stun.public.ip() {
        IpAddr::V4(ip) => ip,
        _ => anyhow::bail!("STUN return a non-IPv4 address"),
    };

    let signal_cfg = create_insecure_server_config(cert.clone(), key.clone())?;
    let signal_server = Server::bind(listen, signal_cfg)?;
    let (conn, _peer) = signal_server.accept().await?;

    let (mut send, mut recv) = conn.accept_bi().await?;

    println!("Waiting for client to connect...");
    let client_public = match recv_msg(&mut recv).await? {
        ControlMessage::ClientPublicAddr { ip, port } => (ip, port),
        _ => anyhow::bail!("Expected ClientPublicAddr"),
    };
    send_msg(
        &mut send,
        &ControlMessage::ServerPublicAddr {
            ip: public_ip,
            port: stun.public.port(),
        },
    )
    .await?;
    send.finish()?;
    drop(conn);

    let client_addr = SocketAddr::new(IpAddr::V4(client_public.0), client_public.1);
    udp_poke(&stun.socket, client_addr)?;

    println!("Client public: {}:{}", client_public.0, client_public.1);

    let direct_config = create_insecure_server_config(cert.clone(), key)?;
    let server = Server::from_std_socket(stun.socket, direct_config)?;

    let client_ip = "100.64.0.2".parse()?;
    let subnet_mask = "255.255.255.0".parse()?;

    let (conn, peer) = server.accept().await?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    match server_pair(
        &mut send,
        &mut recv,
        &pairing,
        &server_name,
        &cert,
        client_ip,
        subnet_mask,
    )
    .await?
    {
        Some((client_name, client_cert)) => {
            send.finish()?;

            let certs_dir = config_dir.join("trusted_clients");
            save_trusted_cert(&certs_dir, &client_name, &client_cert)?;
            println!("Paired with {} — client cert saved", peer);
        }
        None => {
            anyhow::bail!("Pairing Rejected");
        }
    }

    Ok(())
}

pub async fn start(config_dir: &Path, signal_port: u16) -> Result<()> {
    let server_name = hostname::get()?.to_string_lossy().to_string();
    let (cert, key) = load_or_generate_identity(config_dir, &server_name)?;

    let trusted = config_dir.join("trusted_clients");
    let trusted_certs = load_trusted_certs(&trusted)?;

    let stun = stun_query().await?;
    let public_ip = match stun.public.ip() {
        IpAddr::V4(ip) => ip,
        _ => anyhow::bail!("STUN returned a non-IPv4 address"),
    };

    let signal_cfg = create_server_config(cert.clone(), key.clone(), trusted_certs.clone())?;

    let signal_server = Server::bind(&format!("0.0.0.0:{}", signal_port), signal_cfg)?;
    println!("Waiting for signal connection on port {}...", signal_port);

    let (conn, _peer) = signal_server.accept().await?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    println!("Signal Connection Established");

    let client_public = match recv_msg(&mut recv).await? {
        ControlMessage::ClientPublicAddr { ip, port } => (ip, port),
        _ => anyhow::bail!("Expected ClientPublicAddr"),
    };
    send_msg(
        &mut send,
        &ControlMessage::ServerPublicAddr {
            ip: public_ip,
            port: stun.public.port(),
        },
    )
    .await?;
    send.finish()?;
    drop(conn);

    let client_addr = SocketAddr::new(IpAddr::V4(client_public.0), client_public.1);
    udp_poke(&stun.socket, client_addr)?;

    let secure_config = create_server_config(cert.clone(), key, trusted_certs)?;
    let server = Server::from_std_socket(stun.socket, secure_config)?;
    let (conn, peer) = server.accept().await?;

    let tun = Arc::new(
        TunDevice::open(&TunConfig {
            ip: "100.64.0.1".parse()?,
            ..Default::default()
        })
        .await?,
    );
    println!("Client connected from {} —  tunnel established", peer);

    let tun_to_client = tokio::spawn({
        let tun = tun.clone();
        let conn = conn.clone();
        async move {
            let mut buf = vec![0u8; 1400];
            loop {
                let n = tun.read(&mut buf).await?;
                conn.send_datagram(buf[..n].to_vec().into())?;
            }

            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        }
    });

    let client_to_tun = tokio::spawn({
        let tun = tun.clone();
        let conn = conn.clone();

        async move {
            loop {
                let mut data = conn.read_datagram().await?.to_vec();
                tun.write(&mut data).await?;
            }

            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down...");
        }
            _ = tun_to_client => {}
            _ = client_to_tun => {}
    }

    Ok(())
}
