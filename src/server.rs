use anyhow::Result;
use protocol::wire::ControlMessage;
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
};
use transport::{
    auth::create_insecure_server_config,
    connection::Server,
    crypto::{load_or_generate_identity, save_trusted_cert},
    pairing::{PairingState, recv_msg, send_msg, server_pair},
    stun::{stun_query, udp_poke},
};

pub async fn pair(listen: &str, config_dir: &Path) -> Result<()> {
    let pairing = PairingState::new();
    println!("PIN: {}", pairing.pin());

    let server_name = hostname::get()?.to_string_lossy().to_string();

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
            fs::create_dir_all(&certs_dir)?;

            save_trusted_cert(&certs_dir, &client_name, &client_cert)?;
            println!("Paired with {} — client cert saved", peer);
        }
        None => {
            anyhow::bail!("Pairing Rejected");
        }
    }

    Ok(())
}
