use anyhow::Result;
use protocol::wire::ControlMessage;
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};
use transport::{
    auth::create_insecure_client_config,
    connection::Client,
    crypto::{load_or_generate_identity, save_trusted_cert},
    pairing::{client_pair, recv_msg, send_msg},
    stun::stun_query,
};

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
    std::fs::create_dir_all(&certs_dir)?;
    save_trusted_cert(&certs_dir, &server_name, &server_cert)?;
    println!("Paired with {} — server cert saved", server);

    Ok(())
}
