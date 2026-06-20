use anyhow::Result;
use std::{fs, path::Path};
use transport::{
    auth::create_insecure_server_config,
    connection::Server,
    crypto::{load_or_generate_identity, save_trusted_cert},
    pairing::{PairingState, server_pair},
};

pub async fn pair(listen: &str, config_dir: &Path) -> Result<()> {
    let (cert, key) = load_or_generate_identity(config_dir, "server")?;
    let config = create_insecure_server_config(cert.clone(), key)?;
    let server = Server::bind(listen, config)?;
    let addr = server.local_addr()?;

    let client_ip = "100.64.0.2".parse()?;
    let subnet_mask = "255.255.255.0".parse()?;

    let pairing = PairingState::new();
    println!("Listening on {}", addr);
    println!("PIN: {}", pairing.pin());
    println!("Waiting for client to connect...");

    let (conn, peer) = server.accept().await?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    match server_pair(
        &mut send,
        &mut recv,
        &pairing,
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
