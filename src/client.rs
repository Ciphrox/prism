use anyhow::Result;
use std::path::Path;
use transport::{
    auth::create_insecure_client_config,
    connection::Client,
    crypto::{load_or_generate_identity, save_trusted_cert},
    pairing::client_pair,
};

pub async fn pair(server: &str, pin: &str, config_dir: &Path) -> Result<()> {
    let (cert, key) = load_or_generate_identity(config_dir, "client")?;
    let config = create_insecure_client_config(cert.clone(), key)?;
    let client_name = hostname::get()?.to_string_lossy().to_string();

    let mut client = Client::new()?;
    let conn = client.connect(server, config).await?;

    let (mut send, mut recv) = conn.open_bi().await?;
    let server_cert = client_pair(&mut send, &mut recv, pin, &client_name, &cert).await?;
    send.finish()?;

    let certs_dir = config_dir.join("trusted_servers");
    std::fs::create_dir_all(&certs_dir)?;
    save_trusted_cert(&certs_dir, "server", &server_cert)?;
    println!("Paired with {} — server cert saved", server);

    Ok(())
}
