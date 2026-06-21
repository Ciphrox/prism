use std::net::Ipv4Addr;
use transport::{
    auth::{create_insecure_client_config, create_insecure_server_config},
    connection::{Client, Server},
    crypto::generate_identity,
    pairing::{PairingState, client_pair, server_pair},
};

#[tokio::test(flavor = "multi_thread")]
async fn test_pairing_success() {
    let (server_cert, server_key) = generate_identity("server").unwrap();
    let (client_cert, client_key) = generate_identity("client").unwrap();

    let server_config = create_insecure_server_config(server_cert.clone(), server_key).unwrap();
    let server = Server::bind("127.0.0.1:0", server_config).unwrap();
    let port = server.local_addr().unwrap().port();
    let addr = format!("127.0.0.1:{}", port);

    let pairing_state = PairingState::new();
    let pin = pairing_state.pin().to_string();

    let server_cert_for_server = server_cert.clone();
    let client_cert_for_server = client_cert.clone();
    let client_ip = Ipv4Addr::new(100, 64, 0, 2);
    let subnet_mask = Ipv4Addr::new(255, 255, 255, 0);

    let server_task = tokio::spawn(async move {
        let (conn, _peer) = server.accept().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let result = server_pair(
            &mut send,
            &mut recv,
            &pairing_state,
            "test-server",
            &server_cert_for_server,
            client_ip,
            subnet_mask,
        )
        .await
        .unwrap();

        let (name, cert) = result.expect("pairing should succeed");
        assert_eq!(name, "test-client");
        assert_eq!(cert, client_cert_for_server);
        conn
    });

    let client_config = create_insecure_client_config(client_cert.clone(), client_key).unwrap();
    let mut client = Client::new().unwrap();

    let conn = client.connect(&addr, client_config).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let (server_name, server_cert_received) =
        client_pair(&mut send, &mut recv, &pin, "test-client", &client_cert)
            .await
            .unwrap();

    assert_eq!(server_name, "test-server");
    assert_eq!(server_cert_received, server_cert);

    let _srv_conn = server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wrong_pin_rejected() {
    let (server_cert, server_key) = generate_identity("server").unwrap();
    let (client_cert, client_key) = generate_identity("client").unwrap();

    let server_config = create_insecure_server_config(server_cert.clone(), server_key).unwrap();
    let server = Server::bind("127.0.0.1:0", server_config).unwrap();
    let port = server.local_addr().unwrap().port();
    let addr = format!("127.0.0.1:{}", port);

    let pairing_state = PairingState::new();
    let wrong_pin = "000000";

    let server_cert_for_server = server_cert.clone();
    let client_ip = Ipv4Addr::new(100, 64, 0, 2);
    let subnet_mask = Ipv4Addr::new(255, 255, 255, 0);

    let server_task = tokio::spawn(async move {
        let (conn, _peer) = server.accept().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let result = server_pair(
            &mut send,
            &mut recv,
            &pairing_state,
            "test-server",
            &server_cert_for_server,
            client_ip,
            subnet_mask,
        )
        .await
        .unwrap();

        assert!(result.is_none(), "server should reject wrong PIN");
        conn
    });

    let client_config = create_insecure_client_config(client_cert.clone(), client_key).unwrap();
    let mut client = Client::new().unwrap();
    let conn = client.connect(&addr, client_config).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let result = client_pair(&mut send, &mut recv, wrong_pin, "test-client", &client_cert).await;

    assert!(result.is_err(), "client_pair should fail with wrong PIN");

    let _srv_conn = server_task.await.unwrap();
}
