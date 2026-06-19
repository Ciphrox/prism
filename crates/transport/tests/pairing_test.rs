use transport::{
    auth::{create_insecure_client_config, create_insecure_server_config},
    connection::{Client, Server},
    crypto::generate_identity,
    pairing::{PairingState, client_pair, server_pair},
};

#[tokio::test]
async fn test_connection_accept() {
    let (server_cert, server_key) = generate_identity("server").unwrap();
    let (client_cert, client_key) = generate_identity("client").unwrap();

    let server_config = create_insecure_server_config(server_cert.clone(), server_key).unwrap();
    let server = Server::bind("127.0.0.1:0", server_config).unwrap();
    let port = server.local_addr().unwrap().port();
    let addr = format!("127.0.0.1:{}", port);

    let pairing_state = PairingState::new();
    let pin = pairing_state.pin().to_string();
    println!("PIN: {}", pin);

    let server_cert_for_server = server_cert.clone();
    let client_cert_for_server = client_cert.clone();

    let server_task = tokio::spawn(async move {
        println!("[server] waiting for connection...");
        let (conn, _peer) = server.accept().await.unwrap();
        println!("[server] accepted, waiting for stream...");
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        println!("[server] got stream, running server_pair...");
        let recieved_client_cert = server_pair(
            &mut send,
            &mut recv,
            &server_cert_for_server,
            &pairing_state,
        )
        .await
        .unwrap();

        assert_eq!(recieved_client_cert, client_cert_for_server);
        println!("[server] pair done, client cert matches");
        conn
    });

    let client_config = create_insecure_client_config(client_cert.clone(), client_key).unwrap();

    let mut client = Client::new().unwrap();

    println!("[client] connecting to {}...", addr);
    let conn = client.connect(&addr, client_config).await.unwrap();
    println!("[client] connected, opening stream...");
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    println!("[client] running client_pair...");
    let (recieved_server_cert, _) = client_pair(&mut send, &mut recv, &pin, &client_cert)
        .await
        .unwrap();

    assert_eq!(recieved_server_cert, server_cert);
    println!("[client] pair done, server cert matches");

    let _srv_conn = server_task.await.unwrap();
    println!("[client] server task joined, done");
}
