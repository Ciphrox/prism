use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use anyhow::Result;
use bincode::config::standard;
use hmac::{Hmac, KeyInit, Mac};
use protocol::wire::ControlMessage;
use quinn::{RecvStream, SendStream};
use rand::RngExt;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

const PIN_LENGTH: usize = 6;
const PIN_EXPIRY_SECS: u64 = 300;

type HmacSha256 = Hmac<Sha256>;

pub struct PairingState {
    pin: String,
    expires_at: Instant,
}

impl PairingState {
    pub fn new() -> Self {
        let pin: String = (0..PIN_LENGTH)
            .map(|_| rand::rng().random_range('0'..='9'))
            .collect();

        Self {
            pin,
            expires_at: Instant::now() + Duration::from_secs(PIN_EXPIRY_SECS),
        }
    }

    pub fn pin(&self) -> &str {
        &self.pin
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    pub fn is_valid(&self, input: &str) -> bool {
        self.pin == input && !self.is_expired()
    }
}

impl Default for PairingState {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn client_pair(
    send: &mut SendStream,
    recv: &mut RecvStream,
    pin: &str,
    client_name: &str,
    client_cert_der: &[u8],
) -> Result<Vec<u8>> {
    let (client_state, client_share) = Spake2::<Ed25519Group>::start_a(
        &Password::new(pin.as_bytes()),
        &Identity::new(b"prism-client"),
        &Identity::new(b"prism-server"),
    );
    send_msg(send, &ControlMessage::ClientPairHello { msg: client_share }).await?;

    let server_share = match recv_msg(recv).await? {
        ControlMessage::ServerPairHello { msg } => msg,
        ControlMessage::PairReject { reason } => anyhow::bail!("Server Rejected: {}", reason),
        _ => anyhow::bail!("Expected ServerPairHello"),
    };

    let shared_secret = client_state
        .finish(&server_share)
        .map_err(|e| anyhow::anyhow!("SPAKE2 failed {}", e))?;

    let mut mac = HmacSha256::new_from_slice(&shared_secret)?;
    mac.update(client_cert_der);
    let client_mac = mac.finalize().into_bytes().to_vec();

    send_msg(
        send,
        &ControlMessage::PairRequest {
            client_name: client_name.to_string(),
            client_cert_der: client_cert_der.to_vec(),
            mac: client_mac,
        },
    )
    .await?;

    let recieved_msg = recv_msg(recv).await?;
    let server_cert = match recieved_msg {
        ControlMessage::PairAccept {
            server_cert_der,
            mac: server_mac,
            ..
        } => {
            let mut mac_verifier = HmacSha256::new_from_slice(&shared_secret)?;
            mac_verifier.update(&server_cert_der);
            mac_verifier.verify_slice(&server_mac)?;

            server_cert_der
        }
        ControlMessage::PairReject { reason } => {
            anyhow::bail!("Server Rejected pairing: {}", reason);
        }
        _ => anyhow::bail!("Expected PairAccept or PairReject"),
    };

    Ok(server_cert)
}

pub async fn server_pair(
    send: &mut SendStream,
    recv: &mut RecvStream,
    state: &PairingState,
    server_cert_der: &[u8],
    client_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
) -> Result<Option<(String, Vec<u8>)>> {
    if state.is_expired() {
        send_msg(
            send,
            &ControlMessage::PairReject {
                reason: "Pin Expired".into(),
            },
        )
        .await?;

        return Ok(None);
    }

    let client_share = match recv_msg(recv).await? {
        ControlMessage::ClientPairHello { msg } => msg,
        _ => anyhow::bail!("Expected ClientPairHello"),
    };

    let (server_state, server_share) = Spake2::<Ed25519Group>::start_b(
        &Password::new(state.pin.as_bytes()),
        &Identity::new(b"prism-client"),
        &Identity::new(b"prism-server"),
    );
    send_msg(send, &ControlMessage::ServerPairHello { msg: server_share }).await?;

    let shared_secret = server_state
        .finish(&client_share)
        .map_err(|e| anyhow::anyhow!("SPAKE2 failed {}", e))?;

    match recv_msg(recv).await? {
        ControlMessage::PairRequest {
            client_name,
            client_cert_der,
            mac: client_mac,
        } => {
            let mut verifier_mac = HmacSha256::new_from_slice(&shared_secret)?;
            verifier_mac.update(&client_cert_der);
            if verifier_mac.verify_slice(&client_mac).is_err() {
                send_msg(
                    send,
                    &ControlMessage::PairReject {
                        reason: "Invalid Pin".into(),
                    },
                )
                .await?;

                return Ok(None);
            }

            let mut mac = HmacSha256::new_from_slice(&shared_secret)?;
            mac.update(server_cert_der);
            let server_mac = mac.finalize().into_bytes().to_vec();

            send_msg(
                send,
                &ControlMessage::PairAccept {
                    server_cert_der: server_cert_der.to_vec(),
                    assigned_ip: client_ip,
                    subnet_mask,
                    mac: server_mac,
                },
            )
            .await?;

            Ok(Some((client_name, client_cert_der)))
        }
        _ => anyhow::bail!("Expected PairRequest"),
    }
}

// Helpers
async fn send_msg(send: &mut quinn::SendStream, msg: &ControlMessage) -> Result<()> {
    let encoded = bincode::serde::encode_to_vec(msg, standard())?;

    let len_bytes = (encoded.len() as u32).to_le_bytes();

    send.write_all(&len_bytes).await?;
    send.write_all(&encoded).await?;

    Ok(())
}

async fn recv_msg(recv: &mut quinn::RecvStream) -> Result<ControlMessage> {
    let mut len_bytes = [0u8; 4];
    recv.read_exact(&mut len_bytes).await?;
    let msg_len = u32::from_le_bytes(len_bytes) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    recv.read_exact(&mut msg_buf).await?;

    let (decoded, _bytes_read) = bincode::serde::decode_from_slice(&msg_buf, standard())?;

    Ok(decoded)
}
