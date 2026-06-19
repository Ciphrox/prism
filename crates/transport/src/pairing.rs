use std::time::{Duration, Instant};

use anyhow::Result;
use quinn::{RecvStream, SendStream};
use rand::RngExt;
use spake2::{Ed25519Group, Identity, Password, Spake2};

const PIN_LENGTH: usize = 6;
const PIN_EXPIRY_SECS: u64 = 300;

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

    pub fn is_valid(&self, input: &str) -> bool {
        self.pin == input && Instant::now() < self.expires_at
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
    client_cert_der: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (state, msg1) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(pin.as_bytes()),
        &Identity::new(b"prism"),
    );

    send.write_all(&msg1).await?;

    let mut buf = vec![0u8; 33];
    recv.read_exact(&mut buf).await?;

    let _key = state
        .finish(&buf)
        .map_err(|e| anyhow::anyhow!("SPAKE2 failed {}", e))?;

    send.write_all(client_cert_der).await?;
    send.finish()?;
    let server_cert = recv.read_to_end(u16::MAX.into()).await?;

    Ok((server_cert, client_cert_der.to_vec()))
}

pub async fn server_pair(
    send: &mut SendStream,
    recv: &mut RecvStream,
    server_cert_der: &[u8],
    state: &PairingState,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 33];
    recv.read_exact(&mut buf).await?;

    let (s, msg1) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(state.pin.as_bytes()),
        &Identity::new(b"prism"),
    );
    send.write_all(&msg1).await?;

    let _key = s
        .finish(&buf)
        .map_err(|e| anyhow::anyhow!("SPAKE2 failed {}", e))?;

    let client_cert = recv.read_to_end(u16::MAX.into()).await?;
    send.write_all(server_cert_der).await?;
    send.finish()?;

    Ok(client_cert)
}
