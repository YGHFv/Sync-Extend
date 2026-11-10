use crate::{tls, PeerIdentity, Result, SignedHello, TransportError, TransportIdentity};
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    Endpoint, RecvStream, SendStream,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use sync_extend_core_model::ContentId;

pub const MAX_CONTROL_BYTES: usize = 8 * 1024 * 1024 + 4096;
pub const MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024;
const CONTROL_FRAME: u8 = 1;
const BLOCK_FRAME: u8 = 2;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

fn protocol(error: impl std::fmt::Display) -> TransportError {
    TransportError::Connection(error.to_string())
}

fn connect_error(error: quinn::ConnectionError) -> TransportError {
    match error {
        quinn::ConnectionError::Reset
        | quinn::ConnectionError::TimedOut
        | quinn::ConnectionError::ApplicationClosed(_) => protocol(error),
        _ => TransportError::Authorization("QUIC protocol or TLS handshake refused"),
    }
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config.max_concurrent_uni_streams(0u8.into());
    config.max_concurrent_bidi_streams(1u8.into());
    config.max_idle_timeout(Some(IO_TIMEOUT.try_into().expect("fixed timeout")));
    config.keep_alive_interval(Some(Duration::from_secs(10)));
    config.stream_receive_window((128u32 * 1024).into());
    config.receive_window((256u32 * 1024).into());
    Arc::new(config)
}

pub struct Listener {
    endpoint: Endpoint,
}

impl Listener {
    pub fn bind(
        address: SocketAddr,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
    ) -> Result<Self> {
        let crypto = QuicServerConfig::try_from(tls::server(identity, peer)?).map_err(protocol)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(transport());
        Ok(Self {
            endpoint: Endpoint::server(config, address)?,
        })
    }

    pub fn local_address(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    pub async fn accept(
        &self,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
    ) -> Result<Connection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(TransportError::Protocol("listener closed"))?;
        let connection = tokio::time::timeout(IO_TIMEOUT, incoming)
            .await
            .map_err(|_| TransportError::Protocol("handshake timeout"))?
            .map_err(connect_error)?;
        let (send, receive) = tokio::time::timeout(IO_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| TransportError::Protocol("stream timeout"))?
            .map_err(protocol)?;
        Connection::establish(
            self.endpoint.clone(),
            connection,
            send,
            receive,
            identity,
            peer,
            false,
        )
        .await
    }
}

/// One bounded bidirectional stream over mutually authenticated TLS 1.3 QUIC.
pub struct Connection {
    _endpoint: Endpoint,
    connection: quinn::Connection,
    send: SendStream,
    receive: RecvStream,
    channel_binding: ContentId,
    peer: PeerIdentity,
}

impl Connection {
    pub async fn connect(
        address: SocketAddr,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
    ) -> Result<Self> {
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let mut endpoint = Endpoint::client(bind.parse().map_err(protocol)?)?;
        let crypto = QuicClientConfig::try_from(tls::client(identity, peer)?).map_err(protocol)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport());
        endpoint.set_default_client_config(config);
        let connecting = endpoint
            .connect(address, "sync-extend.local")
            .map_err(protocol)?;
        let connection = tokio::time::timeout(IO_TIMEOUT, connecting)
            .await
            .map_err(|_| TransportError::Protocol("handshake timeout"))?
            .map_err(connect_error)?;
        let (send, receive) = connection.open_bi().await.map_err(protocol)?;
        Self::establish(endpoint, connection, send, receive, identity, peer, true).await
    }

    async fn establish(
        endpoint: Endpoint,
        connection: quinn::Connection,
        send: SendStream,
        receive: RecvStream,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
        initiator: bool,
    ) -> Result<Self> {
        let mut exporter = [0u8; 32];
        connection
            .export_keying_material(
                &mut exporter,
                b"EXPORTER-SyncExtend-session-v1",
                identity.peer.space_id.as_str().as_bytes(),
            )
            .map_err(|_| TransportError::Protocol("TLS exporter unavailable"))?;
        let mut result = Self {
            _endpoint: endpoint,
            connection,
            send,
            receive,
            channel_binding: ContentId::hash(&exporter),
            peer: peer.clone(),
        };
        let hello = SignedHello::sign(identity, result.channel_binding.clone())?;
        if initiator {
            result.send_json(&hello).await?;
            result
                .receive_json::<SignedHello>()
                .await?
                .verify(peer, &result.channel_binding)?;
        } else {
            result
                .receive_json::<SignedHello>()
                .await?
                .verify(peer, &result.channel_binding)?;
            result.send_json(&hello).await?;
        }
        Ok(result)
    }

    pub fn peer_identity(&self) -> &PeerIdentity {
        &self.peer
    }
    pub fn channel_binding(&self) -> &ContentId {
        &self.channel_binding
    }

    /// Wait for peer transport acknowledgement before closing the connection.
    /// Application receipts still require their own durable-state validation.
    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish().map_err(protocol)?;
        let stopped = tokio::time::timeout(IO_TIMEOUT, self.send.stopped())
            .await
            .map_err(|_| TransportError::Protocol("finish timeout"))?
            .map_err(protocol)?;
        if stopped.is_some() {
            return Err(TransportError::Protocol("peer stopped outgoing stream"));
        }
        let mut trailing = [0u8; 1];
        let eof = tokio::time::timeout(IO_TIMEOUT, self.receive.read(&mut trailing))
            .await
            .map_err(|_| TransportError::Protocol("peer finish timeout"))?
            .map_err(protocol)?;
        if eof.is_some() {
            return Err(TransportError::Protocol(
                "trailing data after session finish",
            ));
        }
        let _ = self.connection.stable_id();
        Ok(())
    }

    pub async fn send_json<T: Serialize>(&mut self, value: &T) -> Result<()> {
        self.write_frame(
            CONTROL_FRAME,
            &serde_json::to_vec(value)?,
            MAX_CONTROL_BYTES,
        )
        .await
    }

    pub async fn receive_json<T: DeserializeOwned>(&mut self) -> Result<T> {
        Ok(serde_json::from_slice(
            &self.read_frame(CONTROL_FRAME, MAX_CONTROL_BYTES).await?,
        )?)
    }

    /// A peer may perform a bounded native Final before its next control frame.
    /// Length checks still precede allocation; ordinary frames retain 30s I/O.
    pub async fn receive_json_after_application<T: DeserializeOwned>(&mut self) -> Result<T> {
        Ok(serde_json::from_slice(
            &self
                .read_frame_with_timeout(CONTROL_FRAME, MAX_CONTROL_BYTES, Duration::from_secs(300))
                .await?,
        )?)
    }

    pub async fn send_block(&mut self, expected: &ContentId, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || ContentId::hash(bytes) != *expected {
            return Err(TransportError::Protocol("invalid outgoing block"));
        }
        self.write_frame(BLOCK_FRAME, bytes, MAX_BLOCK_BYTES).await
    }

    pub async fn receive_block(
        &mut self,
        expected: &ContentId,
        expected_length: u32,
    ) -> Result<Vec<u8>> {
        if expected_length == 0 || expected_length as usize > MAX_BLOCK_BYTES {
            return Err(TransportError::Limit("expected block length"));
        }
        let bytes = self
            .read_frame(BLOCK_FRAME, expected_length as usize)
            .await?;
        if bytes.len() != expected_length as usize || ContentId::hash(&bytes) != *expected {
            return Err(TransportError::Protocol(
                "received block integrity mismatch",
            ));
        }
        Ok(bytes)
    }

    async fn write_frame(&mut self, kind: u8, bytes: &[u8], maximum: usize) -> Result<()> {
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(TransportError::Limit("outgoing frame length"));
        }
        let mut header = [kind, 0, 0, 0, 0];
        header[1..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
        tokio::time::timeout(IO_TIMEOUT, async {
            self.send.write_all(&header).await.map_err(protocol)?;
            self.send.write_all(bytes).await.map_err(protocol)
        })
        .await
        .map_err(|_| TransportError::Protocol("send timeout"))?
    }

    async fn read_frame(&mut self, kind: u8, maximum: usize) -> Result<Vec<u8>> {
        self.read_frame_with_timeout(kind, maximum, IO_TIMEOUT)
            .await
    }

    async fn read_frame_with_timeout(
        &mut self,
        kind: u8,
        maximum: usize,
        wait: Duration,
    ) -> Result<Vec<u8>> {
        tokio::time::timeout(wait, async {
            let mut header = [0u8; 5];
            self.receive
                .read_exact(&mut header)
                .await
                .map_err(protocol)?;
            let length = u32::from_be_bytes(
                header[1..]
                    .try_into()
                    .map_err(|_| TransportError::Protocol("invalid frame header"))?,
            ) as usize;
            if header[0] != kind {
                return Err(TransportError::Protocol("unexpected frame kind"));
            }
            if length == 0 || length > maximum {
                return Err(TransportError::Limit("incoming frame length"));
            }
            let mut bytes = vec![0u8; length];
            self.receive
                .read_exact(&mut bytes)
                .await
                .map_err(protocol)?;
            Ok(bytes)
        })
        .await
        .map_err(|_| TransportError::Protocol("receive timeout"))?
    }
}
