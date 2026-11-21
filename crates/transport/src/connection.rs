use crate::{
    application_budget::{budget_error, Direction, FrameClass, FrameContext},
    tls, ApplicationBudget, FramePermit, PeerIdentity, ProducerKind, Result, SignedHello,
    TransportError, TransportIdentity,
};
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    Endpoint, RecvStream, SendStream,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{io::Write, net::SocketAddr, sync::Arc, time::Duration};
use sync_extend_core_model::{ContentId, EntryId};

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
    budget: Option<Arc<ApplicationBudget>>,
}

impl Listener {
    pub fn bind(
        address: SocketAddr,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
    ) -> Result<Self> {
        Self::bind_with_budget(address, identity, peer, None)
    }

    pub fn bind_with_budget(
        address: SocketAddr,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
        budget: Option<Arc<ApplicationBudget>>,
    ) -> Result<Self> {
        if let Some(budget) = &budget {
            budget.verify_connection(identity, peer)?;
        }
        let crypto = QuicServerConfig::try_from(tls::server(identity, peer)?).map_err(protocol)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(transport());
        Ok(Self {
            endpoint: Endpoint::server(config, address)?,
            budget,
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
        if let Some(budget) = &self.budget {
            budget.verify_connection(identity, peer)?;
        }
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
            self.budget.clone(),
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
    initiated: bool,
    observation: Option<crate::observation::ObservedConnection>,
    budget: Option<Arc<ApplicationBudget>>,
    nonce: EntryId,
}

impl Connection {
    pub async fn connect(
        address: SocketAddr,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
    ) -> Result<Self> {
        Self::connect_with_budget(address, identity, peer, None).await
    }

    pub async fn connect_with_budget(
        address: SocketAddr,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
        budget: Option<Arc<ApplicationBudget>>,
    ) -> Result<Self> {
        if let Some(budget) = &budget {
            budget.verify_connection(identity, peer)?;
        }
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
        Self::establish(
            endpoint, connection, send, receive, identity, peer, true, budget,
        )
        .await
    }

    async fn establish(
        endpoint: Endpoint,
        connection: quinn::Connection,
        send: SendStream,
        receive: RecvStream,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
        initiator: bool,
        budget: Option<Arc<ApplicationBudget>>,
    ) -> Result<Self> {
        if let Some(budget) = &budget {
            budget.verify_connection(identity, peer)?;
        }
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
            initiated: initiator,
            observation: None,
            budget,
            nonce: EntryId::random()?,
        };
        // Signing allocates too: both complete frame liabilities are committed
        // before preparing the application identity exchange.
        let outgoing = result.reserve_outgoing_json(ProducerKind::AuthenticationControl)?;
        let incoming = result.reserve_incoming_json(ProducerKind::AuthenticationControl)?;
        let hello = SignedHello::sign(identity, result.channel_binding.clone())?;
        if initiator {
            result.send_json_with_permit(outgoing, &hello).await?;
            result
                .receive_json_with_permit::<SignedHello>(incoming)
                .await?
                .verify(peer, &result.channel_binding)?;
        } else {
            result
                .receive_json_with_permit::<SignedHello>(incoming)
                .await?
                .verify(peer, &result.channel_binding)?;
            result.send_json_with_permit(outgoing, &hello).await?;
        }
        // Before this point even a valid TLS peer has not completed the signed
        // application identity exchange and must never produce a sample.
        result.observation = crate::observation::ObservedConnection::authenticated();
        result.observe();
        Ok(result)
    }

    fn observe(&self) {
        if let Some(observation) = &self.observation {
            observation.record(
                &self._endpoint,
                &self.connection,
                &self.peer,
                &self.channel_binding,
                self.initiated,
            );
        }
    }

    fn observe_result(&self, success: bool) {
        if !success {
            if let Some(observation) = &self.observation {
                observation.failed();
            }
        }
        self.observe();
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
        let result = self.finish_inner().await;
        if let Some(observation) = &self.observation {
            if result.is_ok() {
                observation.finished();
            } else {
                observation.failed();
            }
        }
        self.observe();
        result
    }

    async fn finish_inner(&mut self) -> Result<()> {
        let permit = self.reserve(
            ProducerKind::EndOfSessionProbe,
            Direction::Receive,
            FrameClass::Probe,
            1,
            None,
        )?;
        self.check_permit(&permit, Direction::Receive, FrameClass::Probe, None)?;
        let wait = self.bounded_wait(IO_TIMEOUT)?;
        self.send.finish().map_err(protocol)?;
        let stopped = tokio::time::timeout(wait, self.send.stopped())
            .await
            .map_err(|_| TransportError::Protocol("finish timeout"))?
            .map_err(protocol)?;
        if stopped.is_some() {
            return Err(TransportError::Protocol("peer stopped outgoing stream"));
        }
        self.check_permit(&permit, Direction::Receive, FrameClass::Probe, None)?;
        let mut trailing = [0u8; 1];
        let eof = tokio::time::timeout(
            self.bounded_wait(IO_TIMEOUT)?,
            self.receive.read(&mut trailing),
        )
        .await
        .map_err(|_| TransportError::Protocol("peer finish timeout"))?
        .map_err(protocol)?;
        if eof.is_some() {
            return Err(TransportError::Protocol(
                "trailing data after session finish",
            ));
        }
        Ok(())
    }

    pub async fn send_json<T: Serialize>(&mut self, value: &T) -> Result<()> {
        self.require_unselected()?;
        let permit = self.reserve_outgoing_json(ProducerKind::DirectFileControl)?;
        self.send_json_with_permit(permit, value).await
    }

    pub async fn receive_json<T: DeserializeOwned>(&mut self) -> Result<T> {
        self.require_unselected()?;
        let permit = self.reserve_incoming_json(ProducerKind::DirectFileControl)?;
        self.receive_json_with_permit(permit).await
    }

    /// A peer may perform a bounded native Final before its next control frame.
    /// Length checks still precede allocation; ordinary frames retain 30s I/O.
    pub async fn receive_json_after_application<T: DeserializeOwned>(&mut self) -> Result<T> {
        self.require_unselected()?;
        let permit = self.reserve_incoming_json(ProducerKind::DirectFileControl)?;
        self.receive_json_after_application_with_permit(permit)
            .await
    }

    pub async fn send_block(&mut self, expected: &ContentId, bytes: &[u8]) -> Result<()> {
        self.require_unselected()?;
        let length = u32::try_from(bytes.len()).map_err(protocol)?;
        let permit =
            self.reserve_outgoing_block(ProducerKind::DirectFileBlock, expected, length)?;
        self.send_block_with_permit(permit, expected, bytes).await
    }

    pub async fn receive_block(
        &mut self,
        expected: &ContentId,
        expected_length: u32,
    ) -> Result<Vec<u8>> {
        self.require_unselected()?;
        let permit =
            self.reserve_incoming_block(ProducerKind::DirectFileBlock, expected, expected_length)?;
        self.receive_block_with_permit(permit, expected, expected_length)
            .await
    }

    fn require_unselected(&self) -> Result<()> {
        if self.budget.is_some() {
            return Err(budget_error(
                "selected application budget requires a typed producer permit",
            ));
        }
        Ok(())
    }

    fn bounded_wait(&self, requested: Duration) -> Result<Duration> {
        self.budget
            .as_ref()
            .map_or(Ok(requested), |budget| budget.bounded_wait(requested))
    }

    fn reserve(
        &self,
        producer: ProducerKind,
        direction: Direction,
        class: FrameClass,
        reserved_bytes: u64,
        content_id: Option<ContentId>,
    ) -> Result<FramePermit> {
        if producer.frame_class() != class {
            return Err(budget_error("producer differs from requested frame class"));
        }
        let reservation = self
            .budget
            .as_ref()
            .map(|budget| {
                budget.reserve(FrameContext {
                    connection: self.nonce.clone(),
                    channel: self.channel_binding.clone(),
                    producer,
                    direction,
                    reserved_bytes,
                    content_id: content_id.clone(),
                })
            })
            .transpose()?;
        Ok(FramePermit {
            producer: Some(producer),
            class,
            direction,
            connection: self.nonce.clone(),
            channel: self.channel_binding.clone(),
            reserved_bytes,
            content_id,
            reservation,
        })
    }

    pub fn reserve_outgoing_json(&self, producer: ProducerKind) -> Result<FramePermit> {
        self.reserve_json(producer, Direction::Send)
    }

    pub fn reserve_incoming_json(&self, producer: ProducerKind) -> Result<FramePermit> {
        self.reserve_json(producer, Direction::Receive)
    }

    fn reserve_json(&self, producer: ProducerKind, direction: Direction) -> Result<FramePermit> {
        let maximum = self
            .budget
            .as_ref()
            .map_or(Ok(producer.maximum_frame_bytes()), |budget| {
                budget.frame_bound(producer)
            })?;
        self.reserve(producer, direction, FrameClass::Control, maximum, None)
    }

    pub fn reserve_outgoing_block(
        &self,
        producer: ProducerKind,
        expected: &ContentId,
        length: u32,
    ) -> Result<FramePermit> {
        self.reserve_block(producer, Direction::Send, expected, length)
    }

    pub fn reserve_incoming_block(
        &self,
        producer: ProducerKind,
        expected: &ContentId,
        length: u32,
    ) -> Result<FramePermit> {
        self.reserve_block(producer, Direction::Receive, expected, length)
    }

    fn reserve_block(
        &self,
        producer: ProducerKind,
        direction: Direction,
        expected: &ContentId,
        length: u32,
    ) -> Result<FramePermit> {
        if length == 0 || length as usize > MAX_BLOCK_BYTES {
            return Err(TransportError::Limit("expected block length"));
        }
        let bytes = u64::from(length)
            .checked_add(5)
            .ok_or_else(|| budget_error("block frame liability overflow"))?;
        self.reserve(
            producer,
            direction,
            FrameClass::Block,
            bytes,
            Some(expected.clone()),
        )
    }

    /// Commit every block liability before any signed batch solicitation.
    /// A rejected later permit leaves earlier reservations charged and unused.
    pub fn reserve_incoming_blocks<'a>(
        &self,
        producer: ProducerKind,
        blocks: impl IntoIterator<Item = (&'a ContentId, u32)>,
    ) -> Result<Vec<FramePermit>> {
        if producer.frame_class() != FrameClass::Block {
            return Err(budget_error(
                "batch producer differs from block frame class",
            ));
        }
        let mut retained = Vec::new();
        let mut sum = 0u64;
        for (id, length) in blocks {
            if retained.len() >= crate::MAX_ORIGINAL_CONTENT_CHUNKS
                || length == 0
                || length as usize > MAX_BLOCK_BYTES
            {
                return Err(TransportError::Limit("bounded incoming block batch"));
            }
            sum = sum
                .checked_add(
                    u64::from(length)
                        .checked_add(5)
                        .ok_or_else(|| budget_error("batch frame liability overflow"))?,
                )
                .ok_or_else(|| budget_error("batch frame liability sum overflow"))?;
            retained
                .try_reserve(1)
                .map_err(|_| TransportError::Limit("bounded block permit list allocation"))?;
            retained.push((id, length));
        }
        let mut permits = Vec::new();
        permits
            .try_reserve_exact(retained.len())
            .map_err(|_| TransportError::Limit("bounded block permit list allocation"))?;
        for (id, length) in retained {
            permits.push(self.reserve_incoming_block(producer, id, length)?);
        }
        Ok(permits)
    }

    fn check_permit(
        &self,
        permit: &FramePermit,
        direction: Direction,
        class: FrameClass,
        content_id: Option<&ContentId>,
    ) -> Result<()> {
        let producer = permit
            .producer
            .ok_or_else(|| budget_error("frame permit has no registered producer"))?;
        if permit.connection != self.nonce
            || permit.channel != self.channel_binding
            || permit.direction != direction
            || permit.class != class
            || producer.frame_class() != class
            || permit.content_id.as_ref() != content_id
        {
            return Err(budget_error(
                "frame permit connection/channel/kind/content differs",
            ));
        }
        match (&self.budget, &permit.reservation) {
            (Some(budget), Some(reservation))
                if reservation.frame
                    == (FrameContext {
                        connection: permit.connection.clone(),
                        channel: permit.channel.clone(),
                        producer,
                        direction,
                        reserved_bytes: permit.reserved_bytes,
                        content_id: permit.content_id.clone(),
                    }) =>
            {
                budget.check_use(reservation)
            }
            (None, None) => Ok(()),
            _ => Err(budget_error("frame permit durable issuer differs")),
        }
    }

    pub async fn send_json_with_permit<T: Serialize>(
        &mut self,
        permit: FramePermit,
        value: &T,
    ) -> Result<()> {
        self.check_permit(&permit, Direction::Send, FrameClass::Control, None)?;
        let maximum = usize::try_from(
            permit
                .reserved_bytes
                .checked_sub(5)
                .ok_or_else(|| budget_error("control frame cap smaller than header"))?,
        )
        .map_err(budget_error)?;
        let mut encoded = BoundedJson {
            bytes: Vec::new(),
            maximum,
        };
        encoded
            .bytes
            .try_reserve_exact(maximum)
            .map_err(|_| TransportError::Limit("bounded outgoing JSON allocation"))?;
        if let Err(error) = serde_json::to_writer(&mut encoded, value) {
            self.observe_result(false);
            return Err(error.into());
        }
        self.write_frame(permit, CONTROL_FRAME, &encoded.bytes, maximum)
            .await
    }

    pub async fn receive_json_with_permit<T: DeserializeOwned>(
        &mut self,
        permit: FramePermit,
    ) -> Result<T> {
        self.receive_json_inner(permit, IO_TIMEOUT).await
    }

    pub async fn receive_json_after_application_with_permit<T: DeserializeOwned>(
        &mut self,
        permit: FramePermit,
    ) -> Result<T> {
        self.receive_json_inner(permit, Duration::from_secs(300))
            .await
    }

    async fn receive_json_inner<T: DeserializeOwned>(
        &mut self,
        permit: FramePermit,
        wait: Duration,
    ) -> Result<T> {
        self.check_permit(&permit, Direction::Receive, FrameClass::Control, None)?;
        let maximum = usize::try_from(
            permit
                .reserved_bytes
                .checked_sub(5)
                .ok_or_else(|| budget_error("control frame cap smaller than header"))?,
        )
        .map_err(budget_error)?;
        let result = self
            .read_frame(permit, CONTROL_FRAME, maximum, wait)
            .await
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into));
        self.observe_result(result.is_ok());
        result
    }

    pub async fn send_block_with_permit(
        &mut self,
        permit: FramePermit,
        expected: &ContentId,
        bytes: &[u8],
    ) -> Result<()> {
        self.check_permit(&permit, Direction::Send, FrameClass::Block, Some(expected))?;
        let exact_bytes = u64::try_from(bytes.len())
            .ok()
            .and_then(|length| length.checked_add(5));
        if bytes.is_empty()
            || bytes.len() > MAX_BLOCK_BYTES
            || exact_bytes != Some(permit.reserved_bytes)
            || ContentId::hash(bytes) != *expected
        {
            self.observe_result(false);
            return Err(TransportError::Protocol(
                "invalid outgoing block or exact permit length",
            ));
        }
        self.write_frame(permit, BLOCK_FRAME, bytes, MAX_BLOCK_BYTES)
            .await
    }

    pub async fn receive_block_with_permit(
        &mut self,
        permit: FramePermit,
        expected: &ContentId,
        expected_length: u32,
    ) -> Result<Vec<u8>> {
        self.check_permit(
            &permit,
            Direction::Receive,
            FrameClass::Block,
            Some(expected),
        )?;
        if expected_length == 0
            || expected_length as usize > MAX_BLOCK_BYTES
            || u64::from(expected_length) + 5 != permit.reserved_bytes
        {
            return Err(TransportError::Limit("incoming block exact permit length"));
        }
        let bytes = self
            .read_frame(permit, BLOCK_FRAME, expected_length as usize, IO_TIMEOUT)
            .await?;
        if bytes.len() != expected_length as usize || ContentId::hash(&bytes) != *expected {
            self.observe_result(false);
            return Err(TransportError::Protocol(
                "received block integrity mismatch",
            ));
        }
        Ok(bytes)
    }

    async fn write_frame(
        &mut self,
        permit: FramePermit,
        kind: u8,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<()> {
        let class = if kind == CONTROL_FRAME {
            FrameClass::Control
        } else {
            FrameClass::Block
        };
        self.check_permit(&permit, Direction::Send, class, permit.content_id.as_ref())?;
        if bytes.is_empty() || bytes.len() > maximum {
            self.observe_result(false);
            return Err(TransportError::Limit("outgoing frame length"));
        }
        let mut header = [kind, 0, 0, 0, 0];
        header[1..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
        let result = tokio::time::timeout(self.bounded_wait(IO_TIMEOUT)?, async {
            self.send.write_all(&header).await.map_err(protocol)?;
            self.check_permit(&permit, Direction::Send, class, permit.content_id.as_ref())?;
            self.send.write_all(bytes).await.map_err(protocol)
        })
        .await
        .unwrap_or_else(|_| Err(TransportError::Protocol("send timeout")));
        self.observe_result(result.is_ok());
        result
    }

    async fn read_frame(
        &mut self,
        permit: FramePermit,
        kind: u8,
        maximum: usize,
        wait: Duration,
    ) -> Result<Vec<u8>> {
        let class = if kind == CONTROL_FRAME {
            FrameClass::Control
        } else {
            FrameClass::Block
        };
        self.check_permit(
            &permit,
            Direction::Receive,
            class,
            permit.content_id.as_ref(),
        )?;
        let result = tokio::time::timeout(self.bounded_wait(wait)?, async {
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
            if class == FrameClass::Block && length as u64 + 5 != permit.reserved_bytes {
                return Err(budget_error(
                    "incoming block header differs from exact reservation",
                ));
            }
            self.check_permit(
                &permit,
                Direction::Receive,
                class,
                permit.content_id.as_ref(),
            )?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| TransportError::Limit("bounded incoming frame allocation"))?;
            bytes.resize(length, 0);
            self.receive
                .read_exact(&mut bytes)
                .await
                .map_err(protocol)?;
            Ok(bytes)
        })
        .await
        .unwrap_or_else(|_| Err(TransportError::Protocol("receive timeout")));
        self.observe_result(result.is_ok());
        result
    }
}

struct BoundedJson {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > self.maximum)
        {
            return Err(std::io::Error::other(
                "JSON exceeds reserved control frame cap",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(observation) = &self.observation {
            observation.dropped();
        }
        self.observe();
    }
}
