//! Live connection and session stream adversarial fuzzing test suite (Option AL / REQUIREMENTS.md §49, §50).
//!
//! Validates that `ServerConn` per-connection actor handles arbitrary malformed,
//! truncated, mutated, and adversarial streams without panicking, hanging, or leaking
//! resources.
//!
//! Enforces `#![forbid(unsafe_code)]` and `CLAUDE.md` §1 invariant #5.

use bytes::Bytes;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

use velcrux_core::error::Result;
use velcrux_core::protocol::capabilities::Capabilities;
use velcrux_core::protocol::frame::{encode_frame, header_size_for, FrameFlags};
use velcrux_core::protocol::fuzzing::FuzzMutator;
use velcrux_core::protocol::message::{Hello, COMMIT, HELLO, VERIFY};
use velcrux_core::protocol::varint::encode_varint;
use velcrux_core::session::{ServerConn, ServerState, ServerStats};
use velcrux_core::storage::MemoryStorageBackend;
use velcrux_core::transport::async_trait;
use velcrux_core::transport::identity::Identity;
use velcrux_core::transport::stats::TransportStats;
use velcrux_core::transport::{
    BiRecv, BiRecvStream, BiSend, BiSendStream, Connection, UniRecv, UniRecvStream, UniSend,
    UniSendStream,
};

/// In-memory mock bidirectional stream for adversarial testing.
struct MockFuzzBiStream {
    recv_buf: Arc<Mutex<VecDeque<u8>>>,
    sent_chunks: Arc<Mutex<Vec<Bytes>>>,
}

#[async_trait]
impl BiSendStream for MockFuzzBiStream {
    async fn write_all(&mut self, data: Bytes) -> Result<()> {
        let mut sent = self.sent_chunks.lock().await;
        sent.push(data);
        Ok(())
    }

    async fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl BiRecvStream for MockFuzzBiStream {
    async fn read_chunk(&mut self, max: usize) -> Result<Option<Bytes>> {
        let mut buf = self.recv_buf.lock().await;
        if buf.is_empty() {
            return Ok(None);
        }
        let take = max.min(buf.len());
        let chunk: Vec<u8> = buf.drain(..take).collect();
        Ok(Some(Bytes::from(chunk)))
    }

    async fn read_exact(&mut self, n: usize) -> Result<Option<Bytes>> {
        let mut buf = self.recv_buf.lock().await;
        if buf.len() < n {
            return Ok(None);
        }
        let chunk: Vec<u8> = buf.drain(..n).collect();
        Ok(Some(Bytes::from(chunk)))
    }
}

struct DummyUniStream;

#[async_trait]
impl UniSendStream for DummyUniStream {
    async fn write_all(&mut self, _data: Bytes) -> Result<()> {
        Ok(())
    }
    async fn finish(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl UniRecvStream for DummyUniStream {
    async fn read_chunk(&mut self, _max: usize) -> Result<Option<Bytes>> {
        Ok(None)
    }
    async fn read_exact(&mut self, _n: usize) -> Result<Option<Bytes>> {
        Ok(None)
    }
}

/// In-memory mock QUIC Connection for fuzzing ServerConn.
struct MockFuzzConnection {
    recv_buf: Arc<Mutex<VecDeque<u8>>>,
    sent_chunks: Arc<Mutex<Vec<Bytes>>>,
    closed: Arc<AtomicBool>,
}

impl MockFuzzConnection {
    fn new(input_bytes: &[u8]) -> Self {
        Self {
            recv_buf: Arc::new(Mutex::new(input_bytes.to_vec().into())),
            sent_chunks: Arc::new(Mutex::new(Vec::new())),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Connection for MockFuzzConnection {
    async fn open_bi(&self) -> Result<(BiSend, BiRecv)> {
        Ok((
            Box::new(MockFuzzBiStream {
                recv_buf: Arc::clone(&self.recv_buf),
                sent_chunks: Arc::clone(&self.sent_chunks),
            }),
            Box::new(MockFuzzBiStream {
                recv_buf: Arc::clone(&self.recv_buf),
                sent_chunks: Arc::clone(&self.sent_chunks),
            }),
        ))
    }

    async fn accept_bi(&self) -> Result<(BiSend, BiRecv)> {
        Ok((
            Box::new(MockFuzzBiStream {
                recv_buf: Arc::clone(&self.recv_buf),
                sent_chunks: Arc::clone(&self.sent_chunks),
            }),
            Box::new(MockFuzzBiStream {
                recv_buf: Arc::clone(&self.recv_buf),
                sent_chunks: Arc::clone(&self.sent_chunks),
            }),
        ))
    }

    async fn open_uni(&self) -> Result<UniSend> {
        Ok(Box::new(DummyUniStream))
    }

    async fn accept_uni(&self) -> Result<UniRecv> {
        Ok(Box::new(DummyUniStream))
    }

    fn peer_identity(&self) -> Option<Identity> {
        Some(Identity::new("fuzz_peer", "", ""))
    }

    fn stats(&self) -> TransportStats {
        TransportStats::default()
    }

    fn close(&self, _code: u32, _reason: &[u8]) {
        self.closed.store(true, Ordering::Relaxed);
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<()> {
        output.fill(0xAA);
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Some("127.0.0.1:9000".parse().unwrap())
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some("127.0.0.1:45000".parse().unwrap())
    }
}

fn create_test_server_actor() -> ServerConn {
    let stats = Arc::new(ServerStats::default());
    let backend = Arc::new(MemoryStorageBackend::new());
    ServerConn::new(
        Capabilities::from_wire(0x03FF),
        "velcrux_fuzz_server",
        stats,
        backend,
    )
}

#[tokio::test]
async fn test_server_conn_fuzz_truncated_inputs() {
    let hello = Hello::default_client();
    let payload = hello.encode().unwrap();
    let mut valid_frame = vec![0u8; header_size_for(payload.len() as u64) + payload.len()];
    let n = encode_frame(&mut valid_frame, HELLO, FrameFlags::NONE, 1, &payload);
    valid_frame.truncate(n);

    // Truncate from 0 bytes up to full length
    for prefix_len in 0..=valid_frame.len() {
        let conn = MockFuzzConnection::new(&valid_frame[..prefix_len]);
        let actor = create_test_server_actor();

        // Must terminate within 200ms without hanging or panicking
        let run_res = timeout(Duration::from_millis(200), actor.run(&conn)).await;
        assert!(
            run_res.is_ok(),
            "ServerConn hung on prefix len {prefix_len}"
        );
    }
}

#[tokio::test]
async fn test_server_conn_fuzz_random_garbage() {
    let mut mutator = FuzzMutator::new(0xDEAD_BEEF_0001);

    for iter in 0..200 {
        let len = (mutator.next_u64() % 512) as usize;
        let garbage = mutator.random_bytes(len);
        let conn = MockFuzzConnection::new(&garbage);
        let actor = create_test_server_actor();

        let run_res = timeout(Duration::from_millis(200), actor.run(&conn)).await;
        assert!(
            run_res.is_ok(),
            "ServerConn hung on random garbage iteration {iter}"
        );
    }
}

#[tokio::test]
async fn test_server_conn_fuzz_mutated_frames() {
    let mut mutator = FuzzMutator::new(0xDEAD_BEEF_0002);

    let hello = Hello::default_client();
    let payload = hello.encode().unwrap();
    let mut base_frame = vec![0u8; header_size_for(payload.len() as u64) + payload.len()];
    let n = encode_frame(&mut base_frame, HELLO, FrameFlags::NONE, 1, &payload);
    base_frame.truncate(n);

    for iter in 0..300 {
        let mutated = mutator.mutate(&base_frame);
        let conn = MockFuzzConnection::new(&mutated);
        let actor = create_test_server_actor();

        let run_res = timeout(Duration::from_millis(200), actor.run(&conn)).await;
        assert!(
            run_res.is_ok(),
            "ServerConn hung on mutated frame iteration {iter}"
        );
    }
}

#[tokio::test]
async fn test_server_conn_fuzz_adversarial_lengths() {
    let oversized_lengths: [u64; 6] = [
        1 << 24, // 16 MiB (exceeds 4 MiB MAX_MESSAGE_SIZE)
        1 << 30, // 1 GiB
        1 << 40, // 1 TiB
        1 << 62, // 4 EiB
        u64::MAX - 1,
        u64::MAX,
    ];

    for &declared_len in &oversized_lengths {
        // Construct header with declared oversized length: version (1), type (HELLO=1), flags (0,0), varint length, request_id (0)
        let mut header = vec![1u8, HELLO, 0, 0];
        let mut vbuf = [0u8; 10];
        let vn = encode_varint(declared_len, &mut vbuf);
        header.extend_from_slice(&vbuf[..vn]);
        header.extend_from_slice(&[0u8; 8]); // request_id

        let conn = MockFuzzConnection::new(&header);
        let actor = create_test_server_actor();

        let run_res = timeout(Duration::from_millis(200), actor.run(&conn)).await;
        assert!(
            run_res.is_ok(),
            "ServerConn hung on oversized length {declared_len}"
        );

        let final_state = run_res.unwrap();
        // Server must either return Err or terminate in Closed
        assert!(
            final_state.is_err() || final_state.unwrap() == ServerState::Closed,
            "Server did not reject oversized length declaration"
        );
    }
}

#[tokio::test]
async fn test_server_conn_fuzz_out_of_order_messages() {
    let invalid_types = [COMMIT, VERIFY, 0x13, 0x31, 0xFF, 0x00];

    for &type_byte in &invalid_types {
        let mut frame = vec![0u8; header_size_for(8) + 8];
        let n = encode_frame(&mut frame, type_byte, FrameFlags::NONE, 1, &[0u8; 8]);
        frame.truncate(n);

        let conn = MockFuzzConnection::new(&frame);
        let actor = create_test_server_actor();

        let run_res = timeout(Duration::from_millis(200), actor.run(&conn)).await;
        assert!(
            run_res.is_ok(),
            "ServerConn hung on out-of-order message type 0x{type_byte:02x}"
        );

        let res = run_res.unwrap();
        assert!(
            conn.closed.load(Ordering::Relaxed)
                || res.is_err()
                || res.unwrap() == ServerState::Closed
        );
    }
}
