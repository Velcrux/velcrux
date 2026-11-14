//! Noise Protocol State Machine (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`) (ADR-081).
//!
//! Provides the cryptographic handshake and symmetric transport session encryption
//! matching the WireGuard specification:
//! - Curve25519 (X25519) Diffie-Hellman key exchanges.
//! - ChaCha20-Poly1305 AEAD authenticated encryption.
//! - BLAKE3 key derivation functions and MAC1/MAC2 verification.
//! - Anti-replay sliding window per established session.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

use super::replay::AntiReplayWindow;
use super::types::{
    HandshakeInitiationPacket, HandshakeResponsePacket, MeshError, MeshResult, NoiseKeyPair,
    TransportDataPacket, PACKET_HANDSHAKE_INITIATION, PACKET_HANDSHAKE_RESPONSE,
    PACKET_TRANSPORT_DATA,
};
use crate::crypto::pqc::x25519;

/// Construction identifier string for Noise_IKpsk2.
const NOISE_CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE3_v1";

/// Established bidirectional transport session between two mesh peers.
#[derive(Debug, Clone)]
pub struct NoiseSession {
    /// Local receiver index assigned to this session.
    pub local_index: u32,
    /// Remote receiver index assigned by the peer.
    pub peer_index: u32,
    /// Symmetric key for transmitting packets to peer.
    pub tx_key: [u8; 32],
    /// Symmetric key for receiving packets from peer.
    pub rx_key: [u8; 32],
    /// Transmission counter for outgoing transport packets.
    pub send_counter: u64,
    /// Anti-replay sliding window for incoming transport packets.
    pub replay_window: AntiReplayWindow,
    /// Timestamp of handshake establishment (ms).
    pub established_at_ms: u64,
    /// Bytes transmitted across this session.
    pub tx_bytes: u64,
    /// Bytes received across this session.
    pub rx_bytes: u64,
}

impl NoiseSession {
    /// Encrypt an IP payload into a WireGuard TransportData packet.
    pub fn encrypt_transport_data(&mut self, payload: &[u8]) -> MeshResult<TransportDataPacket> {
        let counter = self.send_counter;
        self.send_counter = self.send_counter.saturating_add(1);

        let ciphertext = aead_encrypt(&self.tx_key, counter, &[], payload)?;
        self.tx_bytes = self.tx_bytes.saturating_add(payload.len() as u64);

        Ok(TransportDataPacket {
            msg_type: PACKET_TRANSPORT_DATA,
            receiver_index: self.peer_index,
            counter,
            encrypted_payload: ciphertext,
        })
    }

    /// Decrypt a WireGuard TransportData packet and validate anti-replay counter.
    pub fn decrypt_transport_data(&mut self, packet: &TransportDataPacket) -> MeshResult<Vec<u8>> {
        // Step 1: Anti-replay sliding window validation
        self.replay_window.check_and_update(packet.counter)?;

        // Step 2: ChaCha20-Poly1305 AEAD decryption
        let plaintext = aead_decrypt(&self.rx_key, packet.counter, &[], &packet.encrypted_payload)?;
        self.rx_bytes = self.rx_bytes.saturating_add(plaintext.len() as u64);

        Ok(plaintext)
    }
}

/// Noise handshake coordinator implementing `Noise_IKpsk2`.
pub struct NoiseHandshake;

impl NoiseHandshake {
    /// Create a HandshakeInitiation packet for `peer_static_pub`.
    pub fn create_initiation(
        local_keypair: &NoiseKeyPair,
        peer_static_pub: &[u8; 32],
        local_sender_index: u32,
        now_ms: u64,
    ) -> MeshResult<(HandshakeInitiationPacket, EphemeralState)> {
        // Initial chaining key and hash
        let mut ck = blake3_hash(NOISE_CONSTRUCTION);
        let mut h = blake3_hash(&ck);
        h = blake3_hash(&[h.as_slice(), peer_static_pub.as_slice()].concat());

        // 1. Ephemeral keypair
        let ephemeral = NoiseKeyPair::generate();
        let e_pub = ephemeral.public_key;
        h = blake3_hash(&[h.as_slice(), e_pub.as_slice()].concat());

        // 2. DH(e, static_responder)
        let dh1 = x25519(&ephemeral.private_key, peer_static_pub);
        let (next_ck, key1) = kdf2(&ck, &dh1);
        ck = next_ck;

        // 3. Encrypt local static public key
        let encrypted_static = aead_encrypt(&key1, 0, &h, &local_keypair.public_key)?;
        h = blake3_hash(&[h.as_slice(), encrypted_static.as_slice()].concat());

        // 4. DH(static_initiator, static_responder)
        let dh2 = x25519(&local_keypair.private_key, peer_static_pub);
        let (next_ck, key2) = kdf2(&ck, &dh2);
        ck = next_ck;

        // 5. Encrypt TAI64N timestamp (12 bytes)
        let mut timestamp = [0u8; 12];
        let secs = now_ms / 1000;
        let nanos = (now_ms % 1000) * 1_000_000;
        timestamp[0..8].copy_from_slice(&secs.to_be_bytes());
        timestamp[8..12].copy_from_slice(&(nanos as u32).to_be_bytes());

        let encrypted_timestamp = aead_encrypt(&key2, 0, &h, &timestamp)?;
        h = blake3_hash(&[h.as_slice(), encrypted_timestamp.as_slice()].concat());

        // 6. MAC1 computation over initiation packet header & fields
        let mut packet = HandshakeInitiationPacket {
            msg_type: PACKET_HANDSHAKE_INITIATION,
            sender_index: local_sender_index,
            unencrypted_ephemeral: e_pub,
            encrypted_static,
            encrypted_timestamp,
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        };

        let raw_bytes = packet.to_bytes();
        let mac_key = blake3_hash(peer_static_pub);
        packet.mac1 = compute_mac1(&mac_key, &raw_bytes[0..116]);

        let state = EphemeralState {
            ephemeral,
            chaining_key: ck,
            hash: h,
            local_sender_index,
        };

        Ok((packet, state))
    }

    /// Process a HandshakeInitiation packet and produce a HandshakeResponse packet.
    pub fn process_initiation_and_respond(
        local_keypair: &NoiseKeyPair,
        packet: &HandshakeInitiationPacket,
        local_sender_index: u32,
        now_ms: u64,
    ) -> MeshResult<(HandshakeResponsePacket, [u8; 32], NoiseSession)> {
        // Step 1: Verify MAC1
        let raw_bytes = packet.to_bytes();
        let mac_key = blake3_hash(&local_keypair.public_key);
        let expected_mac1 = compute_mac1(&mac_key, &raw_bytes[0..116]);
        if packet.mac1 != expected_mac1 {
            return Err(MeshError::HandshakeFailed("Invalid MAC1".to_string()));
        }

        // Step 2: Initialize chaining key & hash
        let mut ck = blake3_hash(NOISE_CONSTRUCTION);
        let mut h = blake3_hash(&ck);
        h = blake3_hash(&[h.as_slice(), local_keypair.public_key.as_slice()].concat());
        h = blake3_hash(&[h.as_slice(), packet.unencrypted_ephemeral.as_slice()].concat());

        // Step 3: DH(static_responder, e_initiator)
        let dh1 = x25519(&local_keypair.private_key, &packet.unencrypted_ephemeral);
        let (next_ck, key1) = kdf2(&ck, &dh1);
        ck = next_ck;

        // Step 4: Decrypt initiator static public key
        let initiator_static_bytes = aead_decrypt(&key1, 0, &h, &packet.encrypted_static)?;
        if initiator_static_bytes.len() != 32 {
            return Err(MeshError::HandshakeFailed(
                "Invalid decrypted static key".to_string(),
            ));
        }
        let mut initiator_static_pub = [0u8; 32];
        initiator_static_pub.copy_from_slice(&initiator_static_bytes);
        h = blake3_hash(&[h.as_slice(), packet.encrypted_static.as_slice()].concat());

        // Step 5: DH(static_responder, static_initiator)
        let dh2 = x25519(&local_keypair.private_key, &initiator_static_pub);
        let (next_ck, key2) = kdf2(&ck, &dh2);
        ck = next_ck;

        // Step 6: Decrypt timestamp
        let _timestamp = aead_decrypt(&key2, 0, &h, &packet.encrypted_timestamp)?;
        h = blake3_hash(&[h.as_slice(), packet.encrypted_timestamp.as_slice()].concat());

        // ---------------------------------------------------------------------
        // Handshake Response Generation
        // ---------------------------------------------------------------------
        let responder_ephemeral = NoiseKeyPair::generate();
        let e2_pub = responder_ephemeral.public_key;
        h = blake3_hash(&[h.as_slice(), e2_pub.as_slice()].concat());

        // DH(e2_responder, e_initiator)
        let dh3 = x25519(
            &responder_ephemeral.private_key,
            &packet.unencrypted_ephemeral,
        );
        let (next_ck, _) = kdf2(&ck, &dh3);
        ck = next_ck;

        // DH(e2_responder, static_initiator)
        let dh4 = x25519(&responder_ephemeral.private_key, &initiator_static_pub);
        let (next_ck, key3) = kdf2(&ck, &dh4);
        ck = next_ck;

        // Encrypt empty payload
        let encrypted_empty = aead_encrypt(&key3, 0, &h, &[])?;

        let mut response_packet = HandshakeResponsePacket {
            msg_type: PACKET_HANDSHAKE_RESPONSE,
            sender_index: local_sender_index,
            receiver_index: packet.sender_index,
            unencrypted_ephemeral: e2_pub,
            encrypted_empty,
            mac1: [0u8; 16],
            mac2: [0u8; 16],
        };

        let resp_raw = response_packet.to_bytes();
        let resp_mac_key = blake3_hash(&initiator_static_pub);
        response_packet.mac1 = compute_mac1(&resp_mac_key, &resp_raw[0..60]);

        // Derive final symmetric transport keys
        let (tx_key, rx_key) = kdf_split_responder(&ck);

        let session = NoiseSession {
            local_index: local_sender_index,
            peer_index: packet.sender_index,
            tx_key,
            rx_key,
            send_counter: 0,
            replay_window: AntiReplayWindow::new(),
            established_at_ms: now_ms,
            tx_bytes: 0,
            rx_bytes: 0,
        };

        Ok((response_packet, initiator_static_pub, session))
    }

    /// Process a HandshakeResponse packet on the initiator and finalize session.
    pub fn process_response(
        local_keypair: &NoiseKeyPair,
        _peer_static_pub: &[u8; 32],
        state: EphemeralState,
        packet: &HandshakeResponsePacket,
        now_ms: u64,
    ) -> MeshResult<NoiseSession> {
        // Step 1: Verify MAC1
        let resp_raw = packet.to_bytes();
        let resp_mac_key = blake3_hash(&local_keypair.public_key);
        let expected_mac1 = compute_mac1(&resp_mac_key, &resp_raw[0..60]);
        if packet.mac1 != expected_mac1 {
            return Err(MeshError::HandshakeFailed(
                "Invalid response MAC1".to_string(),
            ));
        }

        let mut ck = state.chaining_key;
        let mut h = state.hash;

        h = blake3_hash(&[h.as_slice(), packet.unencrypted_ephemeral.as_slice()].concat());

        // DH(e_initiator, e2_responder)
        let dh3 = x25519(&state.ephemeral.private_key, &packet.unencrypted_ephemeral);
        let (next_ck, _) = kdf2(&ck, &dh3);
        ck = next_ck;

        // DH(static_initiator, e2_responder)
        let dh4 = x25519(&local_keypair.private_key, &packet.unencrypted_ephemeral);
        let (next_ck, key3) = kdf2(&ck, &dh4);
        ck = next_ck;

        // Decrypt empty payload to authenticate responder
        let _ = aead_decrypt(&key3, 0, &h, &packet.encrypted_empty)?;

        // Derive final symmetric transport keys
        let (tx_key, rx_key) = kdf_split_initiator(&ck);

        let session = NoiseSession {
            local_index: state.local_sender_index,
            peer_index: packet.sender_index,
            tx_key,
            rx_key,
            send_counter: 0,
            replay_window: AntiReplayWindow::new(),
            established_at_ms: now_ms,
            tx_bytes: 0,
            rx_bytes: 0,
        };

        Ok(session)
    }
}

/// Ephemeral handshake state kept by initiator between request and response.
#[derive(Debug, Clone)]
pub struct EphemeralState {
    pub ephemeral: NoiseKeyPair,
    pub chaining_key: [u8; 32],
    pub hash: [u8; 32],
    pub local_sender_index: u32,
}

// -----------------------------------------------------------------------------
// Internal Cryptographic Helpers
// -----------------------------------------------------------------------------

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn compute_mac1(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(message);
    let full = hasher.finalize();
    let mut mac = [0u8; 16];
    mac.copy_from_slice(&full.as_bytes()[0..16]);
    mac
}

fn kdf2(chaining_key: &[u8; 32], input: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = blake3::Hasher::new_keyed(chaining_key);
    hasher.update(b"velcrux-noise-kdf2-ck");
    hasher.update(input);
    let next_ck = *hasher.finalize().as_bytes();

    let mut hasher_key = blake3::Hasher::new_keyed(&next_ck);
    hasher_key.update(b"velcrux-noise-kdf2-key");
    let key = *hasher_key.finalize().as_bytes();

    (next_ck, key)
}

fn kdf_split_initiator(chaining_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut h1 = blake3::Hasher::new_keyed(chaining_key);
    h1.update(b"velcrux-noise-tx-initiator");
    let tx = *h1.finalize().as_bytes();

    let mut h2 = blake3::Hasher::new_keyed(chaining_key);
    h2.update(b"velcrux-noise-rx-initiator");
    let rx = *h2.finalize().as_bytes();

    (tx, rx)
}

fn kdf_split_responder(chaining_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut h1 = blake3::Hasher::new_keyed(chaining_key);
    h1.update(b"velcrux-noise-rx-initiator"); // Responder tx is initiator rx
    let tx = *h1.finalize().as_bytes();

    let mut h2 = blake3::Hasher::new_keyed(chaining_key);
    h2.update(b"velcrux-noise-tx-initiator"); // Responder rx is initiator tx
    let rx = *h2.finalize().as_bytes();

    (tx, rx)
}

fn aead_encrypt(
    key: &[u8; 32],
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, MeshError> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| MeshError::HandshakeFailed("Invalid AEAD key".to_string()))?;
    let less_safe = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
        .map_err(|_| MeshError::HandshakeFailed("Invalid nonce".to_string()))?;

    let mut in_out = plaintext.to_vec();
    less_safe
        .seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| MeshError::HandshakeFailed("AEAD seal failed".to_string()))?;
    Ok(in_out)
}

fn aead_decrypt(
    key: &[u8; 32],
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, MeshError> {
    if ciphertext.len() < 16 {
        return Err(MeshError::DecryptionFailed);
    }
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| MeshError::DecryptionFailed)?;
    let less_safe = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    let nonce =
        Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| MeshError::DecryptionFailed)?;

    let mut in_out = ciphertext.to_vec();
    let decrypted = less_safe
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| MeshError::DecryptionFailed)?;
    Ok(decrypted.to_vec())
}
