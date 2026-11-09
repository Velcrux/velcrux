#![forbid(unsafe_code)]

//! Integration Tests for Option DG: Hardware PTP (IEEE 1588v2) Nanosecond High-Precision Clock Synchronization & Bounded Transfer Ordering Mesh (`ADR-075`).

use std::cmp::Ordering;
use velcrux_core::ptp::{
    BmcaEngine, BoundedOrderMesh, ClockDataset, ClockIdentity, ClockQuality, ClockServo,
    CorrectionField, PortIdentity, PtpAnnounce, PtpExchangeSample, PtpHeader, PtpMessage,
    PtpMessageType, PtpPortState, PtpTimestamp, PtpTimestampPayload,
};

#[test]
fn test_ieee1588v2_header_and_payload_framing() {
    let clock_id = ClockIdentity::from_mac([0x00, 0x50, 0x56, 0xAA, 0xBB, 0xCC]);
    let port = PortIdentity::new(clock_id, 1);

    // 1. Sync Message framing
    let sync_hdr = PtpHeader::new(PtpMessageType::Sync, 44, port, 1001);
    let sync_payload = PtpTimestampPayload {
        timestamp: PtpTimestamp::new(1731150000, 500_000_000),
    };
    let sync_msg = PtpMessage::Sync(sync_hdr.clone(), sync_payload);
    let wire_bytes = sync_msg.encode();
    assert_eq!(wire_bytes.len(), 44);

    let decoded = PtpMessage::decode(&wire_bytes).expect("decode sync");
    assert_eq!(decoded.header().message_type, PtpMessageType::Sync);
    assert_eq!(decoded.header().sequence_id, 1001);
    assert_eq!(decoded.header().source_port_identity, port);

    // 2. Announce Message framing
    let announce_hdr = PtpHeader::new(PtpMessageType::Announce, 64, port, 1002);
    let announce_payload = PtpAnnounce {
        origin_timestamp: PtpTimestamp::new(1731150000, 0),
        current_utc_offset: 37,
        grandmaster_priority1: 128,
        grandmaster_clock_quality: ClockQuality::gnss_primary(),
        grandmaster_priority2: 128,
        grandmaster_identity: clock_id,
        steps_removed: 0,
        time_source: 0x20, // GPS
    };
    let announce_msg = PtpMessage::Announce(announce_hdr, announce_payload);
    let ann_bytes = announce_msg.encode();
    assert_eq!(ann_bytes.len(), 64);

    let dec_ann = PtpMessage::decode(&ann_bytes).expect("decode announce");
    if let PtpMessage::Announce(_, a) = dec_ann {
        assert_eq!(a.grandmaster_clock_quality.clock_class, 6);
        assert_eq!(a.grandmaster_identity, clock_id);
    } else {
        panic!("expected announce message");
    }
}

#[test]
fn test_bmca_grandmaster_election_and_failover() {
    let local_id = ClockIdentity::new([0xDD; 8]);
    let local_port = PortIdentity::new(local_id, 1);
    let mut bmca = BmcaEngine::new(local_port, ClockDataset::default_slave(local_id));

    // Initially with no foreign masters, local clock becomes Master
    assert_eq!(bmca.evaluate_state(), PtpPortState::Master);
    assert_eq!(bmca.selected_grandmaster, Some(local_id));

    // Announce Candidate A: GNSS Master (Class 6, Priority 128)
    let id_a = ClockIdentity::new([0xAA; 8]);
    let port_a = PortIdentity::new(id_a, 1);
    let announce_a = PtpAnnounce {
        origin_timestamp: PtpTimestamp::new(100, 0),
        current_utc_offset: 37,
        grandmaster_priority1: 128,
        grandmaster_clock_quality: ClockQuality::gnss_primary(),
        grandmaster_priority2: 128,
        grandmaster_identity: id_a,
        steps_removed: 0,
        time_source: 0x20,
    };

    // Announce Candidate B: Telecom Boundary Clock (Class 135, Priority 128)
    let id_b = ClockIdentity::new([0xBB; 8]);
    let port_b = PortIdentity::new(id_b, 1);
    let announce_b = PtpAnnounce {
        origin_timestamp: PtpTimestamp::new(100, 0),
        current_utc_offset: 37,
        grandmaster_priority1: 128,
        grandmaster_clock_quality: ClockQuality::telecom_boundary(),
        grandmaster_priority2: 128,
        grandmaster_identity: id_b,
        steps_removed: 1,
        time_source: 0xA0, // Internal oscillator
    };

    bmca.process_announce(port_a, &announce_a, 100);
    bmca.process_announce(port_b, &announce_b, 100);

    // BMCA should elect Candidate A as Grandmaster (Class 6 < Class 135)
    assert_eq!(bmca.evaluate_state(), PtpPortState::Slave);
    assert_eq!(bmca.selected_grandmaster, Some(id_a));

    // Simulate Candidate A failure / withdrawal
    bmca.foreign_masters.remove(&port_a);

    // BMCA should fail over to Candidate B
    assert_eq!(bmca.evaluate_state(), PtpPortState::Slave);
    assert_eq!(bmca.selected_grandmaster, Some(id_b));
}

#[test]
fn test_clock_servo_delay_offset_calculation() {
    let mut servo = ClockServo::default();

    // Propagation delay: 1,200 ns
    // Slave offset: -350 ns (slave is 350 ns behind master)
    // t1 = 200s, 0ns
    // t2 = 200s, 1200 - 350 = 850ns
    // t3 = 200s, 100_000ns
    // t4 = 200s, 100_000 + 1200 + 350 = 101_550ns
    let t1 = PtpTimestamp::new(200, 0);
    let t2 = PtpTimestamp::new(200, 850);
    let t3 = PtpTimestamp::new(200, 100_000);
    let t4 = PtpTimestamp::new(200, 101_550);

    let sample = PtpExchangeSample::new(t1, t2, t3, t4, 0);
    assert_eq!(sample.compute_path_delay_nanos(), 1200);
    assert_eq!(sample.compute_offset_from_master_nanos(), -350);

    servo.process_sample(&sample);
    assert_eq!(servo.mean_path_delay_nanos, 1200);
    assert_eq!(servo.current_offset_nanos, -350);

    // Synthesized time should add 350 ns to correct for slave lag
    let raw_slave_time = 1_000_000_000u64;
    let sync_time = servo.get_synchronized_time(raw_slave_time);
    assert_eq!(sync_time.to_nanos_total(), 1_000_000_350u64);
}

#[test]
fn test_sub_nanosecond_correction_field_accumulation() {
    let cf1 = CorrectionField::from_nanos(15.25);
    let cf2 = CorrectionField::from_nanos(8.50);
    let combined = CorrectionField(cf1.0 + cf2.0);

    assert!((combined.to_nanos() - 23.75).abs() < 1e-4);
}

#[test]
fn test_bounded_skew_causal_commit_ordering() {
    let mesh_us = BoundedOrderMesh::new("us-east", 50);
    let mesh_eu = BoundedOrderMesh::new("eu-west", 50);

    let servo_us = ClockServo::default();
    let servo_eu = ClockServo::default();

    // Commit A in us-east at 10.000000000s
    let commit_a = mesh_us.allocate_commit("tx-001", &servo_us, 10_000_000_000);

    // Commit B in eu-west starting after Commit A's wait window (10.000000500s)
    let commit_b = mesh_eu.allocate_commit("tx-002", &servo_eu, 10_000_000_500);

    // Commit A must strictly causally precede Commit B
    assert_eq!(
        commit_a.timestamp.causal_order(&commit_b.timestamp),
        Some(Ordering::Less)
    );
    assert_eq!(
        commit_b.timestamp.causal_order(&commit_a.timestamp),
        Some(Ordering::Greater)
    );
}
