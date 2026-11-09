#![forbid(unsafe_code)]

//! Best Master Clock Algorithm (BMCA) — IEEE 1588-2008 §9.3.
//!
//! Evaluates incoming Announce messages from candidate Grandmasters, compares
//! hierarchical clock quality attributes (priority1, clockClass, clockAccuracy,
//! variance, priority2, identity, stepsRemoved), and determines optimal PTP port states.

use super::message::PtpAnnounce;
use super::types::{ClockIdentity, ClockQuality, PortIdentity, PtpPortState};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;

/// Clock Dataset describing local or foreign master clock characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockDataset {
    pub priority1: u8,
    pub clock_quality: ClockQuality,
    pub priority2: u8,
    pub clock_identity: ClockIdentity,
    pub steps_removed: u16,
}

impl ClockDataset {
    pub fn new(
        priority1: u8,
        clock_quality: ClockQuality,
        priority2: u8,
        clock_identity: ClockIdentity,
        steps_removed: u16,
    ) -> Self {
        Self {
            priority1,
            clock_quality,
            priority2,
            clock_identity,
            steps_removed,
        }
    }

    /// Primary GNSS reference grandmaster clock dataset.
    pub fn gnss_grandmaster(identity: ClockIdentity) -> Self {
        Self {
            priority1: 128,
            clock_quality: ClockQuality::gnss_primary(),
            priority2: 128,
            clock_identity: identity,
            steps_removed: 0,
        }
    }

    /// Default slave or internal oscillator clock dataset.
    pub fn default_slave(identity: ClockIdentity) -> Self {
        Self {
            priority1: 248,
            clock_quality: ClockQuality::default(),
            priority2: 248,
            clock_identity: identity,
            steps_removed: 0,
        }
    }
}

/// Compares two clock datasets according to IEEE 1588v2 dataset comparison algorithm (§9.3.4).
/// Returns `Ordering::Less` if `a` is superior to `b` (better clock), `Ordering::Greater` if `b` is superior.
pub fn compare_datasets(a: &ClockDataset, b: &ClockDataset) -> Ordering {
    // 1. Priority 1 (lower is superior)
    match a.priority1.cmp(&b.priority1) {
        Ordering::Equal => {}
        other => return other,
    }

    // 2. Clock Class (lower is superior)
    match a
        .clock_quality
        .clock_class
        .cmp(&b.clock_quality.clock_class)
    {
        Ordering::Equal => {}
        other => return other,
    }

    // 3. Clock Accuracy (lower is superior)
    match a
        .clock_quality
        .clock_accuracy
        .cmp(&b.clock_quality.clock_accuracy)
    {
        Ordering::Equal => {}
        other => return other,
    }

    // 4. Offset Scaled Log Variance (lower is superior)
    match a
        .clock_quality
        .offset_scaled_log_variance
        .cmp(&b.clock_quality.offset_scaled_log_variance)
    {
        Ordering::Equal => {}
        other => return other,
    }

    // 5. Priority 2 (lower is superior)
    match a.priority2.cmp(&b.priority2) {
        Ordering::Equal => {}
        other => return other,
    }

    // 6. Clock Identity tie-breaker (lower numerical value is superior)
    match a.clock_identity.cmp(&b.clock_identity) {
        Ordering::Equal => {}
        other => return other,
    }

    // 7. Steps Removed (closer to grandmaster is superior)
    a.steps_removed.cmp(&b.steps_removed)
}

/// Recorded foreign master candidate from received Announce message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForeignMasterRecord {
    pub source_port: PortIdentity,
    pub dataset: ClockDataset,
    pub last_seen_epoch_secs: u64,
    pub announce_count: u32,
}

/// BMCA State Machine Engine managing port state selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmcaEngine {
    pub local_port: PortIdentity,
    pub local_dataset: ClockDataset,
    pub current_port_state: PtpPortState,
    pub selected_grandmaster: Option<ClockIdentity>,
    pub foreign_masters: HashMap<PortIdentity, ForeignMasterRecord>,
}

impl BmcaEngine {
    pub fn new(local_port: PortIdentity, local_dataset: ClockDataset) -> Self {
        Self {
            local_port,
            local_dataset,
            current_port_state: PtpPortState::Listening,
            selected_grandmaster: None,
            foreign_masters: HashMap::new(),
        }
    }

    /// Processes an incoming Announce message from a remote candidate master.
    pub fn process_announce(
        &mut self,
        source_port: PortIdentity,
        announce: &PtpAnnounce,
        current_time_secs: u64,
    ) {
        let dataset = ClockDataset::new(
            announce.grandmaster_priority1,
            announce.grandmaster_clock_quality,
            announce.grandmaster_priority2,
            announce.grandmaster_identity,
            announce.steps_removed,
        );

        let record =
            self.foreign_masters
                .entry(source_port)
                .or_insert_with(|| ForeignMasterRecord {
                    source_port,
                    dataset,
                    last_seen_epoch_secs: current_time_secs,
                    announce_count: 0,
                });

        record.dataset = dataset;
        record.last_seen_epoch_secs = current_time_secs;
        record.announce_count += 1;
    }

    /// Evaluates BMCA dataset comparison and updates the PTP port state.
    pub fn evaluate_state(&mut self) -> PtpPortState {
        // Find best foreign master candidate
        let mut best_foreign: Option<(&PortIdentity, &ForeignMasterRecord)> = None;

        for (port, record) in &self.foreign_masters {
            match best_foreign {
                None => best_foreign = Some((port, record)),
                Some((_, current_best)) => {
                    if compare_datasets(&record.dataset, &current_best.dataset) == Ordering::Less {
                        best_foreign = Some((port, record));
                    }
                }
            }
        }

        match best_foreign {
            None => {
                // No foreign masters heard; local clock becomes Grandmaster
                self.current_port_state = PtpPortState::Master;
                self.selected_grandmaster = Some(self.local_dataset.clock_identity);
            }
            Some((_port, best_record)) => {
                let cmp = compare_datasets(&self.local_dataset, &best_record.dataset);
                if cmp == Ordering::Less {
                    // Local clock is superior to all foreign candidates -> Master
                    self.current_port_state = PtpPortState::Master;
                    self.selected_grandmaster = Some(self.local_dataset.clock_identity);
                } else if cmp == Ordering::Greater {
                    // Foreign candidate is superior to local clock -> Slave
                    self.current_port_state = PtpPortState::Slave;
                    self.selected_grandmaster = Some(best_record.dataset.clock_identity);
                } else {
                    // Tie on local vs foreign identity -> Passive
                    self.current_port_state = PtpPortState::Passive;
                    self.selected_grandmaster = Some(best_record.dataset.clock_identity);
                }
            }
        }

        self.current_port_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bmca_dataset_comparison() {
        let id_a = ClockIdentity::new([1, 1, 1, 1, 1, 1, 1, 1]);
        let id_b = ClockIdentity::new([2, 2, 2, 2, 2, 2, 2, 2]);

        let gnss_clock = ClockDataset::gnss_grandmaster(id_a);
        let default_slave = ClockDataset::default_slave(id_b);

        // GNSS clock must be superior (Less) to default slave
        assert_eq!(
            compare_datasets(&gnss_clock, &default_slave),
            Ordering::Less
        );
        assert_eq!(
            compare_datasets(&default_slave, &gnss_clock),
            Ordering::Greater
        );
    }

    #[test]
    fn test_bmca_engine_transition_to_slave_and_master() {
        let local_id = ClockIdentity::new([0xBB; 8]);
        let local_port = PortIdentity::new(local_id, 1);
        let local_ds = ClockDataset::default_slave(local_id);

        let mut engine = BmcaEngine::new(local_port, local_ds);

        // Without foreign announces, evaluate defaults to Master
        assert_eq!(engine.evaluate_state(), PtpPortState::Master);

        // Announce superior GNSS master
        let remote_id = ClockIdentity::new([0xAA; 8]);
        let remote_port = PortIdentity::new(remote_id, 1);
        let announce = PtpAnnounce {
            origin_timestamp: super::super::types::PtpTimestamp::new(1731150000, 0),
            current_utc_offset: 37,
            grandmaster_priority1: 128,
            grandmaster_clock_quality: ClockQuality::gnss_primary(),
            grandmaster_priority2: 128,
            grandmaster_identity: remote_id,
            steps_removed: 0,
            time_source: 0x20,
        };

        engine.process_announce(remote_port, &announce, 1731150001);
        assert_eq!(engine.evaluate_state(), PtpPortState::Slave);
        assert_eq!(engine.selected_grandmaster, Some(remote_id));
    }
}
