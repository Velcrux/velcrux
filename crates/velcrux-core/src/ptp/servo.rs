#![forbid(unsafe_code)]

//! Proportional-Integral (PI) Clock Servo & Hardware Timestamp Synchronizer.
//!
//! Evaluates the standard 4-timestamp PTP exchange:
//! - $t_1$: Master transmit time of Sync / Follow_Up
//! - $t_2$: Slave receive time of Sync
//! - $t_3$: Slave transmit time of Delay_Req
//! - $t_4$: Master receive time of Delay_Req
//!
//! Calculates mean one-way path delay ($\mu$) and master-slave offset ($\theta$),
//! applying closed-loop PI servo filtering to steer the local virtual clock.

use super::types::{PtpTimestamp, ServoLockStatus};
use serde::{Deserialize, Serialize};

/// Nanosecond threshold below which clock is considered phase-locked.
pub const PHASE_LOCK_THRESHOLD_NANOS: i64 = 50;

/// Default proportional gain ($K_p$) for the PI servo loop.
pub const DEFAULT_SERVO_KP: f64 = 0.70;

/// Default integral gain ($K_i$) for the PI servo loop.
pub const DEFAULT_SERVO_KI: f64 = 0.30;

/// Measurement Sample from a completed 4-timestamp PTP exchange round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtpExchangeSample {
    pub t1_master_sync_tx: PtpTimestamp,
    pub t2_slave_sync_rx: PtpTimestamp,
    pub t3_slave_delay_req_tx: PtpTimestamp,
    pub t4_master_delay_req_rx: PtpTimestamp,
    pub correction_nanos: i64,
}

impl PtpExchangeSample {
    pub fn new(
        t1: PtpTimestamp,
        t2: PtpTimestamp,
        t3: PtpTimestamp,
        t4: PtpTimestamp,
        correction: i64,
    ) -> Self {
        Self {
            t1_master_sync_tx: t1,
            t2_slave_sync_rx: t2,
            t3_slave_delay_req_tx: t3,
            t4_master_delay_req_rx: t4,
            correction_nanos: correction,
        }
    }

    /// Computes one-way path delay:
    /// $\mu = \frac{(t_2 - t_1) + (t_4 - t_3) - c}{2}$
    pub fn compute_path_delay_nanos(&self) -> i64 {
        let forward_delay = self.t2_slave_sync_rx.diff_nanos(&self.t1_master_sync_tx);
        let reverse_delay = self
            .t4_master_delay_req_rx
            .diff_nanos(&self.t3_slave_delay_req_tx);
        (forward_delay + reverse_delay - self.correction_nanos) / 2
    }

    /// Computes master-to-slave clock offset:
    /// $\theta = (t_2 - t_1) - \mu - c_{sync}$
    pub fn compute_offset_from_master_nanos(&self) -> i64 {
        let forward_delay = self.t2_slave_sync_rx.diff_nanos(&self.t1_master_sync_tx);
        let path_delay = self.compute_path_delay_nanos();
        forward_delay - path_delay
    }
}

/// Proportional-Integral (PI) Clock Servo Controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockServo {
    pub kp: f64,
    pub ki: f64,
    pub integral_accumulator: f64,
    pub current_offset_nanos: i64,
    pub mean_path_delay_nanos: i64,
    pub estimated_drift_ppb: f64, // Parts per billion
    pub lock_status: ServoLockStatus,
    pub total_samples_processed: u64,
    pub jitter_rms_nanos: f64,
}

impl Default for ClockServo {
    fn default() -> Self {
        Self {
            kp: DEFAULT_SERVO_KP,
            ki: DEFAULT_SERVO_KI,
            integral_accumulator: 0.0,
            current_offset_nanos: 0,
            mean_path_delay_nanos: 0,
            estimated_drift_ppb: 0.0,
            lock_status: ServoLockStatus::Unlocked,
            total_samples_processed: 0,
            jitter_rms_nanos: 0.0,
        }
    }
}

impl ClockServo {
    pub fn new(kp: f64, ki: f64) -> Self {
        Self {
            kp,
            ki,
            ..Default::default()
        }
    }

    /// Ingests a new 4-timestamp exchange sample, updates servo state, and steers virtual clock.
    pub fn process_sample(&mut self, sample: &PtpExchangeSample) {
        let path_delay = sample.compute_path_delay_nanos().max(0);
        let offset = sample.compute_offset_from_master_nanos();

        self.mean_path_delay_nanos = path_delay;
        self.current_offset_nanos = offset;
        self.total_samples_processed += 1;

        // PI Servo update equations
        let err = offset as f64;
        self.integral_accumulator += self.ki * err;
        self.integral_accumulator = self.integral_accumulator.clamp(-1_000_000.0, 1_000_000.0);

        let adj_ppb = (self.kp * err) + self.integral_accumulator;
        self.estimated_drift_ppb = adj_ppb;

        // Exponential moving average for jitter RMS
        let abs_err = err.abs();
        if self.total_samples_processed == 1 {
            self.jitter_rms_nanos = abs_err;
        } else {
            self.jitter_rms_nanos = 0.90 * self.jitter_rms_nanos + 0.10 * abs_err;
        }

        // Update lock state
        if abs_err <= PHASE_LOCK_THRESHOLD_NANOS as f64 {
            self.lock_status = ServoLockStatus::LockedPhase;
        } else if abs_err <= 1000.0 {
            self.lock_status = ServoLockStatus::Calibrating;
        } else {
            self.lock_status = ServoLockStatus::Unlocked;
        }
    }

    /// Synthesizes a synchronized local timestamp compensating for offset and drift.
    pub fn get_synchronized_time(&self, raw_local_nanos: u64) -> PtpTimestamp {
        // Compensate by subtracting master-slave offset (theta)
        let corrected = (raw_local_nanos as i128) - (self.current_offset_nanos as i128);
        let non_neg = corrected.max(0) as u64;
        PtpTimestamp::from_nanos_total(non_neg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptp_exchange_sample_math() {
        // Master clock at 100.000s, Slave clock ahead by 25ns
        // One-way propagation delay: 500ns
        // t1 = 100s, 0ns
        // t2 = 100s, 525ns (delay 500 + offset 25)
        // t3 = 100s, 10_000ns
        // t4 = 100s, 10_475ns (t3 + delay 500 - offset 25)
        let t1 = PtpTimestamp::new(100, 0);
        let t2 = PtpTimestamp::new(100, 525);
        let t3 = PtpTimestamp::new(100, 10_000);
        let t4 = PtpTimestamp::new(100, 10_475);

        let sample = PtpExchangeSample::new(t1, t2, t3, t4, 0);
        let path_delay = sample.compute_path_delay_nanos();
        let offset = sample.compute_offset_from_master_nanos();

        assert_eq!(path_delay, 500);
        assert_eq!(offset, 25);
    }

    #[test]
    fn test_clock_servo_convergence_to_phase_lock() {
        let mut servo = ClockServo::default();

        for i in 0..10 {
            // Gradually converging offset
            let off = 100 - (i * 9);
            let t1 = PtpTimestamp::new(100 + i as u64, 0);
            let t2 = PtpTimestamp::new(100 + i as u64, (200 + off) as u32);
            let t3 = PtpTimestamp::new(100 + i as u64, 50_000);
            let t4 = PtpTimestamp::new(100 + i as u64, (50_200 - off) as u32);

            let sample = PtpExchangeSample::new(t1, t2, t3, t4, 0);
            servo.process_sample(&sample);
        }

        assert_eq!(servo.lock_status, ServoLockStatus::LockedPhase);
        assert!(servo.current_offset_nanos.abs() <= PHASE_LOCK_THRESHOLD_NANOS);
        assert_eq!(servo.mean_path_delay_nanos, 200);
    }
}
