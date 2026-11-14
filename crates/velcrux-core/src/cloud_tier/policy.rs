//! Multi-Cloud Lifecycle Policy & Compaction Automation Engine.
//!
//! Evaluates age-based, heat-map, and fragmentation criteria to orchestrate
//! automatic migration between storage tiers (`Hot` -> `Cool` -> `Cold` -> `DeepArchive`),
//! object expiration, and garbage collection compaction.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use super::types::{CloudTierClass, DEFAULT_COMPACTION_FRAGMENTATION_THRESHOLD};

/// Action determined by the lifecycle policy engine for a cloud object or container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TieringAction {
    /// Keep object in its current tier.
    Retain,
    /// Migrate container to a cooler or deeper storage tier.
    Transition(CloudTierClass),
    /// Permanently expire and delete container.
    Expire,
    /// Trigger compaction and repacking to reclaim tombstoned dead space.
    CompactAndRepack,
}

/// Declarative lifecycle tiering rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudLifecycleRule {
    /// Unique identifier for this rule.
    pub rule_id: String,
    /// Optional object key prefix filter (e.g. `logs/`, `backups/`).
    pub prefix: Option<String>,
    /// Optional tenant ID filter.
    pub tenant_id: Option<String>,
    /// Days after ingestion to transition to Cool tier (e.g. 30).
    pub transition_to_cool_days: Option<u32>,
    /// Days after ingestion to transition to Cold tier (e.g. 90).
    pub transition_to_cold_days: Option<u32>,
    /// Days after ingestion to transition to DeepArchive tier (e.g. 365).
    pub transition_to_deep_archive_days: Option<u32>,
    /// Days after ingestion to expire and delete the container (e.g. 730).
    pub expiration_days: Option<u32>,
    /// Fragmentation ratio threshold above which compaction is triggered (default: 0.30).
    pub compaction_threshold_ratio: f64,
}

impl Default for CloudLifecycleRule {
    fn default() -> Self {
        Self {
            rule_id: "default-rule".into(),
            prefix: None,
            tenant_id: None,
            transition_to_cool_days: Some(30),
            transition_to_cold_days: Some(90),
            transition_to_deep_archive_days: Some(365),
            expiration_days: Some(730),
            compaction_threshold_ratio: DEFAULT_COMPACTION_FRAGMENTATION_THRESHOLD,
        }
    }
}

impl CloudLifecycleRule {
    pub fn new(rule_id: impl Into<String>) -> Self {
        Self {
            rule_id: rule_id.into(),
            ..Default::default()
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Evaluates if this rule applies to an object key and tenant.
    pub fn matches(&self, key: &str, tenant: Option<&str>) -> bool {
        if let Some(ref p) = self.prefix {
            if !key.starts_with(p) {
                return false;
            }
        }
        if let Some(ref t) = self.tenant_id {
            if tenant != Some(t.as_str()) {
                return false;
            }
        }
        true
    }

    /// Evaluates container age (in seconds) and fragmentation against rule thresholds.
    pub fn evaluate(
        &self,
        current_tier: CloudTierClass,
        age_seconds: u64,
        fragmentation_ratio: f64,
    ) -> TieringAction {
        let age_days = (age_seconds / 86400) as u32;

        // 1. Check expiration
        if let Some(exp_days) = self.expiration_days {
            if age_days >= exp_days {
                return TieringAction::Expire;
            }
        }

        // 2. Check compaction fragmentation threshold
        if fragmentation_ratio >= self.compaction_threshold_ratio {
            return TieringAction::CompactAndRepack;
        }

        // 3. Check tier progression (DeepArchive -> Cold -> Cool)
        if let Some(deep_days) = self.transition_to_deep_archive_days {
            if age_days >= deep_days && current_tier < CloudTierClass::DeepArchive {
                return TieringAction::Transition(CloudTierClass::DeepArchive);
            }
        }

        if let Some(cold_days) = self.transition_to_cold_days {
            if age_days >= cold_days && current_tier < CloudTierClass::Cold {
                return TieringAction::Transition(CloudTierClass::Cold);
            }
        }

        if let Some(cool_days) = self.transition_to_cool_days {
            if age_days >= cool_days && current_tier < CloudTierClass::Cool {
                return TieringAction::Transition(CloudTierClass::Cool);
            }
        }

        TieringAction::Retain
    }
}

/// Lifecycle Policy Engine managing multiple prioritized rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloudLifecyclePolicyEngine {
    pub rules: Vec<CloudLifecycleRule>,
}

impl CloudLifecyclePolicyEngine {
    pub fn new() -> Self {
        Self {
            rules: vec![CloudLifecycleRule::default()],
        }
    }

    pub fn add_rule(&mut self, rule: CloudLifecycleRule) {
        self.rules.insert(0, rule); // Higher priority first
    }

    pub fn evaluate_container(
        &self,
        key: &str,
        tenant: Option<&str>,
        current_tier: CloudTierClass,
        age_seconds: u64,
        fragmentation_ratio: f64,
    ) -> TieringAction {
        for rule in &self.rules {
            if rule.matches(key, tenant) {
                return rule.evaluate(current_tier, age_seconds, fragmentation_ratio);
            }
        }
        TieringAction::Retain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_rule_transitions() {
        let rule = CloudLifecycleRule::new("backup-rule")
            .with_prefix("backups/")
            .with_tenant("tenant-corp");

        assert!(rule.matches("backups/db.vlxt", Some("tenant-corp")));
        assert!(!rule.matches("logs/app.log", Some("tenant-corp")));
        assert!(!rule.matches("backups/db.vlxt", Some("tenant-other")));

        // 10 days old, 0% fragmentation -> Retain
        let a1 = rule.evaluate(CloudTierClass::Hot, 10 * 86400, 0.0);
        assert_eq!(a1, TieringAction::Retain);

        // 45 days old -> Transition to Cool
        let a2 = rule.evaluate(CloudTierClass::Hot, 45 * 86400, 0.0);
        assert_eq!(a2, TieringAction::Transition(CloudTierClass::Cool));

        // 120 days old -> Transition to Cold
        let a3 = rule.evaluate(CloudTierClass::Cool, 120 * 86400, 0.0);
        assert_eq!(a3, TieringAction::Transition(CloudTierClass::Cold));

        // 400 days old -> Transition to DeepArchive
        let a4 = rule.evaluate(CloudTierClass::Cold, 400 * 86400, 0.0);
        assert_eq!(a4, TieringAction::Transition(CloudTierClass::DeepArchive));

        // 800 days old -> Expire
        let a5 = rule.evaluate(CloudTierClass::DeepArchive, 800 * 86400, 0.0);
        assert_eq!(a5, TieringAction::Expire);

        // 20 days old but 35% fragmentation -> CompactAndRepack
        let a6 = rule.evaluate(CloudTierClass::Hot, 20 * 86400, 0.35);
        assert_eq!(a6, TieringAction::CompactAndRepack);
    }
}
