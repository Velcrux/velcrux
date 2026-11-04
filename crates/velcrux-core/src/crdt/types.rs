//! Core Conflict-Free Replicated Data Types (LWW-Register, OR-Set, MV-Register).
//!
//! Provides mathematically provable join-semilattice merge operations ensuring
//! strong eventual consistency (SEC) without cross-region locks.
//!
//! Complies strictly with `#![forbid(unsafe_code)]`.

use crate::crdt::clock::{Hlc, VectorClock};
use std::collections::{BTreeMap, BTreeSet};

/// Last-Write-Wins Register (LWW-Register).
///
/// Conflicts are deterministically resolved by comparing Hybrid Logical Clock timestamps.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LwwRegister<T> {
    pub value: T,
    pub timestamp: Hlc,
}

impl<T: Clone + PartialEq> LwwRegister<T> {
    /// Create a new register with an initial value and timestamp.
    pub fn new(value: T, timestamp: Hlc) -> Self {
        Self { value, timestamp }
    }

    /// Update register value if the new timestamp is strictly greater.
    pub fn set(&mut self, value: T, timestamp: Hlc) -> bool {
        if timestamp > self.timestamp {
            self.value = value;
            self.timestamp = timestamp;
            true
        } else {
            false
        }
    }

    /// Merge another register into this one, adopting the latest write.
    pub fn merge(&mut self, other: &LwwRegister<T>) {
        if other.timestamp > self.timestamp {
            self.value = other.value.clone();
            self.timestamp = other.timestamp.clone();
        }
    }

    pub fn get(&self) -> &T {
        &self.value
    }
}

/// Observed-Removed Set (OR-Set / Add-Wins Set).
///
/// Supports concurrent element additions and deletions. If an element is added concurrently
/// with a deletion, the addition wins because the newly generated tag was not yet observed
/// by the deleting node.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrSet<T: Ord + Clone> {
    /// Mapping from element to set of observed operation tag tokens.
    pub elements: BTreeMap<T, BTreeSet<String>>,
    /// Tombstone set of deleted tag tokens.
    pub tombstones: BTreeSet<String>,
}

impl<T: Ord + Clone> Default for OrSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ord + Clone> OrSet<T> {
    /// Create a new, empty OR-Set.
    pub fn new() -> Self {
        Self {
            elements: BTreeMap::new(),
            tombstones: BTreeSet::new(),
        }
    }

    /// Add an element with a globally unique tag token (e.g. ULID / UUID / HLC string).
    pub fn add(&mut self, element: T, tag: impl Into<String>) {
        let tag_str = tag.into();
        self.elements.entry(element).or_default().insert(tag_str);
    }

    /// Remove an element by tombstoning all currently observed tags for it.
    pub fn remove(&mut self, element: &T) -> bool {
        if let Some(tags) = self.elements.get(element) {
            for tag in tags {
                self.tombstones.insert(tag.clone());
            }
            self.elements.remove(element);
            true
        } else {
            false
        }
    }

    /// Returns true if the element exists in the set and has at least one active tag.
    pub fn contains(&self, element: &T) -> bool {
        if let Some(tags) = self.elements.get(element) {
            tags.iter().any(|tag| !self.tombstones.contains(tag))
        } else {
            false
        }
    }

    /// Return all active elements currently in the set.
    pub fn read(&self) -> Vec<T> {
        let mut out = Vec::new();
        for (item, tags) in &self.elements {
            if tags.iter().any(|t| !self.tombstones.contains(t)) {
                out.push(item.clone());
            }
        }
        out
    }

    /// Merge another OR-Set into this one using join-semilattice union.
    pub fn merge(&mut self, other: &OrSet<T>) {
        // Union tombstones
        for ts in &other.tombstones {
            self.tombstones.insert(ts.clone());
        }

        // Union elements and their tags
        for (elem, tags) in &other.elements {
            let entry = self.elements.entry(elem.clone()).or_default();
            for tag in tags {
                entry.insert(tag.clone());
            }
        }

        // Clean up elements that have no surviving non-tombstoned tags
        self.elements.retain(|_, tags| {
            tags.retain(|tag| !self.tombstones.contains(tag));
            !tags.is_empty()
        });
    }

    /// Return total active elements count.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Multi-Value Register (MV-Register).
///
/// Preserves concurrent values until explicitly reconciled by the application.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MvRegister<T: Clone + PartialEq> {
    pub values: Vec<(T, VectorClock)>,
}

impl<T: Clone + PartialEq> MvRegister<T> {
    pub fn new(initial: T, clock: VectorClock) -> Self {
        Self {
            values: vec![(initial, clock)],
        }
    }

    /// Set a new value with an updated vector clock, replacing dominated values.
    pub fn set(&mut self, value: T, clock: VectorClock) {
        // Retain only values that are concurrent with (not dominated by) the new clock
        self.values.retain(|(_, c)| !clock.dominates(c));
        self.values.push((value, clock));
    }

    /// Merge another MV-Register into this one.
    pub fn merge(&mut self, other: &MvRegister<T>) {
        let mut combined = self.values.clone();
        for (ov, oc) in &other.values {
            if !combined.iter().any(|(v, c)| v == ov && c == oc) {
                combined.push((ov.clone(), oc.clone()));
            }
        }

        // Prune any values that are strictly dominated by another value's clock
        let mut surviving = Vec::new();
        for i in 0..combined.len() {
            let (_, c1) = &combined[i];
            let mut is_dominated = false;
            for j in 0..combined.len() {
                if i != j {
                    let (_, c2) = &combined[j];
                    if c2.dominates(c1) && c1 != c2 {
                        is_dominated = true;
                        break;
                    }
                }
            }
            if !is_dominated {
                surviving.push(combined[i].clone());
            }
        }

        self.values = surviving;
    }

    /// Read all surviving concurrent values.
    pub fn read(&self) -> Vec<T> {
        self.values.iter().map(|(v, _)| v.clone()).collect()
    }
}
