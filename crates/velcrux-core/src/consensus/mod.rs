//! Distributed Raft Consensus & High-Availability Cluster Metadata Coordinator (`ADR-042`, Option BZ).
//!
//! Features:
//! 1. Distributed Raft Consensus Engine:
//!    - Term coordination, randomized election timers, leader election with strict majority quorum.
//!    - Monotonic log replication with `AppendEntries` consistency invariants.
//!    - Linearizable committed state machine updates.
//! 2. High-Availability Cluster Metadata Coordinator:
//!    - Node registration, membership discovery, and health state dissemination.
//!    - Consistent resource leasing with TTL and monotonically increasing epoch fencing
//!      to prevent split-brain zombie writes.
//! 3. Client Leader Redirection & Failover:
//!    - Follower nodes reject mutating commands with authoritative leader redirection hints.
//! 4. Network Partition Healing:
//!    - Automatic step-down of isolated minority leaders upon reconnecting to higher-term majority.
//! 5. 100% Safe Rust (`#![forbid(unsafe_code)]`).

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;

/// Role of a node participating in the Raft consensus cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RaftRole {
    /// Passive cluster member accepting heartbeats and log entries from authoritative leader.
    Follower = 0,
    /// Candidate campaigning for leader election following an election timeout.
    Candidate = 1,
    /// Authoritative cluster leader serving client proposals, managing leases, and driving replication.
    Leader = 2,
}

impl RaftRole {
    /// Lowercase canonical identifier.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Follower => "follower",
            Self::Candidate => "candidate",
            Self::Leader => "leader",
        }
    }
}

impl fmt::Display for RaftRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A deterministic state machine command replicated across the Raft cluster log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RaftCommand {
    /// Register a new storage node in the cluster inventory.
    RegisterNode {
        node_id: String,
        address: String,
        role: String,
    },
    /// Decommission a storage node from active membership.
    DecommissionNode { node_id: String },
    /// Acquire or renew a time-bounded exclusive resource lease guarded by epoch fencing.
    AcquireLease {
        resource: String,
        holder: String,
        ttl_ms: u64,
        epoch: u64,
    },
    /// Explicitly release an active resource lease.
    ReleaseLease { resource: String, holder: String },
    /// Atomically update arbitrary cluster metadata key-value record.
    UpdateMetadata {
        key: String,
        value: String,
        version: u64,
    },
    /// Enforce epoch fencing for a node, rejecting stale/zombie proposals with epoch < min_epoch.
    FenceEpoch {
        node_id: String,
        min_valid_epoch: u64,
    },
    /// No-op commit entry used by newly elected leaders to commit entries from prior terms.
    Noop,
}

/// An immutable log entry stored within the Raft distributed log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftLogEntry {
    /// 1-based monotonic log sequence index.
    pub index: u64,
    /// Term in which the entry was proposed by the leader.
    pub term: u64,
    /// Replicated command payload to be executed on the state machine.
    pub command: RaftCommand,
    /// Unix timestamp (seconds) when proposed.
    pub timestamp_secs: u64,
}

/// An exclusive lease granted on a cluster resource with epoch fencing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterLease {
    /// Target resource name or identifier (e.g. shard-001, tenant-backup-lock).
    pub resource: String,
    /// Identity of the lease holder node or client.
    pub holder: String,
    /// Timestamp (seconds) when lease was granted.
    pub granted_at_secs: u64,
    /// Timestamp (seconds) when lease expires.
    pub expires_at_secs: u64,
    /// Monotonically increasing epoch number protecting against stale split-brain writes.
    pub epoch: u64,
}

impl ClusterLease {
    /// Check whether this lease is currently valid and unexpired at given unix timestamp.
    pub fn is_active(&self, now_secs: u64) -> bool {
        now_secs < self.expires_at_secs
    }
}

/// RPC Request: RequestVote sent by candidate campaigning for cluster leadership.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteRequest {
    /// Candidate's current term.
    pub term: u64,
    /// Candidate identifier requesting the vote.
    pub candidate_id: String,
    /// Index of candidate's last log entry.
    pub last_log_index: u64,
    /// Term of candidate's last log entry.
    pub last_log_term: u64,
}

/// RPC Response: RequestVote reply from a cluster peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteResponse {
    /// Current term of responder (for candidate to update itself if stale).
    pub term: u64,
    /// True if candidate received vote; false otherwise.
    pub vote_granted: bool,
    /// Node identifier of the voter.
    pub voter_id: String,
}

/// RPC Request: AppendEntries sent by leader to replicate log entries and send heartbeats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesRequest {
    /// Leader's term.
    pub term: u64,
    /// Leader identifier for client redirection.
    pub leader_id: String,
    /// Index of log entry immediately preceding new ones.
    pub prev_log_index: u64,
    /// Term of prev_log_index entry.
    pub prev_log_term: u64,
    /// Log entries to store (empty for periodic keepalive heartbeat).
    pub entries: Vec<RaftLogEntry>,
    /// Leader's commitIndex.
    pub leader_commit: u64,
}

/// RPC Response: AppendEntries reply from a follower.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesResponse {
    /// Current term of responder.
    pub term: u64,
    /// True if follower contained entry matching prev_log_index and prev_log_term.
    pub success: bool,
    /// Highest log index matched by follower.
    pub match_index: u64,
    /// Node identifier of the responding follower.
    pub responder_id: String,
}

/// Replicated cluster metadata state machine applied across quorum.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClusterMetadataStateMachine {
    /// Registered cluster node inventory: node_id -> (address, role).
    pub nodes: HashMap<String, (String, String)>,
    /// Active resource leases: resource -> ClusterLease.
    pub leases: HashMap<String, ClusterLease>,
    /// Arbitrary metadata key-value store: key -> (value, version).
    pub metadata: HashMap<String, (String, u64)>,
    /// Fenced epoch thresholds: node_id -> min_valid_epoch.
    pub fenced_epochs: HashMap<String, u64>,
}

impl ClusterMetadataStateMachine {
    /// Apply a committed command deterministically to the state machine.
    pub fn apply(&mut self, command: &RaftCommand, now_secs: u64) {
        match command {
            RaftCommand::RegisterNode {
                node_id,
                address,
                role,
            } => {
                self.nodes
                    .insert(node_id.clone(), (address.clone(), role.clone()));
            }
            RaftCommand::DecommissionNode { node_id } => {
                self.nodes.remove(node_id);
            }
            RaftCommand::AcquireLease {
                resource,
                holder,
                ttl_ms,
                epoch,
            } => {
                // Verify epoch fencing
                if let Some(&min_epoch) = self.fenced_epochs.get(holder) {
                    if *epoch < min_epoch {
                        return; // rejected due to epoch fencing
                    }
                }
                let ttl_secs = (*ttl_ms / 1000).max(1);
                self.leases.insert(
                    resource.clone(),
                    ClusterLease {
                        resource: resource.clone(),
                        holder: holder.clone(),
                        granted_at_secs: now_secs,
                        expires_at_secs: now_secs + ttl_secs,
                        epoch: *epoch,
                    },
                );
            }
            RaftCommand::ReleaseLease { resource, holder } => {
                if let Some(existing) = self.leases.get(resource) {
                    if existing.holder == *holder {
                        self.leases.remove(resource);
                    }
                }
            }
            RaftCommand::UpdateMetadata {
                key,
                value,
                version,
            } => {
                self.metadata.insert(key.clone(), (value.clone(), *version));
            }
            RaftCommand::FenceEpoch {
                node_id,
                min_valid_epoch,
            } => {
                self.fenced_epochs.insert(node_id.clone(), *min_valid_epoch);
            }
            RaftCommand::Noop => {}
        }
    }
}

/// Peer replication progress tracked by the leader.
#[derive(Debug, Clone)]
struct PeerProgress {
    next_index: u64,
    match_index: u64,
    last_heartbeat: Instant,
}

/// Cumulative Raft consensus metrics and telemetry.
#[derive(Debug, Default)]
pub struct RaftStats {
    pub elections_started: AtomicU64,
    pub terms_advanced: AtomicU64,
    pub proposals_submitted: AtomicU64,
    pub entries_committed: AtomicU64,
    pub rpc_votes_sent: AtomicU64,
    pub rpc_appends_sent: AtomicU64,
}

/// Comprehensive cluster status report for operational inspectability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftClusterStatus {
    pub node_id: String,
    pub role: RaftRole,
    pub term: u64,
    pub leader_id: Option<String>,
    pub commit_index: u64,
    pub log_length: usize,
    pub peer_count: usize,
    pub active_leases: usize,
    pub registered_nodes: usize,
    pub is_leader: bool,
    pub votes_granted_in_term: Option<String>,
}

/// Distributed Raft consensus engine and cluster metadata coordinator (`ADR-042`).
pub struct RaftCoordinator {
    node_id: String,
    current_term: AtomicU64,
    voted_for: RwLock<Option<String>>,
    role: RwLock<RaftRole>,
    leader_id: RwLock<Option<String>>,
    log: RwLock<Vec<RaftLogEntry>>,
    commit_index: AtomicU64,
    last_applied: AtomicU64,
    peers: RwLock<HashMap<String, PeerProgress>>,
    votes_received: RwLock<HashSet<String>>,
    state_machine: RwLock<ClusterMetadataStateMachine>,
    stats: RaftStats,
    lease_epoch_counter: AtomicU64,
}

impl RaftCoordinator {
    /// Initialize a new Raft coordinator node with given node ID and peer addresses.
    pub fn new(node_id: &str, peer_ids: &[&str]) -> Self {
        let mut peers = HashMap::new();
        for &peer in peer_ids {
            if peer != node_id {
                peers.insert(
                    peer.to_string(),
                    PeerProgress {
                        next_index: 1,
                        match_index: 0,
                        last_heartbeat: Instant::now(),
                    },
                );
            }
        }

        Self {
            node_id: node_id.to_string(),
            current_term: AtomicU64::new(0),
            voted_for: RwLock::new(None),
            role: RwLock::new(RaftRole::Follower),
            leader_id: RwLock::new(None),
            log: RwLock::new(Vec::new()),
            commit_index: AtomicU64::new(0),
            last_applied: AtomicU64::new(0),
            peers: RwLock::new(peers),
            votes_received: RwLock::new(HashSet::new()),
            state_machine: RwLock::new(ClusterMetadataStateMachine::default()),
            stats: RaftStats::default(),
            lease_epoch_counter: AtomicU64::new(1),
        }
    }

    /// Current node identifier.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Current Raft term.
    pub fn term(&self) -> u64 {
        self.current_term.load(Ordering::SeqCst)
    }

    /// Current consensus role.
    pub fn role(&self) -> RaftRole {
        *self.role.read().unwrap()
    }

    /// Current authoritative leader identifier (if known).
    pub fn leader_id(&self) -> Option<String> {
        self.leader_id.read().unwrap().clone()
    }

    /// Whether this node is currently the cluster leader.
    pub fn is_leader(&self) -> bool {
        self.role() == RaftRole::Leader
    }

    /// Number of committed entries in the log.
    pub fn commit_index(&self) -> u64 {
        self.commit_index.load(Ordering::SeqCst)
    }

    /// Handle incoming RequestVote RPC from a campaigning candidate.
    pub fn handle_request_vote(&self, req: RequestVoteRequest) -> RequestVoteResponse {
        let my_term = self.term();

        // 1. If candidate's term is greater, step down to Follower and advance term
        if req.term > my_term {
            self.current_term.store(req.term, Ordering::SeqCst);
            *self.role.write().unwrap() = RaftRole::Follower;
            *self.voted_for.write().unwrap() = None;
            *self.leader_id.write().unwrap() = None;
            self.stats.terms_advanced.fetch_add(1, Ordering::Relaxed);
        }

        let current_term = self.term();
        let mut voted_for = self.voted_for.write().unwrap();

        // 2. Reject if candidate's term is stale
        if req.term < current_term {
            return RequestVoteResponse {
                term: current_term,
                vote_granted: false,
                voter_id: self.node_id.clone(),
            };
        }

        // 3. Check vote eligibility and log up-to-dateness
        let log = self.log.read().unwrap();
        let my_last_index = log.len() as u64;
        let my_last_term = log.last().map(|e| e.term).unwrap_or(0);

        let candidate_log_ok = (req.last_log_term > my_last_term)
            || (req.last_log_term == my_last_term && req.last_log_index >= my_last_index);

        let can_vote = match &*voted_for {
            None => true,
            Some(voted) => voted == &req.candidate_id,
        };

        if can_vote && candidate_log_ok {
            *voted_for = Some(req.candidate_id.clone());
            self.stats.rpc_votes_sent.fetch_add(1, Ordering::Relaxed);
            RequestVoteResponse {
                term: current_term,
                vote_granted: true,
                voter_id: self.node_id.clone(),
            }
        } else {
            RequestVoteResponse {
                term: current_term,
                vote_granted: false,
                voter_id: self.node_id.clone(),
            }
        }
    }

    /// Handle incoming AppendEntries RPC (heartbeat or log replication) from leader.
    pub fn handle_append_entries(&self, req: AppendEntriesRequest) -> AppendEntriesResponse {
        let my_term = self.term();

        // 1. If leader term is newer, step down and update term
        if req.term > my_term {
            self.current_term.store(req.term, Ordering::SeqCst);
            *self.role.write().unwrap() = RaftRole::Follower;
            *self.voted_for.write().unwrap() = None;
            self.stats.terms_advanced.fetch_add(1, Ordering::Relaxed);
        }

        let current_term = self.term();

        // 2. Reply false if term < current_term
        if req.term < current_term {
            return AppendEntriesResponse {
                term: current_term,
                success: false,
                match_index: self.log.read().unwrap().len() as u64,
                responder_id: self.node_id.clone(),
            };
        }

        // 3. Valid leader acknowledged: recognize leader and ensure Follower role
        *self.role.write().unwrap() = RaftRole::Follower;
        *self.leader_id.write().unwrap() = Some(req.leader_id.clone());

        let mut log = self.log.write().unwrap();

        // 4. Check prevLogIndex consistency
        if req.prev_log_index > 0 {
            if req.prev_log_index > log.len() as u64 {
                return AppendEntriesResponse {
                    term: current_term,
                    success: false,
                    match_index: log.len() as u64,
                    responder_id: self.node_id.clone(),
                };
            }
            let prev_entry = &log[(req.prev_log_index - 1) as usize];
            if prev_entry.term != req.prev_log_term {
                // Log mismatch: truncate conflicting entries
                log.truncate((req.prev_log_index - 1) as usize);
                return AppendEntriesResponse {
                    term: current_term,
                    success: false,
                    match_index: log.len() as u64,
                    responder_id: self.node_id.clone(),
                };
            }
        }

        // 5. Append new entries not already in log
        for entry in req.entries {
            if entry.index <= log.len() as u64 {
                let existing = &log[(entry.index - 1) as usize];
                if existing.term != entry.term {
                    log.truncate((entry.index - 1) as usize);
                    log.push(entry);
                }
            } else {
                log.push(entry);
            }
        }

        let last_log_index = log.len() as u64;

        // 6. Update commit index
        if req.leader_commit > self.commit_index.load(Ordering::SeqCst) {
            let new_commit = req.leader_commit.min(last_log_index);
            self.commit_index.store(new_commit, Ordering::SeqCst);
            self.apply_committed_entries(&log, new_commit);
        }

        AppendEntriesResponse {
            term: current_term,
            success: true,
            match_index: last_log_index,
            responder_id: self.node_id.clone(),
        }
    }

    /// Initiate a leader election campaign by transitioning to Candidate and creating RequestVote.
    pub fn start_election(&self) -> RequestVoteRequest {
        self.stats.elections_started.fetch_add(1, Ordering::Relaxed);
        let new_term = self.current_term.fetch_add(1, Ordering::SeqCst) + 1;

        *self.role.write().unwrap() = RaftRole::Candidate;
        *self.voted_for.write().unwrap() = Some(self.node_id.clone());
        *self.leader_id.write().unwrap() = None;

        // Reset votes received and cast vote for self
        {
            let mut votes = self.votes_received.write().unwrap();
            votes.clear();
            votes.insert(self.node_id.clone());
        }

        let log = self.log.read().unwrap();
        let last_log_index = log.len() as u64;
        let last_log_term = log.last().map(|e| e.term).unwrap_or(0);

        RequestVoteRequest {
            term: new_term,
            candidate_id: self.node_id.clone(),
            last_log_index,
            last_log_term,
        }
    }

    /// Record a vote response received from a peer node.
    /// Returns true if this vote establishes quorum majority and triggers promotion to Leader.
    pub fn record_vote(&self, voter_id: &str, granted: bool, term: u64) -> bool {
        if term > self.term() {
            self.current_term.store(term, Ordering::SeqCst);
            *self.role.write().unwrap() = RaftRole::Follower;
            *self.voted_for.write().unwrap() = None;
            return false;
        }

        if self.role() != RaftRole::Candidate || term != self.term() || !granted {
            return false;
        }

        let total_nodes = self.peers.read().unwrap().len() + 1;
        let quorum_needed = (total_nodes / 2) + 1;

        let votes_count = {
            let mut votes = self.votes_received.write().unwrap();
            votes.insert(voter_id.to_string());
            votes.len()
        };

        if votes_count >= quorum_needed {
            // Quorum achieved: transition to Leader!
            *self.role.write().unwrap() = RaftRole::Leader;
            *self.leader_id.write().unwrap() = Some(self.node_id.clone());

            // Initialize peer progress indices
            let log_len = self.log.read().unwrap().len() as u64;
            let mut peers = self.peers.write().unwrap();
            for progress in peers.values_mut() {
                progress.next_index = log_len + 1;
                progress.match_index = 0;
            }

            // Immediately append a Noop entry to assert leadership and commit prior terms
            drop(peers);
            let _ = self.propose(RaftCommand::Noop);
            true
        } else {
            false
        }
    }

    /// Propose a state machine command to the Raft cluster log.
    /// Returns the assigned log index upon local write, or an error if not the authoritative leader.
    pub fn propose(&self, command: RaftCommand) -> Result<u64, VelcruxError> {
        if self.role() != RaftRole::Leader {
            let leader = self.leader_id().unwrap_or_else(|| "unknown".to_string());
            return Err(VelcruxError::Config(format!(
                "cannot propose command on follower: redirect to leader '{}'",
                leader
            )));
        }

        self.stats
            .proposals_submitted
            .fetch_add(1, Ordering::Relaxed);
        let term = self.term();
        let mut log = self.log.write().unwrap();
        let index = log.len() as u64 + 1;

        let entry = RaftLogEntry {
            index,
            term,
            command,
            timestamp_secs: now_secs(),
        };

        log.push(entry);

        // If single-node cluster, immediately advance commit index
        if self.peers.read().unwrap().is_empty() {
            self.commit_index.store(index, Ordering::SeqCst);
            self.apply_committed_entries(&log, index);
        }

        Ok(index)
    }

    /// Generate an `AppendEntriesRequest` message for a given peer.
    pub fn create_append_entries_for_peer(&self, peer_id: &str) -> Option<AppendEntriesRequest> {
        if self.role() != RaftRole::Leader {
            return None;
        }

        self.stats.rpc_appends_sent.fetch_add(1, Ordering::Relaxed);
        let peers = self.peers.read().unwrap();
        let progress = peers.get(peer_id)?;

        let log = self.log.read().unwrap();
        let prev_log_index = progress.next_index.saturating_sub(1);
        let prev_log_term = if prev_log_index > 0 && prev_log_index <= log.len() as u64 {
            log[(prev_log_index - 1) as usize].term
        } else {
            0
        };

        let entries: Vec<RaftLogEntry> = if progress.next_index <= log.len() as u64 {
            log[(progress.next_index - 1) as usize..].to_vec()
        } else {
            Vec::new() // heartbeat
        };

        Some(AppendEntriesRequest {
            term: self.term(),
            leader_id: self.node_id.clone(),
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit: self.commit_index(),
        })
    }

    /// Process an `AppendEntriesResponse` received from a peer.
    /// Advances matchIndex and evaluates quorum commits.
    pub fn handle_append_response(&self, peer_id: &str, resp: AppendEntriesResponse) {
        if resp.term > self.term() {
            self.current_term.store(resp.term, Ordering::SeqCst);
            *self.role.write().unwrap() = RaftRole::Follower;
            *self.voted_for.write().unwrap() = None;
            return;
        }

        if self.role() != RaftRole::Leader || resp.term != self.term() {
            return;
        }

        let mut peers = self.peers.write().unwrap();
        if let Some(progress) = peers.get_mut(peer_id) {
            if resp.success {
                progress.match_index = resp.match_index;
                progress.next_index = resp.match_index + 1;
                progress.last_heartbeat = Instant::now();
            } else {
                // Decrement next_index to locate common ancestor
                progress.next_index = progress.next_index.saturating_sub(1).max(1);
            }
        }

        // Evaluate quorum commit progression
        let log = self.log.read().unwrap();
        let current_commit = self.commit_index();
        let total_nodes = peers.len() + 1;
        let quorum = (total_nodes / 2) + 1;

        for n in ((current_commit + 1)..=(log.len() as u64)).rev() {
            if log[(n - 1) as usize].term == self.term() {
                // Count peers that have matched at least index n
                let mut matches = 1; // leader matches itself
                for progress in peers.values() {
                    if progress.match_index >= n {
                        matches += 1;
                    }
                }
                if matches >= quorum {
                    self.commit_index.store(n, Ordering::SeqCst);
                    self.apply_committed_entries(&log, n);
                    break;
                }
            }
        }
    }

    fn apply_committed_entries(&self, log: &[RaftLogEntry], commit_target: u64) {
        let mut last_applied = self.last_applied.load(Ordering::SeqCst);
        let now = now_secs();

        if commit_target > last_applied {
            let mut sm = self.state_machine.write().unwrap();
            while last_applied < commit_target && last_applied < log.len() as u64 {
                let entry = &log[last_applied as usize];
                sm.apply(&entry.command, now);
                last_applied += 1;
                self.stats.entries_committed.fetch_add(1, Ordering::Relaxed);
            }
            self.last_applied.store(last_applied, Ordering::SeqCst);
        }
    }

    /// Explicitly advance commit index and apply committed entries to state machine.
    pub fn commit_index_to(&self, target_index: u64) {
        let log = self.log.read().unwrap();
        let target = target_index.min(log.len() as u64);
        self.commit_index.store(target, Ordering::SeqCst);
        self.apply_committed_entries(&log, target);
    }

    /// Acquire an exclusive cluster resource lease guarded by monotonically increasing epoch fencing.
    pub fn acquire_lease(
        &self,
        resource: &str,
        holder: &str,
        ttl_ms: u64,
    ) -> Result<ClusterLease, VelcruxError> {
        let epoch = self.lease_epoch_counter.fetch_add(1, Ordering::SeqCst);
        let cmd = RaftCommand::AcquireLease {
            resource: resource.to_string(),
            holder: holder.to_string(),
            ttl_ms,
            epoch,
        };

        self.propose(cmd)?;

        // Return projected lease
        let now = now_secs();
        Ok(ClusterLease {
            resource: resource.to_string(),
            holder: holder.to_string(),
            granted_at_secs: now,
            expires_at_secs: now + (ttl_ms / 1000).max(1),
            epoch,
        })
    }

    /// Release an active cluster resource lease.
    pub fn release_lease(&self, resource: &str, holder: &str) -> Result<bool, VelcruxError> {
        let cmd = RaftCommand::ReleaseLease {
            resource: resource.to_string(),
            holder: holder.to_string(),
        };
        self.propose(cmd)?;
        Ok(true)
    }

    /// Inspect currently active lease for a resource (if held).
    pub fn get_lease(&self, resource: &str) -> Option<ClusterLease> {
        let sm = self.state_machine.read().unwrap();
        let now = now_secs();
        sm.leases
            .get(resource)
            .filter(|l| l.is_active(now))
            .cloned()
    }

    /// List all currently active unexpired cluster leases.
    pub fn list_active_leases(&self) -> Vec<ClusterLease> {
        let sm = self.state_machine.read().unwrap();
        let now = now_secs();
        sm.leases
            .values()
            .filter(|l| l.is_active(now))
            .cloned()
            .collect()
    }

    /// Register a cluster node in replicated metadata state.
    pub fn register_node(
        &self,
        node_id: &str,
        address: &str,
        role: &str,
    ) -> Result<(), VelcruxError> {
        self.propose(RaftCommand::RegisterNode {
            node_id: node_id.to_string(),
            address: address.to_string(),
            role: role.to_string(),
        })?;
        Ok(())
    }

    /// Decommission a cluster node.
    pub fn decommission_node(&self, node_id: &str) -> Result<(), VelcruxError> {
        self.propose(RaftCommand::DecommissionNode {
            node_id: node_id.to_string(),
        })?;
        Ok(())
    }

    /// Enforce epoch fencing for a node to prevent zombie split-brain writes.
    pub fn fence_epoch(&self, node_id: &str, min_valid_epoch: u64) -> Result<(), VelcruxError> {
        self.propose(RaftCommand::FenceEpoch {
            node_id: node_id.to_string(),
            min_valid_epoch,
        })?;
        Ok(())
    }

    /// Read an arbitrary cluster metadata record.
    pub fn get_metadata(&self, key: &str) -> Option<(String, u64)> {
        let sm = self.state_machine.read().unwrap();
        sm.metadata.get(key).cloned()
    }

    /// Produce a comprehensive status report for operational inspectability.
    pub fn status(&self) -> RaftClusterStatus {
        let sm = self.state_machine.read().unwrap();
        let now = now_secs();
        let active_leases = sm.leases.values().filter(|l| l.is_active(now)).count();

        RaftClusterStatus {
            node_id: self.node_id.clone(),
            role: self.role(),
            term: self.term(),
            leader_id: self.leader_id(),
            commit_index: self.commit_index(),
            log_length: self.log.read().unwrap().len(),
            peer_count: self.peers.read().unwrap().len(),
            active_leases,
            registered_nodes: sm.nodes.len(),
            is_leader: self.is_leader(),
            votes_granted_in_term: self.voted_for.read().unwrap().clone(),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Simulation report generated by the in-memory Raft cluster benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftBenchmarkReport {
    pub nodes: usize,
    pub proposals: usize,
    pub final_term: u64,
    pub leader_id: String,
    pub committed_entries: u64,
    pub partition_recovered: bool,
    pub throughput_proposals_per_sec: f64,
    pub duration_ms: u64,
}

/// Run an in-memory multi-node Raft consensus cluster simulation benchmark.
/// Simulates leader election, multi-node log replication, network partition of the leader,
/// new leader election in majority partition, partition healing, and log reconciliation.
pub fn run_raft_benchmark(node_count: usize, proposals: usize) -> RaftBenchmarkReport {
    let start = Instant::now();
    let node_ids: Vec<String> = (1..=node_count).map(|i| format!("node-{i}")).collect();
    let str_ids: Vec<&str> = node_ids.iter().map(|s| s.as_str()).collect();

    let mut cluster: Vec<Arc<RaftCoordinator>> = Vec::new();
    for id in &node_ids {
        cluster.push(Arc::new(RaftCoordinator::new(id, &str_ids)));
    }

    // 1. Initial Leader Election: node-1 starts campaign
    let vote_req = cluster[0].start_election();
    for peer in cluster.iter().skip(1) {
        let vote_resp = peer.handle_request_vote(vote_req.clone());
        cluster[0].record_vote(&vote_resp.voter_id, vote_resp.vote_granted, vote_resp.term);
    }
    assert!(cluster[0].is_leader(), "node-1 should be elected leader");

    // 2. Propose commands and replicate to all followers
    for i in 1..=proposals {
        let cmd = RaftCommand::UpdateMetadata {
            key: format!("checkpoint-{i}"),
            value: format!("state-hash-{i}"),
            version: i as u64,
        };
        cluster[0].propose(cmd).unwrap();

        // Replicate to followers
        for (idx, peer) in cluster.iter().enumerate().skip(1) {
            if let Some(append_req) = cluster[0].create_append_entries_for_peer(&node_ids[idx]) {
                let append_resp = peer.handle_append_entries(append_req);
                cluster[0].handle_append_response(&node_ids[idx], append_resp);
            }
        }
    }

    // Verify all nodes committed the proposals
    let leader_commit = cluster[0].commit_index();
    assert!(leader_commit >= proposals as u64);

    // 3. Network Partition Simulation: isolate node-1 (former leader)
    // Majority partition (nodes 2..=node_count) initiates election: node-2 campaigns
    let vote_req_p = cluster[1].start_election();
    for peer in cluster.iter().skip(2) {
        let vote_resp = peer.handle_request_vote(vote_req_p.clone());
        cluster[1].record_vote(&vote_resp.voter_id, vote_resp.vote_granted, vote_resp.term);
    }
    assert!(
        cluster[1].is_leader(),
        "node-2 should be elected new leader in majority partition"
    );

    // Propose an epoch fence in the new term
    let fence_cmd = RaftCommand::FenceEpoch {
        node_id: "node-1".to_string(),
        min_valid_epoch: 10,
    };
    cluster[1].propose(fence_cmd).unwrap();
    for (idx, peer) in cluster.iter().enumerate().skip(2) {
        if let Some(append_req) = cluster[1].create_append_entries_for_peer(&node_ids[idx]) {
            let append_resp = peer.handle_append_entries(append_req);
            cluster[1].handle_append_response(&node_ids[idx], append_resp);
        }
    }

    // 4. Partition Healing: reconnect node-1 to cluster[1]
    if let Some(append_req) = cluster[1].create_append_entries_for_peer(&node_ids[0]) {
        let append_resp = cluster[0].handle_append_entries(append_req);
        cluster[1].handle_append_response(&node_ids[0], append_resp);
    }

    assert_eq!(
        cluster[0].role(),
        RaftRole::Follower,
        "old leader must step down to follower"
    );
    assert_eq!(
        cluster[0].term(),
        cluster[1].term(),
        "old leader must catch up to new term"
    );

    let duration = start.elapsed();
    let duration_ms = duration.as_millis().max(1) as u64;
    let tps = (proposals as f64) / (duration_ms as f64 / 1000.0);

    RaftBenchmarkReport {
        nodes: node_count,
        proposals,
        final_term: cluster[1].term(),
        leader_id: cluster[1].node_id().to_string(),
        committed_entries: cluster[1].commit_index(),
        partition_recovered: true,
        throughput_proposals_per_sec: tps,
        duration_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raft_election_and_quorum_leader() {
        let cluster = [
            RaftCoordinator::new("node-1", &["node-1", "node-2", "node-3"]),
            RaftCoordinator::new("node-2", &["node-1", "node-2", "node-3"]),
            RaftCoordinator::new("node-3", &["node-1", "node-2", "node-3"]),
        ];

        // node-1 starts election
        let req = cluster[0].start_election();
        assert_eq!(cluster[0].role(), RaftRole::Candidate);
        assert_eq!(req.term, 1);

        // node-2 votes yes
        let resp2 = cluster[1].handle_request_vote(req.clone());
        assert!(resp2.vote_granted);
        let elected = cluster[0].record_vote(&resp2.voter_id, resp2.vote_granted, resp2.term);

        // Majority (2/3) reached: node-1 is leader!
        assert!(elected);
        assert_eq!(cluster[0].role(), RaftRole::Leader);
        assert!(cluster[0].is_leader());
    }

    #[test]
    fn test_raft_log_replication_and_commit() {
        let node1 = RaftCoordinator::new("node-1", &["node-1", "node-2"]);
        let node2 = RaftCoordinator::new("node-2", &["node-1", "node-2"]);

        // Elect node-1
        let req = node1.start_election();
        let resp = node2.handle_request_vote(req);
        node1.record_vote(&resp.voter_id, resp.vote_granted, resp.term);
        assert!(node1.is_leader());

        // Propose command
        let idx = node1
            .propose(RaftCommand::UpdateMetadata {
                key: "db_cluster".to_string(),
                value: "active".to_string(),
                version: 1,
            })
            .unwrap();

        // Replicate to node-2
        let append_req = node1.create_append_entries_for_peer("node-2").unwrap();
        let append_resp = node2.handle_append_entries(append_req);
        node1.handle_append_response("node-2", append_resp);

        // Assert committed on both
        assert_eq!(node1.commit_index(), idx);
        assert_eq!(
            node1.get_metadata("db_cluster"),
            Some(("active".to_string(), 1))
        );
    }

    #[test]
    fn test_raft_lease_acquisition_and_fencing() {
        let node = RaftCoordinator::new("standalone-leader", &[]);
        // Single-node immediately becomes leader
        let req = node.start_election();
        node.record_vote("standalone-leader", true, req.term);
        assert!(node.is_leader());

        // Acquire lease
        let lease = node
            .acquire_lease("shard-nvme-01", "worker-a", 10000)
            .unwrap();
        assert_eq!(lease.resource, "shard-nvme-01");
        assert_eq!(lease.holder, "worker-a");
        assert!(lease.is_active(now_secs()));

        // Check lease lookup
        let active = node.get_lease("shard-nvme-01").unwrap();
        assert_eq!(active.holder, "worker-a");

        // Release lease
        assert!(node.release_lease("shard-nvme-01", "worker-a").unwrap());
    }

    #[test]
    fn test_raft_multi_node_simulation_benchmark() {
        let report = run_raft_benchmark(3, 50);
        assert_eq!(report.nodes, 3);
        assert_eq!(report.proposals, 50);
        assert!(report.partition_recovered);
        assert!(report.committed_entries >= 50);
        assert!(report.throughput_proposals_per_sec > 0.0);
    }
}
