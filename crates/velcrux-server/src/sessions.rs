//! Active session registry and operator termination engine (`docs/OPERATIONS.md` §6, `docs/SECURITY.md` §2).

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{watch, RwLock};

/// Operational session information exposed to operators over CLI/HTTP.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInfo {
    /// Server connection identifier.
    pub conn_id: u64,
    /// Authenticated peer identity name, or None if still handshaking.
    pub identity: Option<String>,
    /// Remote socket address of the client peer.
    pub remote_addr: String,
    /// Connection uptime in seconds.
    pub uptime_secs: u64,
}

/// Internal session entry tracking an active connection actor.
pub struct ActiveSession {
    pub conn_id: u64,
    pub identity: Option<String>,
    pub remote_addr: SocketAddr,
    pub connected_at: Instant,
    pub kill_tx: watch::Sender<bool>,
}

/// Thread-safe registry of live client connections.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: RwLock<HashMap<u64, ActiveSession>>,
}

impl SessionRegistry {
    /// Construct a new empty session registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: RwLock::new(HashMap::new()),
        })
    }

    /// Register a newly accepted connection, returning a kill signal receiver.
    pub async fn register(&self, conn_id: u64, remote_addr: SocketAddr) -> watch::Receiver<bool> {
        let (kill_tx, kill_rx) = watch::channel(false);
        let session = ActiveSession {
            conn_id,
            identity: None,
            remote_addr,
            connected_at: Instant::now(),
            kill_tx,
        };
        let mut g = self.sessions.write().await;
        g.insert(conn_id, session);
        kill_rx
    }

    /// Update the session's authenticated identity once verified.
    pub async fn set_identity(&self, conn_id: u64, identity: &str) {
        let mut g = self.sessions.write().await;
        if let Some(s) = g.get_mut(&conn_id) {
            s.identity = Some(identity.to_string());
        }
    }

    /// Remove a terminated connection from the registry.
    pub async fn unregister(&self, conn_id: u64) {
        let mut g = self.sessions.write().await;
        g.remove(&conn_id);
    }

    /// Return a snapshot list of all active sessions sorted by connection ID.
    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        let g = self.sessions.read().await;
        let mut list: Vec<SessionInfo> = g
            .values()
            .map(|s| SessionInfo {
                conn_id: s.conn_id,
                identity: s.identity.clone(),
                remote_addr: s.remote_addr.to_string(),
                uptime_secs: s.connected_at.elapsed().as_secs(),
            })
            .collect();
        list.sort_by_key(|s| s.conn_id);
        list
    }

    /// Terminate all live sessions matching the specified identity name.
    /// Returns the number of sessions signaled to terminate.
    pub async fn kill_by_identity(&self, identity: &str) -> usize {
        let g = self.sessions.read().await;
        let mut count = 0;
        for s in g.values() {
            if s.identity.as_deref() == Some(identity) {
                let _ = s.kill_tx.send(true);
                count += 1;
            }
        }
        count
    }

    /// Terminate a specific session by its connection ID.
    pub async fn kill_by_conn_id(&self, conn_id: u64) -> bool {
        let g = self.sessions.read().await;
        if let Some(s) = g.get(&conn_id) {
            let _ = s.kill_tx.send(true);
            true
        } else {
            false
        }
    }
}
