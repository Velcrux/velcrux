//! Continuous real-time file watcher, event debouncing, and automated sync engine (Option AZ).
//!
//! Implements `REQUIREMENTS.md` §64–§68 and `ARCHITECTURE.md` §9, §12.
//! Provides pure-Rust directory change monitoring, event coalescing,
//! and batch synchronization without unsafe code or external C library dependencies.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::VelcruxError;
use crate::sync::plan::PathFilter;

/// Type of filesystem modification detected for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// A new file was created.
    Created,
    /// An existing file had its contents or length modified.
    Modified,
    /// A file was removed or unlinked.
    Deleted,
}

/// An individual file modification event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChangeEvent {
    /// Relative path from the watched directory root (forward slash normalized).
    pub rel_path: String,
    /// Classification of modification.
    pub kind: ChangeKind,
    /// Current size in bytes (0 if Deleted).
    pub size: u64,
    /// Last modified time in seconds since Unix epoch.
    pub mtime_secs: u64,
    /// Last modified time nanosecond fraction.
    pub mtime_nanos: u32,
    /// Timestamp when this event was detected locally.
    #[serde(skip, default = "Instant::now")]
    pub detected_at: Instant,
}

impl FileChangeEvent {
    /// Construct a new file change event.
    pub fn new(
        rel_path: impl Into<String>,
        kind: ChangeKind,
        size: u64,
        mtime_secs: u64,
        mtime_nanos: u32,
    ) -> Self {
        Self {
            rel_path: rel_path.into(),
            kind,
            size,
            mtime_secs,
            mtime_nanos,
            detected_at: Instant::now(),
        }
    }
}

/// A coalesced batch of file modifications ready to be synchronized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeBatch {
    /// Monotonically increasing batch sequence number.
    pub batch_id: u64,
    /// List of relative paths created in this batch.
    pub created: Vec<String>,
    /// List of relative paths modified in this batch.
    pub modified: Vec<String>,
    /// List of relative paths deleted in this batch.
    pub deleted: Vec<String>,
    /// Total number of unique file paths affected in this batch.
    pub total_changes: usize,
    /// Number of redundant interim events coalesced into this batch.
    pub coalesced_count: usize,
    /// Latency elapsed between the first detected event and batch dispatch in milliseconds.
    pub duration_since_first_event_ms: u64,
}

impl ChangeBatch {
    /// Return all distinct affected relative file paths in this batch.
    pub fn all_affected_paths(&self) -> Vec<String> {
        let mut paths = Vec::with_capacity(self.total_changes);
        paths.extend(self.created.iter().cloned());
        paths.extend(self.modified.iter().cloned());
        paths.extend(self.deleted.iter().cloned());
        paths.sort();
        paths.dedup();
        paths
    }

    /// Check if this batch is empty.
    pub fn is_empty(&self) -> bool {
        self.total_changes == 0
    }
}

/// Configuration options for real-time continuous directory watching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchConfig {
    /// Debounce quiet window during which further changes reset the dispatch timer (default: 200ms).
    pub debounce_window: Duration,
    /// Interval between directory traversal scan sweeps (default: 500ms).
    pub poll_interval: Duration,
    /// Maximum number of batches to process before terminating (None = continuous loop).
    pub max_batches: Option<usize>,
    /// Glob filter patterns for excluding paths from watching.
    pub filter: PathFilter,
    /// Maximum number of pending events held in the debounce queue before forcing a flush.
    pub max_queue_depth: usize,
    /// Whether to coalesce rapid updates to the same path (default: true).
    pub coalesce: bool,
    /// Initial sync mode: if true, all existing files are emitted as Created on startup.
    pub initial_sync: bool,
}

impl Default for WatchConfig {
    fn default() -> Self {
        let mut filter = PathFilter::new();
        filter.add_exclude(".git/**");
        filter.add_exclude(".git");
        filter.add_exclude(".velcrux-*/**");
        filter.add_exclude("*.tmp");
        filter.add_exclude("*.swp");
        filter.add_exclude("*~");

        Self {
            debounce_window: Duration::from_millis(200),
            poll_interval: Duration::from_millis(500),
            max_batches: None,
            filter,
            max_queue_depth: 10_000,
            coalesce: true,
            initial_sync: false,
        }
    }
}

impl WatchConfig {
    /// Create new configuration with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set debounce window.
    pub fn with_debounce(mut self, window: Duration) -> Self {
        self.debounce_window = window;
        self
    }

    /// Set polling scan interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Set maximum batches to execute before halting.
    pub fn with_max_batches(mut self, max: usize) -> Self {
        self.max_batches = if max == 0 { None } else { Some(max) };
        self
    }

    /// Add an exclusion pattern.
    pub fn with_exclude(mut self, pattern: impl Into<String>) -> Self {
        self.filter.add_exclude(pattern);
        self
    }

    /// Configure whether an initial full sync sweep should be emitted on startup.
    pub fn with_initial_sync(mut self, initial: bool) -> Self {
        self.initial_sync = initial;
        self
    }
}

/// Operational metrics for directory watch synchronization.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchMetrics {
    /// Total raw file modification events detected.
    pub total_events_detected: u64,
    /// Number of rapid redundant events merged via debouncing.
    pub total_events_coalesced: u64,
    /// Number of synchronization batches dispatched.
    pub total_batches_dispatched: u64,
    /// Number of files successfully processed across all batches.
    pub total_files_synced: u64,
    /// Total bytes transferred / synchronized across all batches.
    pub total_bytes_synced: u64,
    /// Average debounce coalescing duration in milliseconds.
    pub average_debounce_ms: f64,
    /// Latency of the most recent batch synchronization in milliseconds.
    pub last_batch_latency_ms: f64,
}

/// Final summary report generated upon watch termination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchSummary {
    /// Total batches processed.
    pub total_batches: u64,
    /// Total files synchronized.
    pub total_files_synced: u64,
    /// Total raw events captured.
    pub total_events_detected: u64,
    /// Total redundant events eliminated through debouncing.
    pub total_events_coalesced: u64,
    /// Wall-clock running time in seconds.
    pub elapsed_duration_secs: f64,
    /// Termination status message.
    pub status: String,
}

/// Internal file state snapshot tracking mtime and size.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileEntrySnapshot {
    size: u64,
    mtime_secs: u64,
    mtime_nanos: u32,
}

/// Filesystem scanner comparing directory trees between sweeps.
#[derive(Debug, Clone, Default)]
pub struct DirectoryScanner {
    baseline: BTreeMap<String, FileEntrySnapshot>,
}

impl DirectoryScanner {
    /// Create a scanner initialized with the current directory tree baseline.
    /// Existing files will not trigger change events on the first scan.
    pub fn new(root: &Path, filter: &PathFilter) -> Result<Self, std::io::Error> {
        let mut scanner = Self::default();
        if root.exists() {
            scanner.baseline = Self::snapshot_tree(root, filter)?;
        }
        Ok(scanner)
    }

    /// Create an uninitialized scanner. The first scan will emit all files as Created.
    pub fn new_uninitialized() -> Self {
        Self::default()
    }

    /// Take a full recursive snapshot of regular files under `root`.
    fn snapshot_tree(
        root: &Path,
        filter: &PathFilter,
    ) -> Result<BTreeMap<String, FileEntrySnapshot>, std::io::Error> {
        let mut map = BTreeMap::new();
        if !root.is_dir() {
            return Ok(map);
        }

        Self::walk_recursive(root, root, filter, &mut map)?;
        Ok(map)
    }

    fn walk_recursive(
        dir: &Path,
        root: &Path,
        filter: &PathFilter,
        map: &mut BTreeMap<String, FileEntrySnapshot>,
    ) -> Result<(), std::io::Error> {
        let entries = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) => return Err(e),
        };

        for entry_res in entries {
            let entry = entry_res?;
            let path = entry.path();
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Ignore dotfiles, temp files, and internal staging directories
            if name_str.starts_with(".velcrux-")
                || name_str.ends_with(".tmp")
                || name_str.ends_with(".swp")
                || name_str.ends_with('~')
            {
                continue;
            }

            let rel_path = match path.strip_prefix(root) {
                Ok(p) => p.to_string_lossy().replace('\\', "/"),
                Err(_) => continue,
            };

            if filter.is_excluded(&rel_path) {
                continue;
            }

            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                // Do not descend into excluded directories
                let dir_pattern = format!("{}/", rel_path);
                if filter.is_excluded(&dir_pattern) {
                    continue;
                }
                Self::walk_recursive(&path, root, filter, map)?;
            } else if file_type.is_file() || file_type.is_symlink() {
                if let Ok(meta) = entry.metadata() {
                    let size = meta.len();
                    let (mtime_secs, mtime_nanos) = match meta.modified() {
                        Ok(t) => {
                            let dur = t.duration_since(UNIX_EPOCH).unwrap_or_default();
                            (dur.as_secs(), dur.subsec_nanos())
                        }
                        Err(_) => (0, 0),
                    };

                    map.insert(
                        rel_path,
                        FileEntrySnapshot {
                            size,
                            mtime_secs,
                            mtime_nanos,
                        },
                    );
                }
            }
        }

        Ok(())
    }

    /// Perform a scan of `root`, returning all detected `FileChangeEvent`s since the last scan.
    pub fn scan(
        &mut self,
        root: &Path,
        filter: &PathFilter,
    ) -> Result<Vec<FileChangeEvent>, std::io::Error> {
        let current = Self::snapshot_tree(root, filter)?;
        let mut events = Vec::new();

        // Check for Created and Modified
        for (rel_path, curr_snap) in &current {
            match self.baseline.get(rel_path) {
                None => {
                    events.push(FileChangeEvent::new(
                        rel_path,
                        ChangeKind::Created,
                        curr_snap.size,
                        curr_snap.mtime_secs,
                        curr_snap.mtime_nanos,
                    ));
                }
                Some(prev_snap) => {
                    if prev_snap.size != curr_snap.size
                        || prev_snap.mtime_secs != curr_snap.mtime_secs
                        || prev_snap.mtime_nanos != curr_snap.mtime_nanos
                    {
                        events.push(FileChangeEvent::new(
                            rel_path,
                            ChangeKind::Modified,
                            curr_snap.size,
                            curr_snap.mtime_secs,
                            curr_snap.mtime_nanos,
                        ));
                    }
                }
            }
        }

        // Check for Deleted
        for (rel_path, prev_snap) in &self.baseline {
            if !current.contains_key(rel_path) {
                events.push(FileChangeEvent::new(
                    rel_path,
                    ChangeKind::Deleted,
                    0,
                    prev_snap.mtime_secs,
                    prev_snap.mtime_nanos,
                ));
            }
        }

        self.baseline = current;
        Ok(events)
    }

    /// Current count of tracked regular files in snapshot baseline.
    pub fn tracked_file_count(&self) -> usize {
        self.baseline.len()
    }
}

/// In-memory debounce queue holding pending change events until quiet window expires.
#[derive(Debug)]
pub struct DebounceQueue {
    /// Pending events mapped by normalized relative path.
    pending: HashMap<String, (FileChangeEvent, Instant)>,
    /// Earliest event arrival timestamp for current pending set.
    first_event_at: Option<Instant>,
    /// Total redundant events coalesced in this queue.
    coalesced_count: usize,
    /// Monotonically increasing batch ID sequence.
    next_batch_id: u64,
}

impl Default for DebounceQueue {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            first_event_at: None,
            coalesced_count: 0,
            next_batch_id: 1,
        }
    }
}

impl DebounceQueue {
    /// Create a new empty debounce queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push an event into the debounce queue, coalescing with existing pending events if enabled.
    pub fn push(&mut self, event: FileChangeEvent, coalesce: bool) {
        let now = Instant::now();
        if self.first_event_at.is_none() {
            self.first_event_at = Some(now);
        }

        if !coalesce {
            self.pending.insert(event.rel_path.clone(), (event, now));
            return;
        }

        if let Some((existing, _)) = self.pending.get_mut(&event.rel_path) {
            match (existing.kind, event.kind) {
                // Created followed by Modified remains Created (with updated size/mtime)
                (ChangeKind::Created, ChangeKind::Modified) => {
                    existing.size = event.size;
                    existing.mtime_secs = event.mtime_secs;
                    existing.mtime_nanos = event.mtime_nanos;
                    existing.detected_at = now;
                    self.coalesced_count += 1;
                }
                // Created followed by Deleted cancels out (file was ephemeral)
                (ChangeKind::Created, ChangeKind::Deleted) => {
                    self.pending.remove(&event.rel_path);
                    self.coalesced_count += 2;
                }
                // Modified followed by Modified stays Modified
                (ChangeKind::Modified, ChangeKind::Modified) => {
                    existing.size = event.size;
                    existing.mtime_secs = event.mtime_secs;
                    existing.mtime_nanos = event.mtime_nanos;
                    existing.detected_at = now;
                    self.coalesced_count += 1;
                }
                // Deleted followed by Created is treated as Modified
                (ChangeKind::Deleted, ChangeKind::Created) => {
                    existing.kind = ChangeKind::Modified;
                    existing.size = event.size;
                    existing.mtime_secs = event.mtime_secs;
                    existing.mtime_nanos = event.mtime_nanos;
                    existing.detected_at = now;
                    self.coalesced_count += 1;
                }
                // Any other combination overwrites
                _ => {
                    *existing = event;
                }
            }
        } else {
            self.pending.insert(event.rel_path.clone(), (event, now));
        }
    }

    /// Number of distinct paths currently queued.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Drain events whose debounce quiet window has expired into a ChangeBatch.
    pub fn drain_ready(&mut self, debounce_window: Duration, now: Instant) -> Option<ChangeBatch> {
        if self.pending.is_empty() {
            self.first_event_at = None;
            return None;
        }

        // Check if all events in queue have been quiet for at least debounce_window
        let all_ready = self
            .pending
            .values()
            .all(|(_, last_updated)| now.duration_since(*last_updated) >= debounce_window);

        if !all_ready {
            return None;
        }

        self.drain_all(now)
    }

    /// Unconditionally drain all pending events into a ChangeBatch.
    pub fn drain_all(&mut self, now: Instant) -> Option<ChangeBatch> {
        if self.pending.is_empty() {
            self.first_event_at = None;
            return None;
        }

        let first = self.first_event_at.unwrap_or(now);
        let duration_ms = now.duration_since(first).as_millis() as u64;

        let mut created = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();

        for (event, _) in self.pending.drain().map(|(_, v)| v) {
            match event.kind {
                ChangeKind::Created => created.push(event.rel_path),
                ChangeKind::Modified => modified.push(event.rel_path),
                ChangeKind::Deleted => deleted.push(event.rel_path),
            }
        }

        created.sort();
        modified.sort();
        deleted.sort();

        let total_changes = created.len() + modified.len() + deleted.len();
        let batch_id = self.next_batch_id;
        self.next_batch_id += 1;
        self.first_event_at = None;

        let batch = ChangeBatch {
            batch_id,
            created,
            modified,
            deleted,
            total_changes,
            coalesced_count: self.coalesced_count,
            duration_since_first_event_ms: duration_ms,
        };

        self.coalesced_count = 0;
        Some(batch)
    }
}

/// Continuous synchronization coordinator orchestrating scanning, debouncing, and batch sync triggers.
pub struct ContinuousSyncCoordinator {
    /// Watched directory root.
    root: PathBuf,
    /// Watch configuration.
    config: WatchConfig,
    /// Directory tree scanner.
    scanner: DirectoryScanner,
    /// Debounce event queue.
    queue: DebounceQueue,
    /// Live performance metrics.
    metrics: Arc<RwLock<WatchMetrics>>,
    /// Cooperative cancellation / shutdown signal.
    shutdown: Arc<AtomicBool>,
}

impl ContinuousSyncCoordinator {
    /// Create a new continuous sync coordinator.
    pub fn new(root: PathBuf, config: WatchConfig) -> Result<Self, std::io::Error> {
        let scanner = if config.initial_sync {
            DirectoryScanner::new_uninitialized()
        } else {
            DirectoryScanner::new(&root, &config.filter)?
        };

        Ok(Self {
            root,
            config,
            scanner,
            queue: DebounceQueue::new(),
            metrics: Arc::new(RwLock::new(WatchMetrics::default())),
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Obtain a handle to cooperatively signal coordinator shutdown.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Access current live metrics snapshot.
    pub fn metrics(&self) -> WatchMetrics {
        self.metrics.read().unwrap().clone()
    }

    /// Perform a single scan step and return a batch if debounce window expired.
    pub fn step_once(&mut self) -> Result<Option<ChangeBatch>, std::io::Error> {
        let events = self.scanner.scan(&self.root, &self.config.filter)?;
        let count = events.len();

        if count > 0 {
            let mut m = self.metrics.write().unwrap();
            m.total_events_detected += count as u64;
        }

        for event in events {
            self.queue.push(event, self.config.coalesce);
        }

        let now = Instant::now();
        // If queue exceeds max depth, flush immediately
        if self.queue.pending_count() >= self.config.max_queue_depth {
            return Ok(self.queue.drain_all(now));
        }

        Ok(self.queue.drain_ready(self.config.debounce_window, now))
    }

    /// Run the continuous sync loop asynchronously, invoking `sync_action` whenever a batch is ready.
    pub async fn run_continuous<F, Fut>(
        &mut self,
        mut sync_action: F,
    ) -> Result<WatchSummary, VelcruxError>
    where
        F: FnMut(&ChangeBatch) -> Fut,
        Fut: std::future::Future<Output = Result<usize, VelcruxError>>,
    {
        let start_time = Instant::now();
        let mut batches_dispatched = 0usize;
        let mut files_synced_total = 0usize;

        while !self.shutdown.load(Ordering::Relaxed) {
            // Check max batches condition
            if let Some(max) = self.config.max_batches {
                if batches_dispatched >= max {
                    break;
                }
            }

            // Step scan and debounce
            let maybe_batch = self.step_once().map_err(VelcruxError::Io)?;

            if let Some(batch) = maybe_batch {
                if !batch.is_empty() {
                    let batch_start = Instant::now();
                    let files_count = sync_action(&batch).await?;
                    let batch_latency = batch_start.elapsed().as_secs_f64() * 1000.0;

                    batches_dispatched += 1;
                    files_synced_total += files_count;

                    {
                        let mut m = self.metrics.write().unwrap();
                        m.total_batches_dispatched += 1;
                        m.total_files_synced += files_count as u64;
                        m.total_events_coalesced += batch.coalesced_count as u64;
                        m.last_batch_latency_ms = batch_latency;
                    }
                }
            }

            tokio::time::sleep(self.config.poll_interval).await;
        }

        // Flush any remaining pending changes on clean shutdown
        if let Some(final_batch) = self.queue.drain_all(Instant::now()) {
            if !final_batch.is_empty() {
                let files_count = sync_action(&final_batch).await?;
                batches_dispatched += 1;
                files_synced_total += files_count;

                let mut m = self.metrics.write().unwrap();
                m.total_batches_dispatched += 1;
                m.total_files_synced += files_count as u64;
            }
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let final_metrics = self.metrics();

        Ok(WatchSummary {
            total_batches: batches_dispatched as u64,
            total_files_synced: files_synced_total as u64,
            total_events_detected: final_metrics.total_events_detected,
            total_events_coalesced: final_metrics.total_events_coalesced,
            elapsed_duration_secs: elapsed,
            status: "Completed".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_debounce_queue_coalescing() {
        let mut queue = DebounceQueue::new();

        // 1. Created followed by rapid Modified -> stays Created
        queue.push(
            FileChangeEvent::new("doc.txt", ChangeKind::Created, 100, 1000, 0),
            true,
        );
        queue.push(
            FileChangeEvent::new("doc.txt", ChangeKind::Modified, 150, 1001, 0),
            true,
        );

        assert_eq!(queue.pending_count(), 1);
        let batch = queue.drain_all(Instant::now()).unwrap();
        assert_eq!(batch.created, vec!["doc.txt"]);
        assert!(batch.modified.is_empty());
        assert_eq!(batch.coalesced_count, 1);

        // 2. Created followed by Deleted -> cancelled (ephemeral)
        queue.push(
            FileChangeEvent::new("temp.tmp", ChangeKind::Created, 50, 2000, 0),
            true,
        );
        queue.push(
            FileChangeEvent::new("temp.tmp", ChangeKind::Deleted, 0, 2001, 0),
            true,
        );
        assert_eq!(queue.pending_count(), 0);

        // 3. Multiple Modified events -> single Modified
        queue.push(
            FileChangeEvent::new("log.txt", ChangeKind::Modified, 200, 3000, 0),
            true,
        );
        queue.push(
            FileChangeEvent::new("log.txt", ChangeKind::Modified, 250, 3001, 0),
            true,
        );
        queue.push(
            FileChangeEvent::new("log.txt", ChangeKind::Modified, 300, 3002, 0),
            true,
        );
        let batch2 = queue.drain_all(Instant::now()).unwrap();
        assert_eq!(batch2.modified, vec!["log.txt"]);
        // 2 from ephemeral temp.tmp cancellation + 2 from duplicate log.txt modifications
        assert_eq!(batch2.coalesced_count, 4);
    }

    #[test]
    fn test_directory_scanner_create_modify_delete() {
        let dir = tempdir().unwrap();
        let path = dir.path();
        let filter = PathFilter::new();

        let mut scanner = DirectoryScanner::new(path, &filter).unwrap();
        assert_eq!(scanner.tracked_file_count(), 0);

        // Step 1: Create file_a.txt
        let file_a = path.join("file_a.txt");
        fs::write(&file_a, b"Hello World").unwrap();

        let events1 = scanner.scan(path, &filter).unwrap();
        assert_eq!(events1.len(), 1);
        assert_eq!(events1[0].rel_path, "file_a.txt");
        assert_eq!(events1[0].kind, ChangeKind::Created);

        // Scan again with no changes -> 0 events
        let events_empty = scanner.scan(path, &filter).unwrap();
        assert!(events_empty.is_empty());

        // Step 2: Modify file_a.txt (update length and content)
        std::thread::sleep(Duration::from_millis(15));
        fs::write(&file_a, b"Hello World with longer text!").unwrap();

        let events2 = scanner.scan(path, &filter).unwrap();
        assert_eq!(events2.len(), 1);
        assert_eq!(events2[0].rel_path, "file_a.txt");
        assert_eq!(events2[0].kind, ChangeKind::Modified);

        // Step 3: Delete file_a.txt
        fs::remove_file(&file_a).unwrap();

        let events3 = scanner.scan(path, &filter).unwrap();
        assert_eq!(events3.len(), 1);
        assert_eq!(events3[0].rel_path, "file_a.txt");
        assert_eq!(events3[0].kind, ChangeKind::Deleted);
    }

    #[tokio::test]
    async fn test_continuous_sync_coordinator_loop() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let config = WatchConfig::new()
            .with_debounce(Duration::from_millis(50))
            .with_poll_interval(Duration::from_millis(20))
            .with_max_batches(1);

        let mut coordinator = ContinuousSyncCoordinator::new(path.clone(), config).unwrap();

        // Create a file in background
        let target_file = path.join("realtime_data.bin");
        fs::write(&target_file, b"test content for watch sync").unwrap();

        let batches_seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let batches_clone = batches_seen.clone();
        let summary = coordinator
            .run_continuous(|batch| {
                let b = batch.clone();
                let b_list = batches_clone.clone();
                let changes = batch.total_changes;
                async move {
                    b_list.lock().unwrap().push(b);
                    Ok(changes)
                }
            })
            .await
            .unwrap();

        assert_eq!(summary.total_batches, 1);
        let list = batches_seen.lock().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].created, vec!["realtime_data.bin"]);
    }
}
