//! Content-addressed manifest cache store (`ARCHITECTURE.md` §3 & §5).
//!
//! Stores manifests keyed by their canonical BLAKE3 content hash:
//! `<storage_root>/manifests/<hex_hash>.manifest`.
//!
//! Because a manifest is content-addressed, repeated transfers of unchanged
//! directory trees or files can reuse the existing manifest without resending
//! or regenerating it (ADR-005).

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::manifest::reader::ManifestReader;
use crate::util::Hash;

/// Content-addressed store for manifest spill files.
pub struct ManifestStore {
    root_dir: PathBuf,
}

impl ManifestStore {
    /// Initialize the manifest store under `root_dir`. Creates the directory if missing.
    pub fn new(root_dir: impl AsRef<Path>) -> Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();
        fs::create_dir_all(&root_dir)?;
        Ok(Self { root_dir })
    }

    /// Return the canonical file path for a manifest with `hash`.
    pub fn manifest_path(&self, hash: &Hash) -> PathBuf {
        self.root_dir.join(format!("{}.manifest", hash))
    }

    /// Check if the store contains a valid cached manifest for `hash`.
    pub fn has_manifest(&self, hash: &Hash) -> bool {
        self.manifest_path(hash).is_file()
    }

    /// Atomically commit a spill file to the store under its content hash.
    pub fn save_manifest(&self, hash: &Hash, spill_path: impl AsRef<Path>) -> Result<PathBuf> {
        let dest_path = self.manifest_path(hash);
        if dest_path.is_file() {
            // Already present, remove the temporary spill file
            let _ = fs::remove_file(spill_path);
            return Ok(dest_path);
        }

        // Atomic rename or copy if cross-device
        match fs::rename(&spill_path, &dest_path) {
            Ok(()) => Ok(dest_path),
            Err(_) => {
                fs::copy(&spill_path, &dest_path)?;
                let _ = fs::remove_file(spill_path);
                Ok(dest_path)
            }
        }
    }

    /// Open a cached manifest for reading.
    pub fn open_manifest(&self, hash: &Hash) -> Result<ManifestReader> {
        let path = self.manifest_path(hash);
        ManifestReader::open(&path, *hash)
    }

    /// Remove a manifest from the store.
    pub fn remove_manifest(&self, hash: &Hash) -> Result<()> {
        let path = self.manifest_path(hash);
        if path.is_file() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}
