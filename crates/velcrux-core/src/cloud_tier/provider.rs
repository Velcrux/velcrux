//! Cloud Object Storage Provider Abstraction & Range-GET Client Engine.
//!
//! Encapsulates multi-cloud wire operations (AWS S3, Google Cloud Storage, Azure Blob,
//! and Local Posix staging), tracking request operations, byte transfers, and simulated cloud costs.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use super::types::{CloudProviderKind, CloudStorageUri, CloudTierClass};
use crate::error::{ProtocolError, Result, VelcruxError};

/// Multi-cloud object storage endpoint instance.
#[derive(Debug, Clone)]
pub struct CloudStorageEndpoint {
    pub endpoint_id: String,
    pub provider: CloudProviderKind,
    pub bucket_or_container: String,
    pub region: String,
    /// In-memory storage representation: `key -> (bytes, tier_class)`
    pub objects: HashMap<String, (Vec<u8>, CloudTierClass)>,
    /// Metrics and cost accounting
    pub put_requests: u64,
    pub get_requests: u64,
    pub range_get_requests: u64,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
}

impl CloudStorageEndpoint {
    pub fn new(
        endpoint_id: impl Into<String>,
        provider: CloudProviderKind,
        bucket_or_container: impl Into<String>,
        region: impl Into<String>,
    ) -> Self {
        Self {
            endpoint_id: endpoint_id.into(),
            provider,
            bucket_or_container: bucket_or_container.into(),
            region: region.into(),
            objects: HashMap::new(),
            put_requests: 0,
            get_requests: 0,
            range_get_requests: 0,
            bytes_uploaded: 0,
            bytes_downloaded: 0,
        }
    }

    /// Uploads an object container to cloud storage.
    pub fn put_object(
        &mut self,
        key: &str,
        data: Vec<u8>,
        tier: CloudTierClass,
    ) -> Result<CloudStorageUri> {
        let len = data.len() as u64;
        self.objects.insert(key.to_string(), (data, tier));
        self.put_requests = self.put_requests.saturating_add(1);
        self.bytes_uploaded = self.bytes_uploaded.saturating_add(len);

        Ok(CloudStorageUri::new(
            self.provider,
            &self.bucket_or_container,
            key,
        ))
    }

    /// Fetches a full object from cloud storage.
    pub fn get_object(&mut self, key: &str) -> Option<(&[u8], CloudTierClass)> {
        self.get_requests = self.get_requests.saturating_add(1);
        if let Some((bytes, tier)) = self.objects.get(key) {
            self.bytes_downloaded = self.bytes_downloaded.saturating_add(bytes.len() as u64);
            Some((bytes.as_slice(), *tier))
        } else {
            None
        }
    }

    /// Executes an HTTP `Range: bytes=start-end` random-access read, fetching ONLY the target chunk bytes.
    pub fn get_object_range(
        &mut self,
        key: &str,
        start: u64,
        end: u64,
    ) -> Option<(Vec<u8>, CloudTierClass)> {
        self.range_get_requests = self.range_get_requests.saturating_add(1);

        let (bytes, tier) = self.objects.get(key)?;
        let start = start as usize;
        let end = (end as usize).min(bytes.len().saturating_sub(1));

        if start > end || start >= bytes.len() {
            return None;
        }

        let slice = bytes[start..=end].to_vec();
        self.bytes_downloaded = self.bytes_downloaded.saturating_add(slice.len() as u64);
        Some((slice, *tier))
    }

    /// Transitions an object's cloud storage class (e.g. S3 Standard -> Glacier, Azure Hot -> Cool).
    pub fn transition_object_tier(&mut self, key: &str, new_tier: CloudTierClass) -> Result<()> {
        let entry = self.objects.get_mut(key).ok_or_else(|| {
            VelcruxError::Protocol(ProtocolError::Malformed(
                "object not found on cloud endpoint",
            ))
        })?;

        entry.1 = new_tier;
        Ok(())
    }

    /// Deletes an object from cloud storage.
    pub fn delete_object(&mut self, key: &str) -> bool {
        self.objects.remove(key).is_some()
    }

    /// Calculates estimated cloud bill: PUT/GET request costs + storage costs.
    pub fn estimate_monthly_cost_usd(&self) -> f64 {
        // Standard pricing approximation:
        // PUT request: $0.005 per 1,000 requests
        // GET request: $0.0004 per 1,000 requests
        // Storage per GB: Hot $0.023, Cool $0.0125, Cold $0.004, DeepArchive $0.00099
        let put_cost = (self.put_requests as f64 / 1000.0) * 0.005;
        let get_cost = ((self.get_requests + self.range_get_requests) as f64 / 1000.0) * 0.0004;

        let mut storage_cost = 0.0;
        for (bytes, tier) in self.objects.values() {
            let gb = (bytes.len() as f64) / (1024.0 * 1024.0 * 1024.0);
            let rate = match tier {
                CloudTierClass::Hot => 0.023,
                CloudTierClass::Cool => 0.0125,
                CloudTierClass::Cold => 0.004,
                CloudTierClass::DeepArchive => 0.00099,
            };
            storage_cost += gb * rate;
        }

        put_cost + get_cost + storage_cost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_range_get_and_metrics() {
        let mut endpoint = CloudStorageEndpoint::new(
            "aws-us-east-1",
            CloudProviderKind::AwsS3,
            "velcrux-prod-chunks",
            "us-east-1",
        );

        let data = vec![0x11u8; 1024];
        let uri = endpoint
            .put_object("c1.vlxt", data, CloudTierClass::Hot)
            .unwrap();
        assert_eq!(uri.to_uri_string(), "s3://velcrux-prod-chunks/c1.vlxt");

        // Range GET: fetch bytes 10..20
        let (range_data, tier) = endpoint.get_object_range("c1.vlxt", 10, 20).unwrap();
        assert_eq!(range_data.len(), 11);
        assert_eq!(tier, CloudTierClass::Hot);
        assert_eq!(endpoint.range_get_requests, 1);
        assert_eq!(endpoint.bytes_downloaded, 11);

        // Transition tier to Cold
        endpoint
            .transition_object_tier("c1.vlxt", CloudTierClass::Cold)
            .unwrap();
        let (_, tier_after) = endpoint.get_object_range("c1.vlxt", 10, 20).unwrap();
        assert_eq!(tier_after, CloudTierClass::Cold);
    }
}
