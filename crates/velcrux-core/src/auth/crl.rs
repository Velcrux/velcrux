//! Certificate Revocation List (CRL) parsing and store.
//!
//! Implements `OPERATIONS.md` §3, §4, §6, and `SECURITY.md` §2:
//! - CRL file parsing in PEM (`-----BEGIN X509 CRL-----`) or DER format.
//! - Revocation lookup by certificate serial number.
//! - Thread-safe runtime reloading on SIGHUP without dropping existing connections.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use tracing::info;

use crate::error::{Result, VelcruxError};

/// Thread-safe in-memory store for revoked certificate serial numbers.
#[derive(Debug, Default, Clone)]
pub struct CrlStore {
    revoked_serials: Arc<RwLock<HashSet<String>>>,
}

fn normalize_serial(serial_hex: &str) -> String {
    let lower = serial_hex.to_ascii_lowercase();
    let trimmed = lower.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

impl CrlStore {
    /// Create a new, empty CRL store.
    pub fn new() -> Self {
        Self {
            revoked_serials: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Insert a raw serial number (byte slice) into the revoked set.
    pub fn insert_serial(&self, serial: &[u8]) {
        let hex = serial
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        self.insert_serial_hex(&hex);
    }

    /// Insert a lowercase hex-encoded serial number into the revoked set.
    pub fn insert_serial_hex(&self, hex: &str) {
        if let Ok(mut set) = self.revoked_serials.write() {
            set.insert(normalize_serial(hex));
        }
    }

    /// Check if a given certificate serial number (hex string) is revoked.
    pub fn is_revoked(&self, serial_hex: &str) -> bool {
        if serial_hex.is_empty() {
            return false;
        }
        self.revoked_serials
            .read()
            .map(|set| set.contains(&normalize_serial(serial_hex)))
            .unwrap_or(false)
    }

    /// Load and add CRL entries from DER-encoded bytes.
    pub fn add_crl_der(&self, der: &[u8]) -> Result<usize> {
        use x509_parser::prelude::FromDer;
        use x509_parser::revocation_list::CertificateRevocationList;

        let (_, crl) = CertificateRevocationList::from_der(der)
            .map_err(|e| VelcruxError::Config(format!("failed to parse X.509 CRL DER: {e}")))?;

        let mut count = 0;
        if let Ok(mut set) = self.revoked_serials.write() {
            for revoked in crl.iter_revoked_certificates() {
                let hex = revoked
                    .raw_serial()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                set.insert(normalize_serial(&hex));
                count += 1;
            }
        }
        info!(revoked_count = count, "loaded X.509 CRL entries from DER");
        Ok(count)
    }

    /// Load and add CRL entries from a PEM bundle (or fallback to DER if already raw).
    pub fn add_crl_pem(&self, pem: &[u8]) -> Result<usize> {
        let crls = match rustls_pemfile::crls(&mut &pem[..]) {
            Ok(c) => c,
            Err(e) => {
                return Err(VelcruxError::Config(format!(
                    "failed to parse CRL PEM bundle: {e}"
                )));
            }
        };

        if crls.is_empty() {
            // Check if input is raw DER (starts with ASN.1 Sequence tag 0x30)
            if !pem.is_empty() && pem[0] == 0x30 {
                return self.add_crl_der(pem);
            }
            return Ok(0);
        }

        let mut total = 0;
        for der in crls {
            total += self.add_crl_der(&der)?;
        }
        Ok(total)
    }

    /// Atomically reload the CRL store from a PEM bundle (e.g. on SIGHUP).
    /// Replaces all previously loaded revoked serial numbers.
    pub fn reload_crl_pem(&self, pem: &[u8]) -> Result<usize> {
        let crls = match rustls_pemfile::crls(&mut &pem[..]) {
            Ok(c) => c,
            Err(e) => {
                return Err(VelcruxError::Config(format!(
                    "failed to parse CRL PEM bundle on reload: {e}"
                )));
            }
        };

        use x509_parser::prelude::FromDer;
        use x509_parser::revocation_list::CertificateRevocationList;

        let mut new_set = HashSet::new();

        if crls.is_empty() && !pem.is_empty() && pem[0] == 0x30 {
            let (_, crl) = CertificateRevocationList::from_der(pem).map_err(|e| {
                VelcruxError::Config(format!("failed to parse X.509 CRL DER on reload: {e}"))
            })?;
            for revoked in crl.iter_revoked_certificates() {
                let hex = revoked
                    .raw_serial()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                new_set.insert(normalize_serial(&hex));
            }
        } else {
            for der in crls {
                let (_, crl) = CertificateRevocationList::from_der(&der).map_err(|e| {
                    VelcruxError::Config(format!("failed to parse X.509 CRL DER on reload: {e}"))
                })?;
                for revoked in crl.iter_revoked_certificates() {
                    let hex = revoked
                        .raw_serial()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>();
                    new_set.insert(normalize_serial(&hex));
                }
            }
        }

        let count = new_set.len();
        if let Ok(mut set) = self.revoked_serials.write() {
            *set = new_set;
        }
        info!(revoked_count = count, "reloaded CRL store on SIGHUP");
        Ok(count)
    }

    /// Number of revoked serial numbers in the store.
    pub fn len(&self) -> usize {
        self.revoked_serials.read().map(|s| s.len()).unwrap_or(0)
    }

    /// True if no certificates are revoked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all revoked serial numbers.
    pub fn clear(&self) {
        if let Ok(mut set) = self.revoked_serials.write() {
            set.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
        DnType, IsCa, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber,
    };

    #[test]
    fn test_crl_store_manual_serials() {
        let store = CrlStore::new();
        assert!(store.is_empty());
        assert!(!store.is_revoked("01ab"));

        store.insert_serial_hex("01ab");
        assert_eq!(store.len(), 1);
        assert!(store.is_revoked("01ab"));
        assert!(store.is_revoked("01AB"));
        assert!(!store.is_revoked("01ac"));

        store.clear();
        assert!(store.is_empty());
        assert!(!store.is_revoked("01ab"));
    }

    #[test]
    fn test_crl_pem_der_parsing_with_rcgen() {
        // 1. Generate CA
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test-ca");
        ca_params.distinguished_name = dn;
        let ca_key = KeyPair::generate().expect("CA key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA self-sign");

        // 2. Build CRL revoking serial 0x42 and 0xbeef
        let crl_params = CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2026, 1, 1),
            next_update: rcgen::date_time_ymd(2026, 12, 31),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![
                RevokedCertParams {
                    serial_number: SerialNumber::from(0x42u64),
                    revocation_time: rcgen::date_time_ymd(2026, 1, 2),
                    reason_code: None,
                    invalidity_date: None,
                },
                RevokedCertParams {
                    serial_number: SerialNumber::from(0xbeefu64),
                    revocation_time: rcgen::date_time_ymd(2026, 1, 2),
                    reason_code: None,
                    invalidity_date: None,
                },
            ],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };

        let crl = crl_params.signed_by(&ca_cert, &ca_key).expect("sign CRL");
        let crl_pem = crl.pem().expect("crl pem");
        let crl_der = crl.der();

        // Test PEM parsing
        let store = CrlStore::new();
        let loaded = store.add_crl_pem(crl_pem.as_bytes()).expect("add crl pem");
        assert_eq!(loaded, 2);
        assert_eq!(store.len(), 2);
        assert!(store.is_revoked("42"));
        assert!(store.is_revoked("beef"));
        assert!(!store.is_revoked("cafe"));

        // Test DER parsing
        let store2 = CrlStore::new();
        let loaded2 = store2.add_crl_der(crl_der).expect("add crl der");
        assert_eq!(loaded2, 2);
        assert!(store2.is_revoked("42"));
        assert!(store2.is_revoked("beef"));
        assert!(!store2.is_revoked("cafe"));
    }
}
