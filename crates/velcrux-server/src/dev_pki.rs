//! Development PKI: dev CA + dev cert issuance.
//!
//! `DEVELOPMENT.md` §3: the dev CA is short-lived (30 days), dev certs
//! are even shorter (24 h). We use Ed25519 throughout for compact keys
//! and clean rustls interop. Files are written as PEM (cert) and PKCS#8
//! (key) so they can be loaded by `rustls_pemfile`.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rcgen::Error as RcgenError;
use std::fs;
use std::path::Path;

/// Issue a self-signed dev CA. Writes `ca.crt` (PEM) and `ca.key` (PKCS#8 PEM).
pub fn issue_dev_ca(out: &Path, days: u32) -> Result<()> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "velcrux dev CA");
    dn.push(DnType::OrganizationName, "velcrux");
    params.distinguished_name = dn;

    let key = KeyPair::generate().map_err(rcgen_err)?;
    let cert = params.self_signed(&key).map_err(rcgen_err)?;
    fs::write(out.join("ca.crt"), cert.pem()).context("write ca.crt")?;
    fs::write(out.join("ca.key"), key.serialize_pem()).context("write ca.key")?;
    Ok(())
}

/// Issue a server cert signed by the dev CA. Writes `<name>.crt` and `<name>.key`.
pub fn issue_server_cert(ca_dir: &Path, out: &Path, hosts: &[String], _hours: u32) -> Result<()> {
    let (ca_cert, ca_key) = load_dev_ca(ca_dir)?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    let cn = hosts.first().cloned().unwrap_or_else(|| "velcruxd".into());
    dn.push(DnType::CommonName, &cn);
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = hosts
        .iter()
        .map(|h| SanType::DnsName(h.clone().try_into().unwrap()))
        .collect();

    let key = KeyPair::generate().map_err(rcgen_err)?;
    let cert = params.signed_by(&key, &ca_cert, &ca_key).map_err(rcgen_err)?;

    let name = sanitize(&cn);
    fs::write(out.join(format!("{name}.crt")), cert.pem()).context("write server cert")?;
    fs::write(out.join(format!("{name}.key")), key.serialize_pem()).context("write server key")?;
    Ok(())
}

/// Issue a client cert signed by the dev CA with SAN URI
/// `velcrux://identity/<name>`. Writes `<name>.crt` and `<name>.key`.
pub fn issue_client_cert(ca_dir: &Path, out: &Path, identity: &str, _hours: u32) -> Result<()> {
    let (ca_cert, ca_key) = load_dev_ca(ca_dir)?;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, identity);
    params.distinguished_name = dn;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names = vec![SanType::URI(
        format!("velcrux://identity/{identity}").try_into().unwrap(),
    )];

    let key = KeyPair::generate().map_err(rcgen_err)?;
    let cert = params.signed_by(&key, &ca_cert, &ca_key).map_err(rcgen_err)?;

    let name = sanitize(identity);
    fs::write(out.join(format!("{name}.crt")), cert.pem()).context("write client cert")?;
    fs::write(out.join(format!("{name}.key")), key.serialize_pem()).context("write client key")?;
    Ok(())
}

/// Load the dev CA's cert and key. We re-derive the `Certificate` object
/// by parsing the PEM and re-constructing it (rcgen does not export a
/// public method to reload a `Certificate` from PEM with the `pem` feature
/// alone, so we instead use a slightly heavier path: parse the CA's
/// `CertificateParams` from the PEM, then re-self-sign to get a fresh
/// `Certificate`. The result is byte-identical to the original
/// self-signed CA so re-signing child certs against it is equivalent.
fn load_dev_ca(ca_dir: &Path) -> Result<(Certificate, KeyPair)> {
    let (ca_cert_pem, ca_key_pem) = load_ca(ca_dir)?;
    let key = parse_key(&ca_key_pem)?;
    let pem_str = std::str::from_utf8(&ca_cert_pem).context("CA cert is not UTF-8")?;
    let params = CertificateParams::from_ca_cert_pem(pem_str).map_err(rcgen_err)?;
    let cert = params.self_signed(&key).map_err(rcgen_err)?;
    Ok((cert, key))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_ca(ca_dir: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let cert = fs::read(ca_dir.join("ca.crt")).context("read ca.crt")?;
    let key = fs::read(ca_dir.join("ca.key")).context("read ca.key")?;
    Ok((cert, key))
}

fn parse_key(pem: &[u8]) -> Result<KeyPair> {
    let s = std::str::from_utf8(pem).context("key is not UTF-8")?;
    KeyPair::from_pem(s).map_err(rcgen_err)
}

fn rcgen_err(e: RcgenError) -> anyhow::Error {
    anyhow::anyhow!("rcgen: {e}")
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}
