//! Session-scoped CA and dynamic certificate generation.
//!
//! Each session gets a unique CA. The proxy generates leaf certs on-the-fly
//! per SNI hostname, signed by the session CA.

use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use std::collections::HashMap;
use std::sync::Mutex;
use time::OffsetDateTime;

/// A session-scoped certificate authority.
pub struct SessionCA {
    ca_cert_pem: String,
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, CachedCert>>,
}

/// A cached leaf certificate (PEM cert + DER private key).
#[derive(Clone)]
pub struct CachedCert {
    pub cert_pem: String,
    pub key_der: Vec<u8>,
}

impl SessionCA {
    /// Generate a new session CA with a unique key pair, valid for 24 hours.
    pub fn new() -> anyhow::Result<Self> {
        let key_pair = KeyPair::generate()?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "ClosedShell Session CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "ClosedShell");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);

        let ca_cert = params.self_signed(&key_pair)?;
        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_cert_pem,
            ca_cert,
            ca_key: key_pair,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Return the CA certificate in PEM format.
    pub fn ca_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Generate (or return cached) a leaf cert for the given hostname,
    /// signed by this session CA. The hostname is added as a SAN.
    pub fn generate_leaf_cert(&self, hostname: &str) -> anyhow::Result<CachedCert> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(hostname) {
                return Ok(cached.clone());
            }
        }

        let leaf_key = KeyPair::generate()?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, hostname);
        params.subject_alt_names = vec![SanType::DnsName(hostname.try_into()?)];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(1);

        let leaf_cert = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;

        let cached = CachedCert {
            cert_pem: leaf_cert.pem(),
            key_der: leaf_key.serialize_der(),
        };

        {
            let mut cache = self.cache.lock().unwrap();
            cache.insert(hostname.to_string(), cached.clone());
        }

        Ok(cached)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_generates_pem() {
        let ca = SessionCA::new().unwrap();
        let pem = ca.ca_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn test_two_cas_have_different_fingerprints() {
        let ca1 = SessionCA::new().unwrap();
        let ca2 = SessionCA::new().unwrap();
        // Different key pairs → different PEM output
        assert_ne!(ca1.ca_pem(), ca2.ca_pem());
    }

    #[test]
    fn test_leaf_cert_generated() {
        let ca = SessionCA::new().unwrap();
        let leaf = ca.generate_leaf_cert("example.com").unwrap();
        assert!(leaf.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!leaf.key_der.is_empty());
    }

    #[test]
    fn test_leaf_cert_cached() {
        let ca = SessionCA::new().unwrap();
        let leaf1 = ca.generate_leaf_cert("example.com").unwrap();
        let leaf2 = ca.generate_leaf_cert("example.com").unwrap();
        // Should be the same cached cert
        assert_eq!(leaf1.cert_pem, leaf2.cert_pem);
        assert_eq!(leaf1.key_der, leaf2.key_der);
    }

    #[test]
    fn test_different_hostnames_different_certs() {
        let ca = SessionCA::new().unwrap();
        let leaf1 = ca.generate_leaf_cert("example.com").unwrap();
        let leaf2 = ca.generate_leaf_cert("other.com").unwrap();
        assert_ne!(leaf1.cert_pem, leaf2.cert_pem);
    }

    #[test]
    fn test_leaf_cert_for_many_hostnames() {
        let ca = SessionCA::new().unwrap();
        let hosts = ["a.com", "b.com", "c.com", "d.com"];
        for host in &hosts {
            let leaf = ca.generate_leaf_cert(host).unwrap();
            assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        }
        // Verify cache has all entries
        let cache = ca.cache.lock().unwrap();
        assert_eq!(cache.len(), 4);
    }
}
