use super::TlsAuthority;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::net::{IpAddr, Ipv4Addr};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

#[test]
fn authority_rejects_malformed_ca_material() {
    let error = TlsAuthority::from_pem(b"not a certificate", b"not a key", 4).unwrap_err();

    assert!(error.to_string().contains("CA certificate"));
}

#[test]
fn authority_rejects_a_private_key_that_does_not_match_the_ca() {
    let (certificate, _) = test_ca();
    let other_key = KeyPair::generate().unwrap().serialize_pem();

    let error =
        TlsAuthority::from_pem(certificate.as_bytes(), other_key.as_bytes(), 4).unwrap_err();

    assert!(error.to_string().contains("does not match"));
}

#[test]
fn authority_issues_exact_dns_and_ip_subject_alt_names() {
    let (certificate, key) = test_ca();
    let authority = TlsAuthority::from_pem(certificate.as_bytes(), key.as_bytes(), 4).unwrap();

    let dns = authority.issue("api.example.test").unwrap();
    let ip = authority.issue("127.0.0.1").unwrap();

    assert_eq!(
        subject_alt_names(dns.certificate_der()),
        vec!["api.example.test"]
    );
    assert_eq!(subject_alt_names(ip.certificate_der()), vec!["127.0.0.1"]);
    assert_eq!(authority.trust_anchor_der(), ca_der(&certificate));
}

#[test]
fn authority_reuses_cached_certificates_and_bounds_the_cache() {
    let (certificate, key) = test_ca();
    let authority = TlsAuthority::from_pem(certificate.as_bytes(), key.as_bytes(), 2).unwrap();

    let first = authority.issue("one.example.test").unwrap();
    let again = authority.issue("one.example.test").unwrap();
    authority.issue("two.example.test").unwrap();
    authority.issue("three.example.test").unwrap();

    assert!(std::sync::Arc::ptr_eq(&first, &again));
    assert_eq!(authority.cache_len(), 2);
}

fn test_ca() -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["Agora Sandbox Test CA".to_string()]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let certificate = params.self_signed(&key).unwrap();
    (certificate.pem(), key.serialize_pem())
}

fn subject_alt_names(der: &[u8]) -> Vec<String> {
    let (_, certificate) = X509Certificate::from_der(der).unwrap();
    certificate
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(value) => Some((*value).to_string()),
            GeneralName::IPAddress(value) if value.len() == 4 => {
                Some(IpAddr::V4(Ipv4Addr::new(value[0], value[1], value[2], value[3])).to_string())
            }
            _ => None,
        })
        .collect()
}

fn ca_der(certificate: &str) -> Vec<u8> {
    rustls_pemfile::certs(&mut certificate.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec()
}
