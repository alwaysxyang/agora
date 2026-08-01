use super::{load_pem_root_certificates, other_error, timeout_error};
use rcgen::{CertificateParams, KeyPair};
use std::io::ErrorKind;

#[test]
fn fallback_root_bundle_accepts_certificates_and_rejects_invalid_inputs() {
    let directory =
        std::env::temp_dir().join(format!("agora-fallback-roots-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&directory).unwrap();

    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(Vec::new())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let valid = directory.join("valid.pem");
    std::fs::write(&valid, certificate.pem()).unwrap();
    assert_eq!(
        load_pem_root_certificates(valid.to_str().unwrap())
            .unwrap()
            .len(),
        1
    );

    let empty = directory.join("empty.pem");
    std::fs::write(&empty, b"").unwrap();
    assert!(
        load_pem_root_certificates(empty.to_str().unwrap())
            .unwrap_err()
            .to_string()
            .contains("contains no certificates")
    );

    let malformed = directory.join("malformed.pem");
    std::fs::write(
        &malformed,
        b"-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    assert!(load_pem_root_certificates(malformed.to_str().unwrap()).is_err());
    assert!(
        load_pem_root_certificates(directory.join("missing.pem").to_str().unwrap())
            .unwrap_err()
            .to_string()
            .contains("failed to read fallback TLS roots")
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn tls_error_helpers_preserve_their_intended_error_kinds() {
    let other = other_error("TLS bridge failed");
    assert_eq!(other.kind(), ErrorKind::Other);
    assert_eq!(other.to_string(), "TLS bridge failed");

    let timeout = timeout_error("TLS handshake timed out");
    assert_eq!(timeout.kind(), ErrorKind::TimedOut);
    assert_eq!(timeout.to_string(), "TLS handshake timed out");
}
