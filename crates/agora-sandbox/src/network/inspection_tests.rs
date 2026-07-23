use super::inspection::{DomainObservation, ProtocolInspector};
use crate::audit::DomainSource;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::sync::Arc;

#[test]
fn http_host_is_detected_and_normalized() {
    let mut inspector = ProtocolInspector::new();

    assert_eq!(
        inspector.inspect(b"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\n"),
        None
    );
    assert_eq!(
        inspector.inspect(b"Connection: close\r\n\r\n"),
        Some(DomainObservation {
            domain: "example.com".to_string(),
            source: DomainSource::HttpHost,
        })
    );
}

#[test]
fn fragmented_tls_client_hello_sni_is_detected() {
    let hello = tls_client_hello("secure.example.com");
    let split = hello.len() / 2;
    let mut inspector = ProtocolInspector::new();

    assert_eq!(inspector.inspect(&hello[..split]), None);
    assert_eq!(
        inspector.inspect(&hello[split..]),
        Some(DomainObservation {
            domain: "secure.example.com".to_string(),
            source: DomainSource::TlsSni,
        })
    );
}

#[test]
fn non_http_and_non_tls_payload_has_no_domain() {
    let mut inspector = ProtocolInspector::new();

    assert_eq!(inspector.inspect(b"SSH-2.0-OpenSSH_9.9\r\n"), None);
    assert_eq!(inspector.inspect(b"Host: misleading.example\r\n\r\n"), None);
}

fn tls_client_hello(server_name: &str) -> Vec<u8> {
    let config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let server_name = ServerName::try_from(server_name.to_string()).expect("valid server name");
    let mut connection =
        ClientConnection::new(Arc::new(config), server_name).expect("client connection");
    let mut hello = Vec::new();
    connection.write_tls(&mut hello).expect("client hello");
    hello
}
