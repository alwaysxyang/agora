pub(super) mod certificate;
mod io;

#[cfg(test)]
mod io_tests;

pub(super) use certificate::TlsAuthority;

use super::UpstreamConnection;
use super::inspection::TlsClientHello;
use super::relay::{RelayOutcome, relay_bidirectional};
use anyhow::{Result, bail};
pub(super) use io::PrefixedIo;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fmt;
use std::io as std_io;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub(in crate::network) struct TlsBridge {
    authority: TlsAuthority,
    upstream_roots: RootCertStore,
}

impl TlsBridge {
    pub(in crate::network) fn new(authority: TlsAuthority) -> Result<Self> {
        let native = rustls_native_certs::load_native_certs();
        if native.certs.is_empty() {
            let details = native
                .errors
                .first()
                .map_or_else(|| "no certificates found".to_string(), ToString::to_string);
            bail!("failed to load native TLS roots: {details}");
        }
        Self::with_root_certificates(authority, native.certs)
    }

    pub(in crate::network) fn with_root_certificates(
        authority: TlsAuthority,
        certificates: Vec<CertificateDer<'static>>,
    ) -> Result<Self> {
        let mut upstream_roots = RootCertStore::empty();
        let (valid, _) = upstream_roots.add_parsable_certificates(certificates);
        if valid == 0 {
            bail!("upstream TLS root store contains no valid certificates");
        }
        Ok(Self {
            authority,
            upstream_roots,
        })
    }

    pub(in crate::network) fn trust_anchor_der(&self) -> Vec<u8> {
        self.authority.trust_anchor_der()
    }

    pub(in crate::network) async fn establish(
        &self,
        client: TcpStream,
        upstream: UpstreamConnection,
        initial_client_data: Vec<u8>,
        hello: &TlsClientHello,
        identity: String,
        timeout: Duration,
    ) -> std_io::Result<TlsConnection> {
        let certificate = self.authority.issue(&identity).map_err(other_error)?;
        let server_name = ServerName::try_from(identity.clone()).map_err(|error| {
            std_io::Error::new(
                std_io::ErrorKind::InvalidInput,
                format!("invalid TLS server identity {identity}: {error}"),
            )
        })?;
        let mut upstream_config = ClientConfig::builder()
            .with_root_certificates(self.upstream_roots.clone())
            .with_no_client_auth();
        upstream_config.alpn_protocols.clone_from(&hello.alpn);
        let connector = TlsConnector::from(Arc::new(upstream_config));
        let upstream = tokio::time::timeout(
            timeout,
            connector.connect(
                server_name,
                PrefixedIo::new(upstream.initial_data, upstream.stream),
            ),
        )
        .await
        .map_err(|_| timeout_error("upstream TLS handshake timed out"))?
        .map_err(other_error)?;
        let upstream_alpn = upstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);

        let mut downstream_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedResolver(certificate.certified_key())));
        downstream_config.alpn_protocols = upstream_alpn.iter().cloned().collect();
        let acceptor = TlsAcceptor::from(Arc::new(downstream_config));
        let downstream = tokio::time::timeout(
            timeout,
            acceptor.accept(PrefixedIo::new(initial_client_data, client)),
        )
        .await
        .map_err(|_| timeout_error("downstream TLS handshake timed out"))?
        .map_err(other_error)?;
        let downstream_alpn = downstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        if downstream_alpn != upstream_alpn {
            return Err(std_io::Error::other(
                "upstream and downstream TLS ALPN negotiation differ",
            ));
        }

        Ok(TlsConnection {
            downstream,
            upstream,
            alpn: upstream_alpn.map(|protocol| String::from_utf8_lossy(&protocol).into_owned()),
        })
    }
}

pub(in crate::network) struct TlsConnection {
    downstream: tokio_rustls::server::TlsStream<PrefixedIo<TcpStream>>,
    upstream: tokio_rustls::client::TlsStream<PrefixedIo<TcpStream>>,
    alpn: Option<String>,
}

impl TlsConnection {
    pub(in crate::network) fn alpn(&self) -> Option<&str> {
        self.alpn.as_deref()
    }

    pub(in crate::network) async fn relay(self) -> RelayOutcome {
        relay_bidirectional(self.downstream, self.upstream).await
    }
}

struct FixedResolver(Arc<CertifiedKey>);

impl fmt::Debug for FixedResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("FixedResolver").finish()
    }
}

impl ResolvesServerCert for FixedResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

fn other_error(error: impl fmt::Display) -> std_io::Error {
    std_io::Error::other(error.to_string())
}

fn timeout_error(message: &'static str) -> std_io::Error {
    std_io::Error::new(std_io::ErrorKind::TimedOut, message)
}
