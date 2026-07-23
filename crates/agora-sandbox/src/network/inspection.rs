use crate::audit::DomainSource;
use rustls::server::Acceptor;
use std::io::Cursor;
use std::net::IpAddr;

const MAX_INSPECTION_BYTES: usize = 64 * 1024;
const MAX_HTTP_HEADERS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DomainObservation {
    pub(super) domain: String,
    pub(super) source: DomainSource,
}

pub(super) struct ProtocolInspector {
    buffer: Vec<u8>,
    protocol: Protocol,
}

impl ProtocolInspector {
    pub(super) fn new() -> Self {
        Self {
            buffer: Vec::new(),
            protocol: Protocol::Unknown,
        }
    }

    pub(super) fn inspect(&mut self, bytes: &[u8]) -> Option<DomainObservation> {
        if self.protocol == Protocol::Done || bytes.is_empty() {
            return None;
        }
        if self.buffer.len().saturating_add(bytes.len()) > MAX_INSPECTION_BYTES {
            self.finish();
            return None;
        }
        self.buffer.extend_from_slice(bytes);
        if self.protocol == Protocol::Unknown {
            self.protocol = match self.buffer.first() {
                Some(0x16) => Protocol::Tls,
                Some(first) if first.is_ascii_alphabetic() => Protocol::Http,
                Some(_) => Protocol::Done,
                None => Protocol::Unknown,
            };
        }

        let result = match self.protocol {
            Protocol::Http => Self::inspect_http(&self.buffer),
            Protocol::Tls => Self::inspect_tls(&self.buffer),
            Protocol::Unknown | Protocol::Done => InspectionResult::Complete(None),
        };
        match result {
            InspectionResult::Pending => None,
            InspectionResult::Complete(observation) => {
                self.finish();
                observation
            }
            InspectionResult::Invalid => {
                self.finish();
                None
            }
        }
    }

    fn inspect_http(bytes: &[u8]) -> InspectionResult {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(bytes) {
            Ok(httparse::Status::Partial) => InspectionResult::Pending,
            Ok(httparse::Status::Complete(_)) => {
                let observation = request
                    .headers
                    .iter()
                    .find(|header| header.name.eq_ignore_ascii_case("host"))
                    .and_then(|header| Self::normalize_domain(header.value))
                    .map(|domain| DomainObservation {
                        domain,
                        source: DomainSource::HttpHost,
                    });
                InspectionResult::Complete(observation)
            }
            Err(_) => InspectionResult::Invalid,
        }
    }

    fn inspect_tls(bytes: &[u8]) -> InspectionResult {
        let mut acceptor = Acceptor::default();
        let mut reader = Cursor::new(bytes);
        if acceptor.read_tls(&mut reader).is_err() {
            return InspectionResult::Invalid;
        }
        match acceptor.accept() {
            Ok(None) => InspectionResult::Pending,
            Ok(Some(accepted)) => {
                let observation = accepted
                    .client_hello()
                    .server_name()
                    .and_then(|domain| Self::normalize_domain(domain.as_bytes()))
                    .map(|domain| DomainObservation {
                        domain,
                        source: DomainSource::TlsSni,
                    });
                InspectionResult::Complete(observation)
            }
            Err(_) => InspectionResult::Invalid,
        }
    }

    fn normalize_domain(value: &[u8]) -> Option<String> {
        let value = std::str::from_utf8(value).ok()?.trim();
        let host = if let Some(bracketed) = value.strip_prefix('[') {
            bracketed.split_once(']')?.0
        } else if let Some((host, port)) = value.rsplit_once(':') {
            if port.parse::<u16>().is_ok() {
                host
            } else {
                value
            }
        } else {
            value
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            None
        } else {
            Some(host)
        }
    }

    fn finish(&mut self) {
        self.protocol = Protocol::Done;
        self.buffer.clear();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Protocol {
    Unknown,
    Http,
    Tls,
    Done,
}

enum InspectionResult {
    Pending,
    Complete(Option<DomainObservation>),
    Invalid,
}
