use super::config::HookConfig;
use super::interpose::ProcessContext;
use super::socket::{RawSocketAddress, socket_addr_from_raw};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

#[test]
fn ipv4_socket_address_round_trips_through_raw_storage() {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443);
    let raw = RawSocketAddress::new(address);

    let decoded = unsafe { socket_addr_from_raw(raw.as_ptr(), raw.len()) };

    assert_eq!(decoded, Some(address));
}

#[test]
fn ipv6_socket_address_round_trips_scope_and_flow_information() {
    let address = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 12, 7));
    let raw = RawSocketAddress::new(address);

    let decoded = unsafe { socket_addr_from_raw(raw.as_ptr(), raw.len()) };

    assert_eq!(decoded, Some(address));
}

#[test]
fn hook_configuration_requires_all_runtime_values() {
    let values = HashMap::from([
        ("AGORA_SANDBOX_TOKEN", "token"),
        ("AGORA_SANDBOX_PROXY_IPV4", "127.0.0.1:41000"),
        ("AGORA_SANDBOX_PROXY_IPV6", "[::1]:41001"),
        ("AGORA_SANDBOX_EXECUTION_CONTROL", "127.0.0.1:41002"),
        ("AGORA_SANDBOX_EXECUTION_TOKEN", "execution-token"),
        ("AGORA_SANDBOX_HOOK_LIBRARIES", "/tmp/hook.dylib"),
        ("AGORA_SANDBOX_TRACE_IDS", "trace-root"),
    ]);
    let config = HookConfig::from_getter(|key| values.get(key).map(ToString::to_string)).unwrap();

    assert_eq!(config.tls_trust_anchor_der(), None);

    assert_eq!(
        config.proxy_for(SocketAddr::from(([203, 0, 113, 10], 443))),
        SocketAddr::from(([127, 0, 0, 1], 41000))
    );
    assert_eq!(
        config.proxy_for(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443))),
        "[::1]:41001".parse().unwrap()
    );
    assert!(config.is_internal("127.0.0.1:41000".parse().unwrap()));
    assert!(config.is_internal("[::1]:41001".parse().unwrap()));
    assert!(config.is_internal("127.0.0.1:41002".parse().unwrap()));

    let error = HookConfig::from_getter(|key| {
        (key != "AGORA_SANDBOX_TOKEN")
            .then(|| values.get(key).map(ToString::to_string))
            .flatten()
    })
    .unwrap_err();
    assert!(error.contains("AGORA_SANDBOX_TOKEN"));
}

#[test]
fn hook_configuration_propagates_an_optional_tls_trust_anchor() {
    let values = HashMap::from([
        ("AGORA_SANDBOX_TOKEN", "token"),
        ("AGORA_SANDBOX_PROXY_IPV4", "127.0.0.1:41000"),
        ("AGORA_SANDBOX_PROXY_IPV6", "[::1]:41001"),
        ("AGORA_SANDBOX_EXECUTION_CONTROL", "127.0.0.1:41002"),
        ("AGORA_SANDBOX_EXECUTION_TOKEN", "execution-token"),
        ("AGORA_SANDBOX_HOOK_LIBRARIES", "/tmp/hook.dylib"),
        ("AGORA_SANDBOX_TRACE_IDS", "trace-root"),
        ("AGORA_SANDBOX_TLS_TRUST_ANCHOR_DER", "Y2VydGlmaWNhdGU="),
        ("AGORA_SANDBOX_TLS_TRUST_BUNDLE", "/tmp/agora-ca.pem"),
    ]);

    let config = HookConfig::from_getter(|key| values.get(key).map(ToString::to_string)).unwrap();

    assert_eq!(config.tls_trust_anchor_der(), Some("Y2VydGlmaWNhdGU="));
    assert_eq!(config.tls_trust_bundle(), Some("/tmp/agora-ca.pem"));
    assert!(config.child_environment().contains(&(
        "AGORA_SANDBOX_TLS_TRUST_ANCHOR_DER",
        "Y2VydGlmaWNhdGU=".to_string()
    )));
    for key in [
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "GIT_SSL_CAINFO",
    ] {
        assert!(
            config
                .child_environment()
                .contains(&(key, "/tmp/agora-ca.pem".to_string())),
            "missing {key}"
        );
    }
}

#[test]
fn process_context_uses_the_current_process_for_each_connection() {
    let context = ProcessContext::new("/tmp/client".to_string());

    let (parent_id, parent) = context.snapshot_for(101, 100);
    let (child_id, child) = context.snapshot_for(202, 101);

    assert_eq!(parent.pid, 101);
    assert_eq!(parent.ppid, 100);
    assert_eq!(child.pid, 202);
    assert_eq!(child.ppid, 101);
    assert_eq!(child.executable, "/tmp/client");
    assert_ne!(parent_id, child_id);
}

#[test]
fn hook_configuration_rejects_invalid_or_non_loopback_proxy_addresses() {
    let valid = HashMap::from([
        ("AGORA_SANDBOX_TOKEN", "token"),
        ("AGORA_SANDBOX_PROXY_IPV4", "127.0.0.1:41000"),
        ("AGORA_SANDBOX_PROXY_IPV6", "[::1]:41001"),
        ("AGORA_SANDBOX_EXECUTION_CONTROL", "127.0.0.1:41002"),
        ("AGORA_SANDBOX_EXECUTION_TOKEN", "execution-token"),
        ("AGORA_SANDBOX_HOOK_LIBRARIES", "/tmp/hook.dylib"),
        ("AGORA_SANDBOX_TRACE_IDS", "trace-root"),
    ]);
    let parse = |overrides: &[(&str, &str)]| {
        HookConfig::from_getter(|key| {
            overrides
                .iter()
                .find_map(|(name, value)| (*name == key).then(|| (*value).to_string()))
                .or_else(|| valid.get(key).map(ToString::to_string))
        })
    };

    assert!(
        parse(&[("AGORA_SANDBOX_TOKEN", "")])
            .unwrap_err()
            .contains("TOKEN")
    );
    assert!(
        parse(&[("AGORA_SANDBOX_PROXY_IPV4", "invalid")])
            .unwrap_err()
            .contains("invalid AGORA_SANDBOX_PROXY_IPV4")
    );
    assert!(
        parse(&[("AGORA_SANDBOX_PROXY_IPV6", "invalid")])
            .unwrap_err()
            .contains("invalid AGORA_SANDBOX_PROXY_IPV6")
    );
    assert!(
        parse(&[("AGORA_SANDBOX_PROXY_IPV4", "203.0.113.1:80")])
            .unwrap_err()
            .contains("IPv4 loopback")
    );
    assert!(
        parse(&[("AGORA_SANDBOX_PROXY_IPV4", "[::1]:80")])
            .unwrap_err()
            .contains("IPv4 loopback")
    );
    assert!(
        parse(&[("AGORA_SANDBOX_PROXY_IPV6", "[2001:db8::1]:80")])
            .unwrap_err()
            .contains("IPv6 loopback")
    );
    assert!(
        parse(&[("AGORA_SANDBOX_PROXY_IPV6", "127.0.0.1:80")])
            .unwrap_err()
            .contains("IPv6 loopback")
    );
    assert!(
        parse(&[("AGORA_SANDBOX_EXECUTION_CONTROL", "[::1]:80")])
            .unwrap_err()
            .contains("IPv4 loopback")
    );
}

#[test]
fn raw_socket_decoder_rejects_null_short_and_unknown_addresses() {
    assert_eq!(unsafe { socket_addr_from_raw(std::ptr::null(), 0) }, None);

    let mut unknown: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let address = std::ptr::addr_of_mut!(unknown).cast::<libc::sockaddr>();
    unsafe {
        (*address).sa_family = libc::AF_UNIX as libc::sa_family_t;
    }
    assert_eq!(unsafe { socket_addr_from_raw(address, 1) }, None);
    assert_eq!(
        unsafe {
            socket_addr_from_raw(
                address,
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            )
        },
        None
    );
}
