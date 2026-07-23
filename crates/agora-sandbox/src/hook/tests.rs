use super::config::HookConfig;
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
        ("AGORA_SANDBOX_ID", "sandbox-1"),
        ("AGORA_SANDBOX_RUN_ID", "run-1"),
        ("AGORA_SANDBOX_PROXY_IPV4", "127.0.0.1:41000"),
        ("AGORA_SANDBOX_PROXY_IPV6", "[::1]:41001"),
        ("AGORA_SANDBOX_FAIL_OPEN", "1"),
    ]);
    let config = HookConfig::from_getter(|key| values.get(key).map(ToString::to_string)).unwrap();

    assert_eq!(
        config.proxy_for(SocketAddr::from(([203, 0, 113, 10], 443))),
        SocketAddr::from(([127, 0, 0, 1], 41000))
    );
    assert_eq!(
        config.proxy_for(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443))),
        "[::1]:41001".parse().unwrap()
    );
    assert!(config.fail_open());
    assert!(config.is_proxy("127.0.0.1:41000".parse().unwrap()));
    assert!(config.is_proxy("[::1]:41001".parse().unwrap()));

    let error = HookConfig::from_getter(|key| {
        (key != "AGORA_SANDBOX_TOKEN")
            .then(|| values.get(key).map(ToString::to_string))
            .flatten()
    })
    .unwrap_err();
    assert!(error.contains("AGORA_SANDBOX_TOKEN"));
}
