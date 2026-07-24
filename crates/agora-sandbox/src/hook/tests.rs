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
