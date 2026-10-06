//! Milestone 74 & 75 (Option AE): Multi-Homed Network Interface & Source IP Binding.
//!
//! Validates:
//! - Pure-Rust network interface discovery and enumeration (`list_interfaces`, `find_interface`).
//! - Address resolution logic for explicit source IPs, interface names, and ports (`resolve_bind_addr`).
//! - Destination address family matching (IPv4 vs IPv6).
//! - Client endpoint socket binding to specified local source address and inspection of `local_addr`.

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use velcrux_core::transport::interface::{
    find_interface, list_interfaces, parse_ifconfig_output, parse_ip_command_output,
    resolve_bind_addr,
};
use velcrux_core::transport::quic::ClientBuilder;

#[test]
fn test_list_interfaces_and_find() {
    let ifaces = list_interfaces();
    assert!(
        !ifaces.is_empty(),
        "must discover at least one network interface"
    );

    let first = &ifaces[0];
    let found = find_interface(&first.name);
    assert!(found.is_some(), "must find interface by exact name");
    assert_eq!(found.unwrap().name, first.name);

    let found_case = find_interface(&first.name.to_uppercase());
    assert!(
        found_case.is_some(),
        "must find interface case-insensitively"
    );

    let missing = find_interface("definitely_nonexistent_interface_9999");
    assert!(missing.is_none());
}

#[test]
fn test_resolve_bind_addr_explicit_ip() {
    // IPv4 with port
    let addr = resolve_bind_addr(Some("127.0.0.1"), None, 8080, None).expect("valid ipv4");
    assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());

    // IPv6 with port
    let addr_v6 = resolve_bind_addr(Some("::1"), None, 9090, None).expect("valid ipv6");
    assert_eq!(addr_v6, "[::1]:9090".parse().unwrap());

    // Full socket address provided in bind_ip overrides port
    let addr_sock =
        resolve_bind_addr(Some("10.0.0.1:5555"), None, 9999, None).expect("valid socket addr");
    assert_eq!(addr_sock, "10.0.0.1:5555".parse().unwrap());

    // Invalid IP format fails
    let err = resolve_bind_addr(Some("invalid.ip.str"), None, 8080, None);
    assert!(err.is_err());
}

#[test]
fn test_resolve_bind_addr_by_interface() {
    let ifaces = list_interfaces();
    assert!(!ifaces.is_empty());
    let iface = ifaces
        .iter()
        .find(|i| !i.ips.is_empty())
        .expect("system must have at least one interface with an assigned IP");

    let resolved =
        resolve_bind_addr(None, Some(&iface.name), 7777, None).expect("resolves known interface");
    assert_eq!(resolved.port(), 7777);
    assert!(
        iface.ips.contains(&resolved.ip()),
        "resolved IP {} must belong to interface {:?}",
        resolved.ip(),
        iface.ips
    );

    // If there is any interface without an assigned IP, resolving it must error
    if let Some(empty_iface) = ifaces.iter().find(|i| i.ips.is_empty()) {
        let err = resolve_bind_addr(None, Some(&empty_iface.name), 7777, None);
        assert!(err.is_err());
    }

    // Non-existent interface fails
    let err = resolve_bind_addr(None, Some("fake_iface_xyz"), 7777, None);
    assert!(err.is_err());
}

#[test]
fn test_resolve_bind_addr_family_matching() {
    let target_v4: SocketAddr = "192.168.1.1:7443".parse().unwrap();
    let target_v6: SocketAddr = "[2001:db8::1]:7443".parse().unwrap();

    // Default with no bind options: IPv4 target yields 0.0.0.0
    let v4 = resolve_bind_addr(None, None, 1234, Some(target_v4)).expect("default v4");
    assert_eq!(v4, "0.0.0.0:1234".parse().unwrap());

    // Default with no bind options: IPv6 target yields [::]
    let v6 = resolve_bind_addr(None, None, 1234, Some(target_v6)).expect("default v6");
    assert_eq!(v6, "[::]:1234".parse().unwrap());

    // Interface with both IPv4 and IPv6 selects matching family
    let iface_multi = velcrux_core::transport::InterfaceInfo::new(
        "test0",
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ],
        true,
        false,
    );

    let ip_v4 = iface_multi.matching_ip_for_target(Some(target_v4));
    assert_eq!(ip_v4, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

    let ip_v6 = iface_multi.matching_ip_for_target(Some(target_v6));
    assert_eq!(
        ip_v6,
        Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
    );
}

#[test]
fn test_parser_linux_ip_command_output() {
    let output = r#"
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe4e:66a1/64 scope link \       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    inet 10.10.0.5/16 scope global eth1
"#;
    let ifaces = parse_ip_command_output(output);
    assert_eq!(ifaces.len(), 3);

    let lo = ifaces.iter().find(|i| i.name == "lo").unwrap();
    assert!(lo.ips.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(lo.ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));

    let eth0 = ifaces.iter().find(|i| i.name == "eth0").unwrap();
    assert!(eth0
        .ips
        .contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));

    let eth1 = ifaces.iter().find(|i| i.name == "eth1").unwrap();
    assert!(eth1.ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 10, 0, 5))));
}

#[test]
fn test_parser_ifconfig_output() {
    let output = r#"
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000 
	inet6 ::1 prefixlen 128 
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1 
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	ether ac:de:48:00:11:22 
	inet 192.168.0.105 netmask 0xffffff00 broadcast 192.168.0.255
	inet6 2601:647:4e00::1 prefixlen 64 
"#;
    let ifaces = parse_ifconfig_output(output);
    assert!(ifaces.len() >= 2);

    let lo0 = ifaces.iter().find(|i| i.name == "lo0").unwrap();
    assert!(lo0.ips.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(lo0.ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));

    let en0 = ifaces.iter().find(|i| i.name == "en0").unwrap();
    assert!(en0
        .ips
        .contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 105))));
}

#[tokio::test]
async fn test_quic_client_custom_bind_addr() {
    let bind_target: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let builder = ClientBuilder::new().with_bind_addr(bind_target);
    let transport = builder.build().expect("build client transport");

    let local = transport.local_addr().expect("inspect bound local address");
    assert_eq!(local.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert!(local.port() > 0, "ephemeral port must be assigned");
}
