//! Multi-homed network interface discovery and source IP binding (`REQUIREMENTS.md` §74, §75).
//!
//! Provides pure-Rust, safe network interface enumeration, address resolution,
//! and address-family matching for dedicated data-plane NIC segmentation.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use crate::error::VelcruxError;

/// Details of a local network interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    /// Interface name (e.g. "eth0", "ens3f0", "en0", "lo").
    pub name: String,
    /// IP addresses assigned to this interface.
    pub ips: Vec<IpAddr>,
    /// Whether the interface is administratively UP and running.
    pub is_up: bool,
    /// Whether this is a loopback interface.
    pub is_loopback: bool,
}

impl InterfaceInfo {
    /// Create a new interface descriptor.
    pub fn new(name: impl Into<String>, ips: Vec<IpAddr>, is_up: bool, is_loopback: bool) -> Self {
        Self {
            name: name.into(),
            ips,
            is_up,
            is_loopback,
        }
    }

    /// Find the first IPv4 address assigned to this interface.
    pub fn first_ipv4(&self) -> Option<Ipv4Addr> {
        self.ips.iter().find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
    }

    /// Find the first non-link-local IPv6 address, or any IPv6 address.
    pub fn first_ipv6(&self) -> Option<Ipv6Addr> {
        self.ips
            .iter()
            .find_map(|ip| match ip {
                IpAddr::V6(v6) => {
                    // Prefer non-link-local (fe80::/10)
                    let segments = v6.segments();
                    if (segments[0] & 0xffc0) != 0xfe80 {
                        Some(*v6)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .or_else(|| {
                self.ips.iter().find_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(*v6),
                    _ => None,
                })
            })
    }

    /// Find an IP address matching the address family of the given target address.
    pub fn matching_ip_for_target(&self, target: Option<SocketAddr>) -> Option<IpAddr> {
        match target {
            Some(SocketAddr::V6(_)) => self
                .first_ipv6()
                .map(IpAddr::V6)
                .or_else(|| self.first_ipv4().map(IpAddr::V4)),
            Some(SocketAddr::V4(_)) => self
                .first_ipv4()
                .map(IpAddr::V4)
                .or_else(|| self.first_ipv6().map(IpAddr::V6)),
            None => {
                // Default: prefer IPv4, fallback to IPv6
                self.first_ipv4()
                    .map(IpAddr::V4)
                    .or_else(|| self.first_ipv6().map(IpAddr::V6))
            }
        }
    }
}

/// Parse Linux `/proc/net/if_inet6` lines into interface names and IPv6 addresses.
pub fn parse_linux_proc_if_inet6(content: &str) -> Vec<(String, Ipv6Addr)> {
    let mut results = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            let hex_str = parts[0];
            let if_name = parts[parts.len() - 1];
            if hex_str.len() == 32 {
                let mut bytes = [0u8; 16];
                let mut valid = true;
                for i in 0..16 {
                    if let Ok(byte) = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16) {
                        bytes[i] = byte;
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid {
                    results.push((if_name.to_string(), Ipv6Addr::from(bytes)));
                }
            }
        }
    }
    results
}

/// Parse Linux `ip -o addr show` or `ip addr show` output into [`InterfaceInfo`] entries.
pub fn parse_ip_command_output(output: &str) -> Vec<InterfaceInfo> {
    let mut ifaces: std::collections::BTreeMap<String, (Vec<IpAddr>, bool, bool)> =
        std::collections::BTreeMap::new();
    let mut current_iface: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();

        // 1. Check for oneline format: "1: lo inet 127.0.0.1/8 ..." or "2: eth0 inet6 ::1/128 ..."
        if parts.len() >= 4 && (parts[2] == "inet" || parts[2] == "inet6") {
            let name = parts[1].trim_end_matches(':').to_string();
            let proto = parts[2];
            let cidr = parts[3];
            let ip_str = cidr.split('/').next().unwrap_or(cidr);
            let parsed_ip = match proto {
                "inet" => ip_str.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
                "inet6" => ip_str.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
                _ => None,
            };
            let entry = ifaces.entry(name.clone()).or_insert_with(|| {
                let is_lo = name == "lo" || name.starts_with("loop");
                (Vec::new(), true, is_lo)
            });
            if let Some(ip) = parsed_ip {
                if !entry.0.contains(&ip) {
                    entry.0.push(ip);
                }
            }
            continue;
        }

        // 2. Check for multiline header: "1: lo: <LOOPBACK,UP...> mtu 65536 ..."
        if let Some(first) = parts.first() {
            if first.ends_with(':')
                && first
                    .trim_end_matches(':')
                    .chars()
                    .all(|c| c.is_ascii_digit())
            {
                if let Some(second) = parts.get(1) {
                    let name = second.trim_end_matches(':').to_string();
                    let is_up = line.contains("UP");
                    let is_lo = name == "lo" || name.starts_with("loop");
                    ifaces
                        .entry(name.clone())
                        .or_insert((Vec::new(), is_up, is_lo));
                    current_iface = Some(name);
                    continue;
                }
            }
        }

        // 3. Check for multiline inet/inet6 line: "inet 127.0.0.1/8 ..."
        if (parts[0] == "inet" || parts[0] == "inet6") && parts.len() >= 2 {
            if let Some(ref ifname) = current_iface {
                let proto = parts[0];
                let cidr = parts[1];
                let ip_str = cidr.split('/').next().unwrap_or(cidr);
                let parsed_ip = match proto {
                    "inet" => ip_str.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
                    "inet6" => ip_str.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
                    _ => None,
                };
                if let Some(ip) = parsed_ip {
                    let entry = ifaces.entry(ifname.clone()).or_insert_with(|| {
                        let is_lo = ifname == "lo" || ifname.starts_with("loop");
                        (Vec::new(), true, is_lo)
                    });
                    if !entry.0.contains(&ip) {
                        entry.0.push(ip);
                    }
                }
            }
        }
    }

    ifaces
        .into_iter()
        .map(|(name, (ips, is_up, is_loopback))| InterfaceInfo::new(name, ips, is_up, is_loopback))
        .collect()
}

/// Parse macOS / BSD `ifconfig` output into [`InterfaceInfo`] entries.
pub fn parse_ifconfig_output(output: &str) -> Vec<InterfaceInfo> {
    let mut ifaces = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_ips: Vec<IpAddr> = Vec::new();
    let mut current_up = false;
    let mut current_lo = false;

    for line in output.lines() {
        if line.starts_with('\t') || line.starts_with("    ") {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("inet ") {
                if let Some(ip_str) = rest.split_whitespace().next() {
                    if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
                        current_ips.push(IpAddr::V4(v4));
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
                if let Some(ip_str) = rest.split_whitespace().next() {
                    let cleaned = ip_str.split('%').next().unwrap_or(ip_str);
                    if let Ok(v6) = cleaned.parse::<Ipv6Addr>() {
                        current_ips.push(IpAddr::V6(v6));
                    }
                }
            }
        } else if let Some((name_part, flags_part)) = line.split_once(':') {
            // Save previous interface
            if let Some(name) = current_name.take() {
                ifaces.push(InterfaceInfo::new(
                    name,
                    current_ips,
                    current_up,
                    current_lo,
                ));
                current_ips = Vec::new();
            }

            let name = name_part.trim().to_string();
            current_lo = name == "lo0" || name == "lo" || name.starts_with("loop");
            current_up = flags_part.contains("UP");
            current_name = Some(name);
        }
    }

    if let Some(name) = current_name {
        ifaces.push(InterfaceInfo::new(
            name,
            current_ips,
            current_up,
            current_lo,
        ));
    }

    ifaces
}

/// Discover all local network interfaces on the host system without unsafe code.
pub fn list_interfaces() -> Vec<InterfaceInfo> {
    // 1. Try `ip -o addr show` (Linux)
    if let Ok(out) = std::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
    {
        if out.status.success() {
            let str_out = String::from_utf8_lossy(&out.stdout);
            let mut parsed = parse_ip_command_output(&str_out);
            if !parsed.is_empty() {
                ensure_loopback_ips(&mut parsed);
                return parsed;
            }
        }
    }

    // 2. Try `ifconfig` (macOS / BSD / legacy Linux)
    if let Ok(out) = std::process::Command::new("ifconfig").output() {
        if out.status.success() {
            let str_out = String::from_utf8_lossy(&out.stdout);
            let mut parsed = parse_ifconfig_output(&str_out);
            if !parsed.is_empty() {
                ensure_loopback_ips(&mut parsed);
                return parsed;
            }
        }
    }

    // 3. Fallback: Linux /sys/class/net and /proc/net/if_inet6
    if Path::new("/sys/class/net").exists() {
        if let Ok(read_dir) = std::fs::read_dir("/sys/class/net") {
            let mut ifaces = Vec::new();
            let proc_inet6 = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
            let v6_map = parse_linux_proc_if_inet6(&proc_inet6);

            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let operstate =
                    std::fs::read_to_string(entry.path().join("operstate")).unwrap_or_default();
                let is_up = operstate.trim() != "down";
                let is_loopback = name == "lo" || name.starts_with("loop");

                let mut ips = Vec::new();
                for (if_name, v6) in &v6_map {
                    if if_name == &name {
                        ips.push(IpAddr::V6(*v6));
                    }
                }

                if is_loopback {
                    if !ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)) {
                        ips.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
                    }
                    if !ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)) {
                        ips.push(IpAddr::V6(Ipv6Addr::LOCALHOST));
                    }
                }

                ifaces.push(InterfaceInfo::new(name, ips, is_up, is_loopback));
            }

            if !ifaces.is_empty() {
                ensure_loopback_ips(&mut ifaces);
                return ifaces;
            }
        }
    }

    // 4. Fallback: standard loopback
    vec![InterfaceInfo::new(
        "lo",
        vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
        true,
        true,
    )]
}

fn ensure_loopback_ips(ifaces: &mut Vec<InterfaceInfo>) {
    let mut has_lo = false;
    for iface in ifaces.iter_mut() {
        if iface.is_loopback {
            has_lo = true;
            if !iface.ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)) {
                iface.ips.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
            if !iface.ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)) {
                iface.ips.push(IpAddr::V6(Ipv6Addr::LOCALHOST));
            }
        }
    }
    if !has_lo {
        ifaces.push(InterfaceInfo::new(
            "lo",
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
            true,
            true,
        ));
    }
}

/// Find a specific interface by name.
pub fn find_interface(name: &str) -> Option<InterfaceInfo> {
    list_interfaces()
        .into_iter()
        .find(|i| i.name.eq_ignore_ascii_case(name))
}

/// Resolve the local source `SocketAddr` from `--bind-ip` or `--bind-interface` and port.
pub fn resolve_bind_addr(
    bind_ip: Option<&str>,
    bind_interface: Option<&str>,
    bind_port: u16,
    target_addr: Option<SocketAddr>,
) -> Result<SocketAddr, VelcruxError> {
    // 1. Explicit bind IP given
    if let Some(ip_str) = bind_ip {
        let trimmed = ip_str.trim();
        // Check if full socket address was supplied
        if let Ok(sock) = trimmed.parse::<SocketAddr>() {
            return Ok(sock);
        }
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, bind_port));
        }
        return Err(VelcruxError::Config(format!(
            "invalid --bind-ip address '{}': expected valid IPv4 or IPv6 address",
            ip_str
        )));
    }

    // 2. Specific interface name given
    if let Some(if_name) = bind_interface {
        let iface = find_interface(if_name).ok_or_else(|| {
            VelcruxError::Config(format!(
                "network interface '{}' not found on system (available: {})",
                if_name,
                list_interfaces()
                    .iter()
                    .map(|i| i.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;

        let ip = iface.matching_ip_for_target(target_addr).ok_or_else(|| {
            VelcruxError::Config(format!(
                "network interface '{}' has no compatible IP address for target {:?}",
                if_name, target_addr
            ))
        })?;

        return Ok(SocketAddr::new(ip, bind_port));
    }

    // 3. Neither specified: bind to wildcard matching target address family
    match target_addr {
        Some(SocketAddr::V6(_)) => Ok(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            bind_port,
        )),
        _ => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bind_port,
        )),
    }
}
