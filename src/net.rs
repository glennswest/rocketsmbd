//! Network interface enumeration for SMB3 multichannel
//! (FSCTL_QUERY_NETWORK_INTERFACE_INFO). The client uses the reported
//! interfaces — their link speed and RSS capability — to decide how many
//! channels (parallel connections) to open to the server.

use std::net::IpAddr;

pub const IF_CAP_RSS: u32 = 0x0000_0001;
#[allow(dead_code)]
pub const IF_CAP_RDMA: u32 = 0x0000_0002;

#[derive(Debug, Clone)]
pub struct Iface {
    pub index: u32,
    pub addr: IpAddr,
    /// Link speed in bits per second.
    pub speed: u64,
    pub capability: u32,
    /// Retained for diagnostics / future "don't advertise loopback" policy.
    #[allow(dead_code)]
    pub loopback: bool,
}

/// Read /sys/class/net/<name>/speed (Mbps) → bits/sec. Falls back to a high
/// value so virtual/loopback interfaces still advertise as fast (multichannel
/// is desirable on them for local/striped testing).
fn link_speed_bps(name: &str, loopback: bool) -> u64 {
    let path = format!("/sys/class/net/{name}/speed");
    if let Ok(s) = std::fs::read_to_string(&path) {
        if let Ok(mbps) = s.trim().parse::<i64>() {
            if mbps > 0 {
                return mbps as u64 * 1_000_000;
            }
        }
    }
    // Loopback and feature-less virtual NICs: advertise 100 Gbps so clients
    // are willing to open multiple channels.
    if loopback {
        100_000_000_000
    } else {
        10_000_000_000
    }
}

/// Enumerate usable interfaces. Includes loopback so single-host multichannel
/// testing works; real deployments will pick the routable address.
pub fn interfaces() -> Vec<Iface> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let loopback = ifa.ifa_flags as i32 & libc::IFF_LOOPBACK != 0;
        let up = ifa.ifa_flags as i32 & libc::IFF_UP != 0;
        if !up {
            continue;
        }
        let addr = match family {
            libc::AF_INET => {
                let sa = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
            }
            libc::AF_INET6 => {
                let sa = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                IpAddr::V6(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        let index = unsafe { libc::if_nametoindex(ifa.ifa_name) };
        out.push(Iface {
            index,
            addr,
            speed: link_speed_bps(&name, loopback),
            capability: IF_CAP_RSS,
            loopback,
        });
    }
    unsafe { libc::freeifaddrs(ifap) };
    out
}

/// Encode the interface list as a chain of NETWORK_INTERFACE_INFO structures
/// (MS-SMB2 2.2.32.5) for the FSCTL_QUERY_NETWORK_INTERFACE_INFO reply.
pub fn encode_interface_info(ifaces: &[Iface]) -> Vec<u8> {
    use crate::wire::Put;
    let mut out = Vec::new();
    let mut entry_offsets = Vec::with_capacity(ifaces.len());
    for ifc in ifaces {
        let start = out.len();
        entry_offsets.push(start);
        out.p32(0); // Next, patched below
        out.p32(ifc.index);
        out.p32(ifc.capability);
        out.p32(0); // Reserved
        out.p64(ifc.speed);
        // SOCKADDR_STORAGE (128 bytes): family + address.
        let sa_start = out.len();
        match ifc.addr {
            IpAddr::V4(v4) => {
                out.p16(2); // AF_INET (Windows value, also Linux)
                out.p16(0); // port
                out.pbytes(&v4.octets());
                out.zeros(8); // sin_zero
            }
            IpAddr::V6(v6) => {
                out.p16(23); // AF_INET6 (Windows value)
                out.p16(0); // port
                out.p32(0); // flowinfo
                out.pbytes(&v6.octets());
                out.p32(0); // scope id
            }
        }
        // Pad SOCKADDR_STORAGE out to 128 bytes.
        let pad = 128 - (out.len() - sa_start);
        out.zeros(pad);
    }
    // Patch Next offsets (last stays 0).
    for w in entry_offsets.windows(2) {
        let next = (w[1] - w[0]) as u32;
        out[w[0]..w[0] + 4].copy_from_slice(&next.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_shape() {
        let ifaces = vec![
            Iface {
                index: 1,
                addr: "127.0.0.1".parse().unwrap(),
                speed: 100_000_000_000,
                capability: IF_CAP_RSS,
                loopback: true,
            },
            Iface {
                index: 2,
                addr: "10.0.0.5".parse().unwrap(),
                speed: 25_000_000_000,
                capability: IF_CAP_RSS,
                loopback: false,
            },
        ];
        let b = encode_interface_info(&ifaces);
        // Each entry is 24 bytes header + 128 SOCKADDR_STORAGE = 152.
        assert_eq!(b.len(), 152 * 2);
        // First Next points to the second entry.
        assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), 152);
        // Last Next is zero.
        assert_eq!(u32::from_le_bytes(b[152..156].try_into().unwrap()), 0);
        // First IfIndex.
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 1);
        // LinkSpeed at offset 16 (after Next/IfIndex/Capability/Reserved).
        assert_eq!(u64::from_le_bytes(b[16..24].try_into().unwrap()), 100_000_000_000);
    }

    #[test]
    fn enumerate_has_loopback() {
        let ifs = interfaces();
        assert!(ifs.iter().any(|i| i.loopback), "should find loopback");
    }
}
