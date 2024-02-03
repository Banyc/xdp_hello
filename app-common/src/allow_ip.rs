use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

use crate::address::{FiveTuple, IpAddr};

const MAX_ENTRIES: u32 = 1024;

type BpfIpv4AllowIp = aya_bpf::maps::LruHashMap<u32, u32>;
#[aya_bpf::macros::map]
static IPV4_ALLOW_IP: BpfIpv4AllowIp = BpfIpv4AllowIp::with_max_entries(MAX_ENTRIES, 0);
pub fn ipv4_allowed(ip_hdr: &Ipv4Hdr) -> bool {
    let src_ip = u32::from_be(ip_hdr.src_addr);
    unsafe { IPV4_ALLOW_IP.get(&src_ip) }.is_some()
}

type BpfIpv6AllowIp = aya_bpf::maps::LruHashMap<u128, u32>;
#[aya_bpf::macros::map]
static IPV6_ALLOW_IP: BpfIpv6AllowIp = BpfIpv6AllowIp::with_max_entries(MAX_ENTRIES, 0);
pub fn ipv6_allowed(ip_hdr: &Ipv6Hdr) -> bool {
    let src_ip = u128::from_be_bytes(unsafe { ip_hdr.src_addr.in6_u.u6_addr8 });
    unsafe { IPV6_ALLOW_IP.get(&src_ip) }.is_some()
}

pub fn ip_allowed(tuple: &FiveTuple) -> bool {
    match tuple.src.ip {
        IpAddr::Ipv4(ip) => unsafe { IPV4_ALLOW_IP.get(&ip) }.is_some(),
        IpAddr::Ipv6(ip) => unsafe { IPV6_ALLOW_IP.get(&ip) }.is_some(),
    }
}

#[cfg(feature = "user")]
#[derive(Debug)]
/// Store the IPs of the legit application level users
///
/// So that when network access is restricted, the application is still available to them
pub struct UserAllowIp {
    /// Allowed IPs
    ipv4_map: aya::maps::HashMap<aya::maps::MapData, u32, u32>,
    /// Allowed IPs
    ipv6_map: aya::maps::HashMap<aya::maps::MapData, u128, u32>,
}
#[cfg(feature = "user")]
impl UserAllowIp {
    pub fn try_bind(bpf: &mut aya::Bpf) -> Option<Self> {
        let ipv4_map = bpf.take_map("IPV4_ALLOW_IP")?;
        let ipv6_map = bpf.take_map("IPV6_ALLOW_IP")?;

        let ipv4_map = aya::maps::HashMap::try_from(ipv4_map).ok()?;
        let ipv6_map = aya::maps::HashMap::try_from(ipv6_map).ok()?;
        Some(Self { ipv4_map, ipv6_map })
    }

    pub fn insert_allowed_ip(&mut self, ip: std::net::IpAddr) {
        match ip {
            std::net::IpAddr::V4(ip) => {
                let ip: u32 = ip.into();
                self.ipv4_map.insert(ip, 0, 0).unwrap();
            }
            std::net::IpAddr::V6(ip) => {
                let ip: u128 = ip.into();
                self.ipv6_map.insert(ip, 0, 0).unwrap();
            }
        }
    }

    pub fn remove_allowed_ip(&mut self, ip: std::net::IpAddr) {
        match ip {
            std::net::IpAddr::V4(ip) => {
                let ip: u32 = ip.into();
                let _ = self.ipv4_map.remove(&ip);
            }
            std::net::IpAddr::V6(ip) => {
                let ip: u128 = ip.into();
                let _ = self.ipv6_map.remove(&ip);
            }
        }
    }
}
