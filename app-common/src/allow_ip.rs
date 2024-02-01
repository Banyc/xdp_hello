use network_types::ip::{Ipv4Hdr, Ipv6Hdr};

const MAX_ENTRIES: u32 = 1024;

type BpfRestrictedPort = aya_bpf::maps::HashMap<u16, u32>;
#[aya_bpf::macros::map]
static RESTRICTED_PORT: BpfRestrictedPort = BpfRestrictedPort::with_max_entries(MAX_ENTRIES, 0);
pub fn port_restricted(port: u16) -> bool {
    unsafe { RESTRICTED_PORT.get(&port) }.is_some()
}

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

#[cfg(feature = "user")]
/// Store the IPs of the legit application level users
///
/// So that when network access is restricted, the application is still available to them
///
/// Restriction is identified by an ingress port
pub struct UserAllowIp<'map> {
    /// Allowed IPs
    ipv4_map: aya::maps::HashMap<&'map mut aya::maps::MapData, u32, u32>,
    /// Allowed IPs
    ipv6_map: aya::maps::HashMap<&'map mut aya::maps::MapData, u128, u32>,
    /// Restriction identifying local ports
    port_map: aya::maps::HashMap<&'map mut aya::maps::MapData, u16, u32>,
}
#[cfg(feature = "user")]
impl<'map> UserAllowIp<'map> {
    pub fn try_bind(bpf: &'map mut aya::Bpf) -> Option<Self> {
        let mut ipv4_map = None;
        let mut ipv6_map = None;
        let mut port_map = None;
        for (name, map) in bpf.maps_mut() {
            match name {
                "IPV4_ALLOW_IP" => ipv4_map = Some(map),
                "IPV6_ALLOW_IP" => ipv6_map = Some(map),
                "RESTRICTED_PORT" => port_map = Some(map),
                _ => (),
            }
        }

        let ipv4_map = aya::maps::HashMap::try_from(ipv4_map?).ok()?;
        let ipv6_map = aya::maps::HashMap::try_from(ipv6_map?).ok()?;
        let port_map = aya::maps::HashMap::try_from(port_map?).ok()?;
        Some(Self {
            ipv4_map,
            ipv6_map,
            port_map,
        })
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

    pub fn insert_restricted_port(&mut self, port: u16) {
        self.port_map.insert(port, 0, 0).unwrap();
    }

    pub fn remove_restricted_port(&mut self, port: u16) {
        self.port_map.remove(&port).unwrap();
    }

    pub fn restricted_ports(&self) -> Vec<u16> {
        self.port_map.keys().collect::<Result<_, _>>().unwrap()
    }
}
