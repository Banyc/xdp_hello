const MAX_ENTRIES: u32 = 1024;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[allow(dead_code)]
pub struct AsciiIp {
    /// 45: max length of a textual IP address
    bytes: [u8; 45],
}
impl AsciiIp {
    pub fn from_ascii(b: &[u8]) -> Result<Self, NotAnAsciiIp> {
        if b.len() > 45 {
            return Err(NotAnAsciiIp);
        }
        let mut bytes = [0; 45];
        bytes[..b.len()].copy_from_slice(b);
        Ok(Self { bytes })
    }
}
#[derive(Debug, Clone, Copy)]
pub struct NotAnAsciiIp;
#[cfg(feature = "user")]
unsafe impl aya::Pod for AsciiIp {}

type BpfAllowAsciiIp = aya_bpf::maps::LruHashMap<AsciiIp, u32>;
#[aya_bpf::macros::map]
static ALLOW_ASCII_IP: BpfAllowAsciiIp = BpfAllowAsciiIp::with_max_entries(MAX_ENTRIES, 0);
pub fn ascii_ip_allowed(ip: &AsciiIp) -> bool {
    unsafe { ALLOW_ASCII_IP.get(&ip) }.is_some()
}

#[cfg(feature = "user")]
#[derive(Debug)]
/// Store the IPs of the legit application level users
///
/// So that when network access is restricted, the application is still available to them
pub struct UserAllowAsciiIp {
    /// Allowed IPs
    map: aya::maps::HashMap<aya::maps::MapData, AsciiIp, u32>,
}
#[cfg(feature = "user")]
impl UserAllowAsciiIp {
    pub fn try_bind(bpf: &mut aya::Bpf) -> Option<Self> {
        let map = bpf.take_map("ALLOW_ASCII_IP")?;

        let map = aya::maps::HashMap::try_from(map).ok()?;
        Some(Self { map })
    }

    pub fn insert_allowed_ip(&mut self, ip: std::net::IpAddr) {
        let s = ip.to_string();
        let ip = AsciiIp::from_ascii(s.as_bytes()).unwrap();
        self.map.insert(ip, 0, 0).unwrap();
    }

    pub fn remove_allowed_ip(&mut self, ip: std::net::IpAddr) {
        let s = ip.to_string();
        let ip = AsciiIp::from_ascii(s.as_bytes()).unwrap();
        let _ = self.map.remove(&ip);
    }
}
