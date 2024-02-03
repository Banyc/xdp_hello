use network_types::ip::Ipv4Hdr;

type BpfBlockIp = aya_bpf::maps::HashMap<u32, u32>;
#[aya_bpf::macros::map]
static BLOCK_IP: BpfBlockIp = BpfBlockIp::with_max_entries(1024, 0);
pub fn blocked(ip_hdr: &Ipv4Hdr) -> bool {
    let src_ip = u32::from_be(ip_hdr.src_addr);
    unsafe { BLOCK_IP.get(&src_ip) }.is_some()
}

#[cfg(feature = "user")]
pub struct UserBlockIp<'map> {
    map: aya::maps::HashMap<&'map mut aya::maps::MapData, u32, u32>,
}
#[cfg(feature = "user")]
impl<'map> UserBlockIp<'map> {
    const MAP_NAME: &'static str = "BLOCK_IP";

    pub fn try_bind(bpf: &'map mut aya::Bpf) -> Option<Self> {
        let map = aya::maps::HashMap::try_from(bpf.map_mut(Self::MAP_NAME).unwrap()).ok()?;
        Some(Self { map })
    }

    pub fn insert(&mut self, ip: std::net::Ipv4Addr) {
        let ip: u32 = ip.into();
        self.map.insert(ip, 0, 0).unwrap();
    }
}
