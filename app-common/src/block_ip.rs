pub type BpfBlockIp = aya_bpf::maps::HashMap<u32, u32>;
#[aya_bpf::macros::map]
pub static BLOCK_IP: BpfBlockIp = BpfBlockIp::with_max_entries(1024, 0);
pub fn blocked(ip: u32) -> bool {
    unsafe { BLOCK_IP.get(&ip) }.is_some()
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

    pub fn insert(&mut self, ip: u32) {
        self.map.insert(ip, 0, 0).unwrap();
    }
}
