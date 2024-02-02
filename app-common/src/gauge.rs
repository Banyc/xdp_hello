const MAX_PORTS: u32 = 2_u32.pow(16);

type BpfPacketsPerPort = aya_bpf::maps::HashMap<u16, u64>;
#[aya_bpf::macros::map]
static PACKETS_PER_PORT: BpfPacketsPerPort = BpfPacketsPerPort::with_max_entries(MAX_PORTS, 0);
pub fn increment_packets(port: u16) -> Result<(), MapInsertionError> {
    let packets = unsafe { PACKETS_PER_PORT.get(&port) };
    let packets = match packets {
        Some(packets) => *packets,
        None => 0,
    };
    let packets = packets + 1;
    PACKETS_PER_PORT
        .insert(&port, &packets, 0)
        .map_err(|_| MapInsertionError)
}
pub struct MapInsertionError;

#[cfg(feature = "user")]
pub struct UserPacketsPerPort<'map> {
    map: aya::maps::HashMap<&'map mut aya::maps::MapData, u16, u64>,
}
#[cfg(feature = "user")]
impl<'map> UserPacketsPerPort<'map> {
    pub fn try_bind(bpf: &'map mut aya::Bpf) -> Option<Self> {
        let mut map = None;
        for (name, m) in bpf.maps_mut() {
            match name {
                "PACKETS_PER_PORT" => map = Some(m),
                _ => (),
            }
        }

        let map = aya::maps::HashMap::try_from(map?).ok()?;
        Some(Self { map })
    }

    pub fn packets(&self, port: u16) -> u64 {
        self.map.get(&port, 0).unwrap_or_default()
    }
}
