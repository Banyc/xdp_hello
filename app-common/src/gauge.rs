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
    let packets = packets.wrapping_add(1);
    PACKETS_PER_PORT
        .insert(&port, &packets, 0)
        .map_err(|_| MapInsertionError)
}
#[derive(Debug, Clone, Copy)]
pub struct MapInsertionError;

#[cfg(feature = "user")]
pub struct UserGauge {
    packets_per_port: aya::maps::HashMap<aya::maps::MapData, u16, u64>,
}
#[cfg(feature = "user")]
impl UserGauge {
    pub fn try_bind(bpf: &mut aya::Bpf) -> Option<Self> {
        let map = bpf.take_map("PACKETS_PER_PORT")?;

        let packets_per_port = aya::maps::HashMap::try_from(map).ok()?;
        Some(Self { packets_per_port })
    }

    pub fn packets(&self, port: u16) -> u64 {
        self.packets_per_port.get(&port, 0).unwrap_or_default()
    }
}
