const MAX_PORTS: u32 = 2_u32.pow(16);

type BpfRestrictedPort = aya_bpf::maps::HashMap<u16, u32>;
#[aya_bpf::macros::map]
static RESTRICTED_PORT: BpfRestrictedPort = BpfRestrictedPort::with_max_entries(MAX_PORTS, 0);
pub fn port_restricted(port: u16) -> bool {
    unsafe { RESTRICTED_PORT.get(&port) }.is_some()
}

#[cfg(feature = "user")]
#[derive(Debug)]
/// To tell BPF programs which port is being restricted
pub struct UserRestrictedPort {
    /// Restriction identifying local ports
    port_map: aya::maps::HashMap<aya::maps::MapData, u16, u32>,
}
#[cfg(feature = "user")]
impl UserRestrictedPort {
    pub fn try_bind(bpf: &mut aya::Bpf) -> Option<Self> {
        let port_map = bpf.take_map("RESTRICTED_PORT")?;

        let port_map = aya::maps::HashMap::try_from(port_map).ok()?;
        Some(Self { port_map })
    }

    pub fn insert_restricted_port(&mut self, port: u16) {
        self.port_map.insert(port, 0, 0).unwrap();
    }

    pub fn remove_restricted_port(&mut self, port: u16) {
        let _ = self.port_map.remove(&port);
    }

    pub fn restricted_ports(&self) -> Vec<u16> {
        self.port_map.keys().collect::<Result<_, _>>().unwrap()
    }
}
