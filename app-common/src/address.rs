#[derive(Clone, Copy)]
pub struct FiveTuple {
    pub protocol: L4Protocol,
    pub src: Address,
    pub dst: Address,
}

#[derive(Clone, Copy)]
pub enum L4Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy)]
pub struct Address {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Clone, Copy)]
pub enum IpAddr {
    Ipv4(u32),
    Ipv6(u128),
}
