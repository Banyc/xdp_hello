#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiveTuple {
    pub protocol: L4Protocol,
    pub src: Address,
    pub dst: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddr {
    Ipv4(u32),
    Ipv6(u128),
}
