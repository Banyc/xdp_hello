use aya_bpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{
    error::AbortMsg,
    mem::{ref_at, PointedOutOfRange},
};

pub fn main(ctx: &XdpContext) -> Result<u32, ParseError> {
    let ethhdr: &EthHdr = unsafe { ref_at(ctx, 0) }?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4_hdr: &Ipv4Hdr = unsafe { ref_at(ctx, EthHdr::LEN) }?;
    let src_ip = u32::from_be(ipv4_hdr.src_addr);
    let l4_protocol = ipv4_hdr.proto;

    let l4_hdr_offset = EthHdr::LEN + Ipv4Hdr::LEN;
    let src_port: u16 = match l4_protocol {
        IpProto::Tcp => {
            let tcp_hdr: &TcpHdr = unsafe { ref_at(ctx, l4_hdr_offset) }?;
            tcp_hdr.source
        }
        IpProto::Udp => {
            let udp_hdr: &UdpHdr = unsafe { ref_at(ctx, l4_hdr_offset) }?;
            udp_hdr.source
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    info!(ctx, "SRC IP: {:i}, SRC PORT: {}", src_ip, src_port);
    Ok(xdp_action::XDP_PASS)
}
#[derive(Debug)]
pub enum ParseError {
    Mem(PointedOutOfRange),
}
impl AbortMsg for ParseError {
    fn err_msg(&self) -> &'static str {
        match self {
            ParseError::Mem(_) => "pointed value out of range",
        }
    }
}
impl From<PointedOutOfRange> for ParseError {
    fn from(value: PointedOutOfRange) -> Self {
        Self::Mem(value)
    }
}
