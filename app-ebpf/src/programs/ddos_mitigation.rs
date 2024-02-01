use app_common::allow_ip;
use aya_bpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::{
    error::AbortMsg,
    mem::{ref_at, PointedOutOfRange},
};

pub fn main(ctx: &XdpContext) -> Result<u32, ParseError> {
    // Parse port number from the packet
    let eth_hdr: &EthHdr = unsafe { ref_at(ctx, 0) }?;
    let (ip_hdr, port) = match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4_hdr: &Ipv4Hdr = unsafe { ref_at(ctx, EthHdr::LEN) }?;
            (IpHdr::Ipv4(ipv4_hdr), unsafe {
                port_from_ip_proto(ctx, ipv4_hdr.proto, Ipv4Hdr::LEN)
            }?)
        }
        EtherType::Ipv6 => {
            let ipv6_hdr: &Ipv6Hdr = unsafe { ref_at(ctx, EthHdr::LEN) }?;
            (IpHdr::Ipv6(ipv6_hdr), unsafe {
                port_from_ip_proto(ctx, ipv6_hdr.next_hdr, Ipv6Hdr::LEN)
            }?)
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };
    let Some(port) = port else {
        return Ok(xdp_action::XDP_PASS);
    };

    // Pass all traffic through unrestricted ports
    if !allow_ip::port_restricted(port) {
        return Ok(xdp_action::XDP_PASS);
    }

    info!(ctx, "ENTERED RESTRICTED PORT: {}", port);

    // Only allow trusted source IPs
    let allowed = match ip_hdr {
        IpHdr::Ipv4(ip) => allow_ip::ipv4_allowed(ip),
        IpHdr::Ipv6(ip) => allow_ip::ipv6_allowed(ip),
    };
    let action = match allowed {
        true => xdp_action::XDP_PASS,
        false => xdp_action::XDP_DROP,
    };
    Ok(action)
}

enum IpHdr<'a> {
    Ipv4(&'a Ipv4Hdr),
    Ipv6(&'a Ipv6Hdr),
}

/// # Safety
///
/// Make sure:
/// - `ctx` is an Ethernet packet
/// - `l4_proto` is extracted from the right position in `ctx`
/// - `ip_hdr_len` is the length of the IP header in `ctx`
unsafe fn port_from_ip_proto(
    ctx: &XdpContext,
    l4_proto: IpProto,
    ip_hdr_len: usize,
) -> Result<Option<u16>, PointedOutOfRange> {
    let be_port = match l4_proto {
        IpProto::Tcp => {
            let tcp_hdr: &TcpHdr = unsafe { ref_at(ctx, EthHdr::LEN + ip_hdr_len)? };
            tcp_hdr.dest
        }
        IpProto::Udp => {
            let udp_hdr: &UdpHdr = unsafe { ref_at(ctx, EthHdr::LEN + ip_hdr_len)? };
            udp_hdr.dest
        }
        _ => return Ok(None),
    };
    Ok(Some(u16::from_be(be_port)))
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
