use core::slice;

use app_common::{
    address::{IpAddr, L4Protocol},
    allow_ascii_ip::{ascii_ip_allowed, AsciiIp, NotAnAsciiIp},
    gauge::{increment_packets, MapInsertionError},
    restricted_port,
};
use aya_bpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
};

use crate::{
    address::five_tuple,
    error::AbortMsg,
    mem::{find, PointedOutOfRange},
};

pub fn main(ctx: &XdpContext) -> Result<u32, ParseError> {
    // Parse port number from the packet
    let Some(tuple) = five_tuple(ctx)? else {
        return Ok(xdp_action::XDP_PASS);
    };

    // Gauge the throughput per port
    increment_packets(tuple.dst.port)?;

    // Pass all traffic through unrestricted ports
    if !restricted_port::port_restricted(tuple.dst.port) {
        return Ok(xdp_action::XDP_PASS);
    }

    // Crop out the header value that contains the IP string
    if matches!(tuple.protocol, L4Protocol::Udp) {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip_hdr_len = match tuple.src.ip {
        IpAddr::Ipv4(_) => Ipv4Hdr::LEN,
        IpAddr::Ipv6(_) => Ipv6Hdr::LEN,
    };
    let tcp_data_start = EthHdr::LEN + ip_hdr_len + TcpHdr::LEN;

    const SRC_IP_HEADER_KEY: &str = "CF-Connecting-IP: ";
    let Some(key_start) = find(ctx, tcp_data_start, SRC_IP_HEADER_KEY.as_bytes()) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let ip_start = key_start + SRC_IP_HEADER_KEY.len();
    let Some(ip_end) = find(ctx, ip_start, b"\n") else {
        return Ok(xdp_action::XDP_PASS);
    };

    let ip_str = AsciiIp::from_ascii(unsafe {
        slice::from_raw_parts(ip_start as *const u8, ip_end - ip_start)
    })?;

    // Only allow trusted source IPs
    let allowed = ascii_ip_allowed(&ip_str);
    let action = match allowed {
        true => {
            match tuple.src.ip {
                IpAddr::Ipv4(ip) => info!(ctx, "PASS {:i} on local port {}", ip, tuple.dst.port),
                IpAddr::Ipv6(_) => info!(ctx, "PASS on local port {}", tuple.dst.port),
            }
            xdp_action::XDP_PASS
        }
        false => {
            match tuple.src.ip {
                IpAddr::Ipv4(ip) => info!(ctx, "DROP {:i} on local port {}", ip, tuple.dst.port),
                IpAddr::Ipv6(_) => info!(ctx, "DROP on local port {}", tuple.dst.port),
            }
            xdp_action::XDP_DROP
        }
    };
    Ok(action)
}

#[derive(Debug)]
pub enum ParseError {
    Mem(PointedOutOfRange),
    Map(MapInsertionError),
    ParseIp(NotAnAsciiIp),
}
impl AbortMsg for ParseError {
    fn err_msg(&self) -> &'static str {
        match self {
            ParseError::Mem(_) => "pointed value out of range",
            ParseError::Map(_) => "failed to insert value to a map",
            ParseError::ParseIp(_) => "failed to parse IP from the HTTP header",
        }
    }
}
impl From<PointedOutOfRange> for ParseError {
    fn from(value: PointedOutOfRange) -> Self {
        Self::Mem(value)
    }
}
impl From<MapInsertionError> for ParseError {
    fn from(value: MapInsertionError) -> Self {
        Self::Map(value)
    }
}
impl From<NotAnAsciiIp> for ParseError {
    fn from(value: NotAnAsciiIp) -> Self {
        Self::ParseIp(value)
    }
}
