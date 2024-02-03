use core::slice;

use app_common::{
    address::{IpAddr, L4Protocol},
    allow_ip::ip_allowed,
    gauge::{increment_packets, MapInsertionError},
    restricted_port,
    trim_ascii::trim_ascii,
};
use aya_bpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;
use bstr::ByteSlice;
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
};

use crate::{address::five_tuple, error::AbortMsg, mem::PointedOutOfRange};

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

    // crop out the header value that contains the IP string
    if matches!(tuple.protocol, L4Protocol::Udp) {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip_hdr_len = match tuple.src.ip {
        IpAddr::Ipv4(_) => Ipv4Hdr::LEN,
        IpAddr::Ipv6(_) => Ipv6Hdr::LEN,
    };
    let tcp_data_start = EthHdr::LEN + ip_hdr_len + TcpHdr::LEN;
    let Some(tcp_data_remaining) = ctx.data_end().checked_sub(tcp_data_start) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let tcp_data_remaining: &[u8] =
        unsafe { slice::from_raw_parts(tcp_data_start as *const u8, tcp_data_remaining) };
    let Some((_, ip_str_remaining)) = tcp_data_remaining.split_once_str("CF-Connecting-IP:") else {
        return Ok(xdp_action::XDP_PASS);
    };
    let Some((_, ip_str)) = ip_str_remaining.split_once_str("\n") else {
        return Ok(xdp_action::XDP_PASS);
    };

    let Some(ip) = IpAddr::from_ascii(trim_ascii(ip_str)) else {
        return Ok(xdp_action::XDP_PASS);
    };

    // Only allow trusted source IPs
    let allowed = ip_allowed(ip);
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
}
impl AbortMsg for ParseError {
    fn err_msg(&self) -> &'static str {
        match self {
            ParseError::Mem(_) => "pointed value out of range",
            ParseError::Map(_) => "failed to insert value to a map",
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
