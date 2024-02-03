use core::slice;

use app_common::{
    address::{IpAddr, L4Protocol},
    allow_ascii_ip::{ascii_ip_allowed, AsciiIp, NotAnAsciiIp},
    gauge::{increment_packets, MapInsertionError},
    restricted_port,
    trim_ascii::{trim_ascii_end, trim_ascii_start},
};
use aya_bpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;
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

    // Crop out the header value that contains the IP string
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
    const SRC_IP_HEADER_KEY: &str = "CF-Connecting-IP:";
    let Some(ip_str_start) = tcp_data_remaining
        .windows(SRC_IP_HEADER_KEY.len())
        .position(|s| s == SRC_IP_HEADER_KEY.as_bytes())
        .map(|x| x + SRC_IP_HEADER_KEY.len())
    else {
        return Ok(xdp_action::XDP_PASS);
    };
    // let ip_str_remaining = &tcp_data_remaining[ip_str_start..];
    let Some(ip_str_remaining) = tcp_data_remaining.len().checked_sub(ip_str_start) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let ip_str_remaining = unsafe {
        slice::from_raw_parts(
            tcp_data_remaining
                .as_ptr()
                .offset(isize::try_from(ip_str_start).unwrap()),
            ip_str_remaining,
        )
    };
    let Some(ip_str_end) = ip_str_remaining.iter().position(|c| *c == b'\n') else {
        return Ok(xdp_action::XDP_PASS);
    };
    // let ip_str = &ip_str_remaining[..ip_str_end];
    let ip_str = unsafe { slice::from_raw_parts(ip_str_remaining.as_ptr(), ip_str_end) };

    // Trim out the white spaces
    let start = trim_ascii_start(ip_str);
    let end = trim_ascii_end(ip_str);
    // let ip_str = &ip_str[start..end];
    let ip_str = unsafe { slice::from_raw_parts(ip_str.as_ptr(), end) };
    let len = end.checked_sub(start).unwrap();
    let ip_str = unsafe {
        slice::from_raw_parts(ip_str.as_ptr().offset(isize::try_from(start).unwrap()), len)
    };

    let ip_str = AsciiIp::from_ascii(ip_str)?;

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
