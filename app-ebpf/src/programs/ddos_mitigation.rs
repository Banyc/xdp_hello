use app_common::{
    address::IpAddr,
    allow_ip::{self, ip_allowed},
    gauge::{increment_packets, MapInsertionError},
};
use aya_bpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;

use crate::{address::five_tuple, error::AbortMsg, mem::PointedOutOfRange};

pub fn main(ctx: &XdpContext) -> Result<u32, ParseError> {
    // Parse port number from the packet
    let Some(tuple) = five_tuple(ctx)? else {
        return Ok(xdp_action::XDP_PASS);
    };

    // Gauge the throughput per port
    increment_packets(tuple.dst.port)?;

    // Pass all traffic through unrestricted ports
    if !allow_ip::port_restricted(tuple.dst.port) {
        return Ok(xdp_action::XDP_PASS);
    }

    // Only allow trusted source IPs
    let allowed = ip_allowed(&tuple);
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
