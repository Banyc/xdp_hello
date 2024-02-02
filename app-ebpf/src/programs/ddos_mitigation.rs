use app_common::allow_ip::{self, ip_allowed};
use aya_bpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;

use crate::{address::five_tuple, error::AbortMsg, mem::PointedOutOfRange};

pub fn main(ctx: &XdpContext) -> Result<u32, ParseError> {
    // Parse port number from the packet
    let Some(tuple) = five_tuple(ctx)? else {
        return Ok(xdp_action::XDP_PASS);
    };

    // Pass all traffic through unrestricted ports
    if !allow_ip::port_restricted(tuple.dst.port) {
        return Ok(xdp_action::XDP_PASS);
    }

    // Only allow trusted source IPs
    let allowed = ip_allowed(&tuple);
    let action = match allowed {
        true => {
            info!(ctx, "PASS on local port {}", tuple.dst.port);
            xdp_action::XDP_PASS
        }
        false => {
            info!(ctx, "DROP on local port {}", tuple.dst.port);
            xdp_action::XDP_DROP
        }
    };
    Ok(action)
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
