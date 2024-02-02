use app_common::allow_ip::{self, ip_allowed};
use aya_bpf::{bindings::xdp_action, programs::XdpContext};

use crate::{
    address::{five_tuple, log_five_tuple},
    error::AbortMsg,
    mem::PointedOutOfRange,
};

pub fn main(ctx: &XdpContext) -> Result<u32, ParseError> {
    // Parse port number from the packet
    let Some(tuple) = five_tuple(ctx)? else {
        return Ok(xdp_action::XDP_PASS);
    };

    // Pass all traffic through unrestricted ports
    if !allow_ip::port_restricted(tuple.dst.port) {
        return Ok(xdp_action::XDP_PASS);
    }

    log_five_tuple(ctx, &tuple);

    // Only allow trusted source IPs
    let allowed = ip_allowed(&tuple);
    let action = match allowed {
        true => xdp_action::XDP_PASS,
        false => xdp_action::XDP_DROP,
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
