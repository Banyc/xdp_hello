use app_common::block_ip;
use aya_bpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

use crate::{
    error::AbortMsg,
    mem::{ref_at, PointedOutOfRange},
};

pub fn main(ctx: &XdpContext) -> Result<u32, ParseError> {
    let eth_hdr: &EthHdr = unsafe { ref_at(ctx, 0) }?;
    match eth_hdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4_hdr: &Ipv4Hdr = unsafe { ref_at(ctx, EthHdr::LEN) }?;

    let action = match block_ip::blocked(ipv4_hdr) {
        true => xdp_action::XDP_DROP,
        false => xdp_action::XDP_PASS,
    };

    let src_ip = u32::from_be(ipv4_hdr.src_addr);
    info!(ctx, "SRC IP: {:i}, ACTION: {}", src_ip, action);
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
