use core::convert::Infallible;

use aya_bpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::info;

pub fn main(ctx: &XdpContext) -> Result<u32, Infallible> {
    info!(ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}
