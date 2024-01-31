#![no_std]
#![no_main]

use app_ebpf::start;
use aya_bpf::{macros::xdp, programs::XdpContext};

#[xdp]
pub fn app(ctx: XdpContext) -> u32 {
    start(&ctx, app_ebpf::programs::ddos_mitigation::main)
}
