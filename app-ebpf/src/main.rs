#![no_std]
#![no_main]

use app_ebpf::start;
use aya_bpf::{macros::xdp, programs::XdpContext};

#[xdp]
pub fn app(ctx: XdpContext) -> u32 {
    // start(&ctx, app_ebpf::programs::log_unparsed_packets::main)
    // start(&ctx, app_ebpf::programs::log_l4_packets::main)
    start(&ctx, app_ebpf::programs::firewall::main)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
