#![no_std]

use aya_bpf::{bindings::xdp_action, programs::XdpContext};
use aya_log_ebpf::error;
use error::AbortMsg;

pub mod address;
pub mod error;
pub mod mem;
pub mod programs;

pub fn start<E: AbortMsg>(
    ctx: &XdpContext,
    program: impl Fn(&XdpContext) -> Result<u32, E>,
) -> u32 {
    match program(ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(ctx, "{}", e.err_msg());
            xdp_action::XDP_ABORTED
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[macro_export]
macro_rules! xdp_program {
    ($name: ident) => {
        use app_ebpf::start;
        use aya_bpf::{macros::xdp, programs::XdpContext};

        #[xdp]
        pub fn $name(ctx: XdpContext) -> u32 {
            start(&ctx, app_ebpf::programs::$name::main)
        }
    };
}
