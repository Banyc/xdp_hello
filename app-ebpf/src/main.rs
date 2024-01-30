#![no_std]
#![no_main]

use app_ebpf::{
    error::ErrorMsg,
    mem::{ref_at, PointedOutOfRange},
};
use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{error, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp]
pub fn app(ctx: XdpContext) -> u32 {
    // match try_app(&ctx) {
    match try_xdp_firewall(&ctx) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "{}", e.err_msg());
            xdp_action::XDP_ABORTED
        }
    }
}

// fn try_app(ctx: &XdpContext) -> Result<u32, ()> {
//     info!(ctx, "received a packet");
//     Ok(xdp_action::XDP_PASS)
// }

fn try_xdp_firewall(ctx: &XdpContext) -> Result<u32, FirewallError> {
    let ethhdr: &EthHdr = unsafe { ref_at(ctx, 0) }?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4_hdr: &Ipv4Hdr = unsafe { ref_at(ctx, EthHdr::LEN) }?;
    let src_ip = u32::from_be(ipv4_hdr.src_addr);
    let l4_protocol = ipv4_hdr.proto;

    let l4_hdr_offset = EthHdr::LEN + Ipv4Hdr::LEN;
    let src_port: u16 = match l4_protocol {
        IpProto::Tcp => {
            let tcp_hdr: &TcpHdr = unsafe { ref_at(ctx, l4_hdr_offset) }?;
            tcp_hdr.source
        }
        IpProto::Udp => {
            let udp_hdr: &UdpHdr = unsafe { ref_at(ctx, l4_hdr_offset) }?;
            udp_hdr.source
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    info!(ctx, "SRC IP: {:i}, SRC PORT: {}", src_ip, src_port);
    Ok(xdp_action::XDP_PASS)
}
#[derive(Debug)]
enum FirewallError {
    Mem(PointedOutOfRange),
}
impl ErrorMsg for FirewallError {
    fn err_msg(&self) -> &'static str {
        match self {
            FirewallError::Mem(_) => "pointed value out of range",
        }
    }
}
impl From<PointedOutOfRange> for FirewallError {
    fn from(value: PointedOutOfRange) -> Self {
        Self::Mem(value)
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
