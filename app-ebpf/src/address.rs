use app_common::address::{Address, FiveTuple, IpAddr, L4Protocol};
use aya_bpf::programs::XdpContext;
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use crate::mem::{ref_at, PointedOutOfRange};

pub fn log_five_tuple(ctx: &XdpContext, tuple: &FiveTuple) {
    let p = match tuple.protocol {
        L4Protocol::Tcp => "TCP",
        L4Protocol::Udp => "UDP",
    };
    let src_ip = match tuple.src.ip {
        IpAddr::Ipv4(ip) => ip,
        IpAddr::Ipv6(_ip) => 0,
    };
    let dst_ip = match tuple.dst.ip {
        IpAddr::Ipv4(ip) => ip,
        IpAddr::Ipv6(_ip) => 0,
    };
    info!(
        ctx,
        "{},{:i}:{},{:i}:{}", p, src_ip, tuple.src.port, dst_ip, tuple.dst.port
    );
}

/// Extract the five-tuple from the packet
pub fn five_tuple(ctx: &XdpContext) -> Result<Option<FiveTuple>, PointedOutOfRange> {
    // Parse port number from the packet
    let eth_hdr: &EthHdr = unsafe { ref_at(ctx, 0) }?;
    let tuple = match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4_hdr: &Ipv4Hdr = unsafe { ref_at(ctx, EthHdr::LEN) }?;
            let Some((protocol, src_port, dst_port)) =
                unsafe { ports_from_ip_proto(ctx, ipv4_hdr.proto, Ipv4Hdr::LEN) }?
            else {
                return Ok(None);
            };
            FiveTuple {
                protocol,
                src: Address {
                    ip: IpAddr::Ipv4(u32::from_be(ipv4_hdr.src_addr)),
                    port: src_port,
                },
                dst: Address {
                    ip: IpAddr::Ipv4(u32::from_be(ipv4_hdr.dst_addr)),
                    port: dst_port,
                },
            }
        }
        EtherType::Ipv6 => {
            let ipv6_hdr: &Ipv6Hdr = unsafe { ref_at(ctx, EthHdr::LEN) }?;
            let Some((protocol, src_port, dst_port)) =
                unsafe { ports_from_ip_proto(ctx, ipv6_hdr.next_hdr, Ipv6Hdr::LEN) }?
            else {
                return Ok(None);
            };
            FiveTuple {
                protocol,
                src: Address {
                    ip: IpAddr::Ipv6(u128::from_be_bytes(unsafe {
                        ipv6_hdr.src_addr.in6_u.u6_addr8
                    })),
                    port: src_port,
                },
                dst: Address {
                    ip: IpAddr::Ipv6(u128::from_be_bytes(unsafe {
                        ipv6_hdr.dst_addr.in6_u.u6_addr8
                    })),
                    port: dst_port,
                },
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(tuple))
}

/// # Safety
///
/// Make sure:
/// - `ctx` is an Ethernet packet
/// - `l4_proto` is extracted from the right position in `ctx`
/// - `ip_hdr_len` is the length of the IP header in `ctx`
unsafe fn ports_from_ip_proto(
    ctx: &XdpContext,
    l4_proto: IpProto,
    ip_hdr_len: usize,
) -> Result<Option<(L4Protocol, u16, u16)>, PointedOutOfRange> {
    let (protocol, be_src_port, be_dst_port) = match l4_proto {
        IpProto::Tcp => {
            let tcp_hdr: &TcpHdr = unsafe { ref_at(ctx, EthHdr::LEN + ip_hdr_len)? };
            (L4Protocol::Tcp, tcp_hdr.source, tcp_hdr.dest)
        }
        IpProto::Udp => {
            let udp_hdr: &UdpHdr = unsafe { ref_at(ctx, EthHdr::LEN + ip_hdr_len)? };
            (L4Protocol::Udp, udp_hdr.source, udp_hdr.dest)
        }
        _ => return Ok(None),
    };
    Ok(Some((
        protocol,
        u16::from_be(be_src_port),
        u16::from_be(be_dst_port),
    )))
}
