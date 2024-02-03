#![no_std]
#![no_main]

use app_ebpf::xdp_program;

xdp_program!(firewall);
