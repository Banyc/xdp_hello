use std::net::Ipv4Addr;

use anyhow::Context;
use app::spawn_bpf;
use app_common::allow_ip::UserAllowIp;
use clap::Parser;
use log::info;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    let mut bpf = spawn_bpf(&opt.iface, "ddos_mitigation")?;

    let mut allow_ip = UserAllowIp::try_bind(&mut bpf).context("user allow ip")?;
    allow_ip.insert_restricted_port(53);
    allow_ip.insert_allowed_ip(Ipv4Addr::new(1, 1, 1, 1).into());

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
