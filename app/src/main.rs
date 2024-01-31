use std::net::Ipv4Addr;

use anyhow::Context;
use app::spawn_bpf;
use app_common::block_ip::UserBlockIp;
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

    let mut bpf = spawn_bpf(&opt.iface)?;

    let mut block_ip = UserBlockIp::try_bind(&mut bpf).context("user block ip")?;
    block_ip.insert(Ipv4Addr::new(1, 1, 1, 1));

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
