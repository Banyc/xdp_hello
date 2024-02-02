use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
};

use anyhow::Context;
use app::spawn_bpf;
use app_common::{allow_ip::UserAllowIp, gauge::UserGauge};
use axum::{
    extract::{Path, State},
    routing::{delete, get, put},
    Json, Router,
};
use clap::Parser;
use log::info;
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let mut bpf = spawn_bpf(&opt.iface, "ddos_mitigation")?;

    let gauge = UserGauge::try_bind(&mut bpf).context("user gauge")?;

    let mut allow_ip = UserAllowIp::try_bind(&mut bpf).context("user allow ip")?;
    allow_ip.insert_restricted_port(443);
    allow_ip.insert_allowed_ip(Ipv4Addr::new(1, 1, 1, 1).into());

    let gauge: GaugeHandle = Arc::new(Mutex::new(gauge));
    let allow_ip: AllowIpHandle = Arc::new(Mutex::new(allow_ip));

    info!("Waiting for Ctrl-C...");
    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            res?;
        }
        res = serve(gauge, allow_ip) => {
            res?;
        }
    }
    info!("Exiting...");

    Ok(())
}

pub type GaugeHandle = Arc<Mutex<UserGauge>>;
pub type AllowIpHandle = Arc<Mutex<UserAllowIp>>;

/// Throughput gauges toggle `/port` to restrict traffic on DDoS and relax the restriction periodically to check if the DDoS has stopped
///
/// Applications toggle `/ip` to trust IPs of the legit users so that when the restriction is on, the applications can still serve those users
///
/// Admins check `/ports` to see what ports have been restricted to either monitor or debug
async fn serve(gauge: GaugeHandle, allow_ip: AllowIpHandle) -> anyhow::Result<()> {
    let router = Router::new()
        .route("/packets/:port", get(packets))
        .with_state(gauge)
        .route("/ports", get(ports))
        .route("/port/:port", put(put_port))
        .route("/port/:port", delete(delete_port))
        .route("/ip/:ip", put(trust_ip))
        .route("/ip/:ip", delete(forget_ip))
        .with_state(allow_ip);
    let listener = TcpListener::bind("127.0.0.1:6969").await?;
    axum::serve(listener, router).await?;
    Ok(())
}

/// List packets received of a port
async fn packets(State(gauge): State<GaugeHandle>, Path(port): Path<u16>) -> Json<u64> {
    let gauge = gauge.lock().unwrap();
    Json(gauge.packets(port))
}

/// List all the restricted ports
async fn ports(State(allow_ip): State<AllowIpHandle>) -> Json<Vec<u16>> {
    let allow_ip = allow_ip.lock().unwrap();
    Json(allow_ip.restricted_ports())
}

/// Restrict a port
async fn put_port(State(allow_ip): State<AllowIpHandle>, Path(port): Path<u16>) {
    let mut allow_ip = allow_ip.lock().unwrap();
    allow_ip.insert_restricted_port(port);
}

/// Relax a port
async fn delete_port(State(allow_ip): State<AllowIpHandle>, Path(port): Path<u16>) {
    let mut allow_ip = allow_ip.lock().unwrap();
    allow_ip.remove_restricted_port(port);
}

/// Let this IP pass even if the local port is restricted
async fn trust_ip(State(allow_ip): State<AllowIpHandle>, Path(ip): Path<IpAddr>) {
    let mut allow_ip = allow_ip.lock().unwrap();
    allow_ip.insert_allowed_ip(ip);
}

/// Remove the privilege of this IP from being unrestricted
async fn forget_ip(State(allow_ip): State<AllowIpHandle>, Path(ip): Path<IpAddr>) {
    let mut allow_ip = allow_ip.lock().unwrap();
    allow_ip.remove_allowed_ip(ip);
}
