use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use app::spawn_bpf;
use app_common::allow_ip::UserAllowIp;
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

    let mut allow_ip = UserAllowIp::try_bind(&mut bpf).context("user allow ip")?;
    allow_ip.insert_restricted_port(443);
    allow_ip.insert_allowed_ip(Ipv4Addr::new(1, 1, 1, 1).into());

    let allow_ip: BpfMapHandle = unsafe { std::mem::transmute(Arc::new(Mutex::new(allow_ip))) };

    info!("Waiting for Ctrl-C...");
    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            res?;
        }
        res = serve(allow_ip) => {
            res?;
        }
    }
    info!("Exiting...");

    Ok(())
}

pub type BpfMapHandle = Arc<Mutex<UserAllowIp<'static>>>;

async fn serve(allow_ip: BpfMapHandle) -> anyhow::Result<()> {
    let router = Router::new()
        .route("/ports", get(ports))
        .route("/port/:port", put(put_port))
        .route("/port/:port", delete(delete_port))
        .with_state(allow_ip);
    let listener = TcpListener::bind("127.0.0.1:6969").await?;
    axum::serve(listener, router).await?;
    Ok(())
}

/// List all the restricted ports
async fn ports(State(allow_ip): State<BpfMapHandle>) -> Json<Vec<u16>> {
    let allow_ip = allow_ip.lock().unwrap();
    Json(allow_ip.restricted_ports())
}

/// Restrict a port
async fn put_port(State(allow_ip): State<BpfMapHandle>, Path(port): Path<u16>) {
    let mut allow_ip = allow_ip.lock().unwrap();
    allow_ip.insert_restricted_port(port);
}

/// Relax a port
async fn delete_port(State(allow_ip): State<BpfMapHandle>, Path(port): Path<u16>) {
    let mut allow_ip = allow_ip.lock().unwrap();
    allow_ip.remove_restricted_port(port);
}