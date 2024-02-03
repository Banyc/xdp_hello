use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use app::spawn_bpf;
use app_common::{
    allow_ascii_ip::UserAllowAsciiIp, gauge::UserGauge, restricted_port::UserRestrictedPort,
};
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
    /// Ports to monitor and potentially restrict
    #[clap(long)]
    port: Vec<u16>,
    /// The threshold packets per second to activate the restriction
    #[clap(long)]
    pps: f64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let mut bpf = spawn_bpf(&opt.iface, "cf_rate_limit")?;

    let gauge = UserGauge::try_bind(&mut bpf).context("user gauge")?;
    let restricted_port = UserRestrictedPort::try_bind(&mut bpf).context("user restricted port")?;
    let allow_ip = UserAllowAsciiIp::try_bind(&mut bpf).context("user allow ip")?;

    let handle_context = HandleContext {
        gauge: Arc::new(Mutex::new(gauge)),
        restricted_port: Arc::new(Mutex::new(restricted_port)),
        allow_ip: Arc::new(Mutex::new(allow_ip)),
    };

    tokio::spawn({
        let handle_context = handle_context.clone();
        let mut last_amount = HashMap::new();
        let interval = Duration::from_secs(5);
        let threshold_pps = opt.pps;
        let ports = opt.port.clone();
        async move {
            loop {
                tokio::time::sleep(interval).await;
                for port in &ports {
                    let prev = last_amount.get(port).copied().unwrap_or_default();
                    let now = {
                        let gauge = handle_context.gauge.lock().unwrap();
                        gauge.packets(*port)
                    };
                    last_amount.insert(*port, now);
                    if now < prev {
                        continue;
                    }
                    let pps = (now - prev) as f64 / interval.as_secs_f64();
                    let mut restrict_port = handle_context.restricted_port.lock().unwrap();
                    if pps < threshold_pps {
                        restrict_port.remove_restricted_port(*port);
                    } else {
                        restrict_port.insert_restricted_port(*port);
                    }
                }
            }
        }
    });

    info!("Waiting for Ctrl-C...");
    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            res?;
        }
        res = serve_rest_api(handle_context) => {
            res?;
        }
    }
    info!("Exiting...");

    Ok(())
}

#[derive(Debug, Clone)]
struct HandleContext {
    pub gauge: GaugeHandle,
    pub restricted_port: RestrictPortHandle,
    pub allow_ip: AllowAsciiIpHandle,
}

type GaugeHandle = Arc<Mutex<UserGauge>>;
type RestrictPortHandle = Arc<Mutex<UserRestrictedPort>>;
type AllowAsciiIpHandle = Arc<Mutex<UserAllowAsciiIp>>;

/// Throughput gauges toggle `/port` to restrict traffic on DDoS and relax the restriction periodically to check if the DDoS has stopped
///
/// Applications toggle `/ip` to trust IPs of the legit users so that when the restriction is on, the applications can still serve those users
///
/// Admins check `/ports` to see what ports have been restricted to either monitor or debug
///
/// Admins check `/packets` to check the received amount of packets on a specific port
async fn serve_rest_api(handle_context: HandleContext) -> anyhow::Result<()> {
    let router = Router::new()
        .route("/packets/:port", get(packets))
        .with_state(handle_context.clone())
        .route("/ports", get(ports))
        .route("/port/:port", put(put_port))
        .route("/port/:port", delete(delete_port))
        .route("/ip/:ip", put(trust_ip))
        .route("/ip/:ip", delete(forget_ip))
        .with_state(handle_context.clone());
    let listener = TcpListener::bind("127.0.0.1:6969").await?;
    axum::serve(listener, router).await?;
    Ok(())
}

/// List packets received of a port
async fn packets(State(handle_context): State<HandleContext>, Path(port): Path<u16>) -> Json<u64> {
    let gauge = handle_context.gauge.lock().unwrap();
    Json(gauge.packets(port))
}

/// List all the restricted ports
async fn ports(State(handle_context): State<HandleContext>) -> Json<Vec<u16>> {
    let restricted_port = handle_context.restricted_port.lock().unwrap();
    Json(restricted_port.restricted_ports())
}

/// Restrict a port
async fn put_port(State(handle_context): State<HandleContext>, Path(port): Path<u16>) {
    info!("Restrict {port}");
    let mut restricted_port = handle_context.restricted_port.lock().unwrap();
    restricted_port.insert_restricted_port(port);
}

/// Relax a port
async fn delete_port(State(handle_context): State<HandleContext>, Path(port): Path<u16>) {
    info!("Relax {port}");
    let mut restricted_port = handle_context.restricted_port.lock().unwrap();
    restricted_port.remove_restricted_port(port);
}

/// Let this IP pass even if the local port is restricted
async fn trust_ip(State(handle_context): State<HandleContext>, Path(ip): Path<IpAddr>) {
    info!("Trust {ip}");
    let mut allow_ip = handle_context.allow_ip.lock().unwrap();
    allow_ip.insert_allowed_ip(ip);
}

/// Remove the privilege of this IP from being unrestricted
async fn forget_ip(State(handle_context): State<HandleContext>, Path(ip): Path<IpAddr>) {
    info!("Forget {ip}");
    let mut allow_ip = handle_context.allow_ip.lock().unwrap();
    allow_ip.remove_allowed_ip(ip);
}
