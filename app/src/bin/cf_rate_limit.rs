#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::ddos_mitigation::serve("cf_rate_limit").await
}
