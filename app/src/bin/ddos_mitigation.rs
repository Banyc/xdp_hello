#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::ddos_mitigation::serve("ddos_mitigation").await
}
