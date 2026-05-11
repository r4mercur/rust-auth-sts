use rust_auth_sts::startup::run;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rust_auth_sts::telemetry::init();
    run().await
}
