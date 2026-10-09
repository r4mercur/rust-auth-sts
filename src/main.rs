use std::io::Read;
use rust_auth_sts::startup::run;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        None => {}
        Some("hash-secret") => return hash_secret_from_stdin(),
        Some(other) => anyhow::bail!("unknown command: {other} (available: hash-secret)"),
    }
    rust_auth_sts::telemetry::init();
    run().await
}

fn hash_secret_from_stdin() -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let secret = input.trim_end_matches(['\r', '\n']);
    if secret.is_empty() {
        anyhow::bail!("no secret on stdin");
    }
    println!("{}", rust_auth_sts::crypto::password::hash_secret(secret)?);
    Ok(())
}
