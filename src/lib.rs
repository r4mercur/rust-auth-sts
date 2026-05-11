pub mod startup;
pub mod config;
pub mod error;
pub mod models;
pub mod crypto;
pub mod http;

pub mod repository;

pub mod service;


pub mod telemetry {
    use tracing_subscriber::{EnvFilter, fmt};
    pub fn init() {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }
}
