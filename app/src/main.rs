mod github;
mod runner;
mod webhook;

use axum::{Router, routing::post};
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "primer_app=debug,tower_http=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = Router::new().route("/webhook", post(webhook::handle));

    // Cloud Run injects PORT; LISTEN_ADDR takes priority for local overrides.
    let addr = std::env::var("LISTEN_ADDR")
        .or_else(|_| std::env::var("PORT").map(|p| format!("0.0.0.0:{p}")))
        .unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = TcpListener::bind(&addr).await.expect("failed to bind");
    tracing::info!("primer-app listening on {addr}");
    axum::serve(listener, app).await.expect("server error");
}
