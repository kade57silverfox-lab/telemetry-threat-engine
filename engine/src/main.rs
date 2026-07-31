mod api;
mod detection;
mod ingestion;
mod models;
mod pipeline;
mod queue;

use pipeline::{spawn_producer, spawn_workers, AppState};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

const QUEUE_CAPACITY: usize = 1 << 16; // must be a power of two, per-worker
const WORKER_COUNT: usize = 4;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .json()
        .init();

    tracing::info!(
        queue_capacity_per_worker = QUEUE_CAPACITY,
        worker_count = WORKER_COUNT,
        "starting threat engine"
    );

    let state = Arc::new(AppState::new(WORKER_COUNT, QUEUE_CAPACITY));

    spawn_producer(Arc::clone(&state));
    spawn_workers(Arc::clone(&state));

    let app = api::build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("failed to bind port 8080");

    tracing::info!(
        api_token = std::env::var("API_TOKEN").unwrap_or_else(|_| "dev-token-change-me".to_string()),
        "API listening on http://0.0.0.0:8080 (dashboard login token above -- set API_TOKEN env var in production)"
    );
    axum::serve(listener, app).await.expect("server error");
}
