//! REST API exposed by the engine: health/status for operability, stats
//! and alerts for the dashboard, and a rules listing as the extension
//! point a real "register a new detection rule" endpoint would sit behind.
//!
//! Auth: `/health` stays public (a load balancer or monitoring probe should
//! never need a credential to check liveness). Every other route requires
//! `Authorization: Bearer <token>`, checked against `API_TOKEN` (env var,
//! falls back to a documented dev default). This is intentionally a single
//! shared bearer token, not a full user/session system -- enough to make
//! the full-stack "the admin panel is authenticated" claim real and
//! demonstrable, without pretending this project ships production auth
//! (see docs/DESIGN.md's "Known Limitations" section for what a real
//! deployment would add: per-user accounts, RBAC, token expiry/rotation).

use crate::pipeline::AppState;
use axum::{
    extract::{Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

fn expected_token() -> String {
    std::env::var("API_TOKEN").unwrap_or_else(|_| "dev-token-change-me".to_string())
}

async fn require_auth(req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {}", expected_token()))
        .unwrap_or(false);

    if ok {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    token: String,
}

#[derive(Serialize)]
struct LoginResponse {
    ok: bool,
}

/// Dashboard-facing login: the operator pastes the shared token once and
/// the frontend stores it in memory for the session (see dashboard/index.html).
/// This just validates the token is correct so the UI can show a clear
/// "wrong token" error instead of silently failing on the first real
/// request.
async fn login(Json(body): Json<LoginRequest>) -> impl IntoResponse {
    if body.token == expected_token() {
        (StatusCode::OK, Json(LoginResponse { ok: true }))
    } else {
        (StatusCode::UNAUTHORIZED, Json(LoginResponse { ok: false }))
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    events_processed: u64,
    events_dropped: u64,
}

#[derive(Serialize)]
struct StatsResponse {
    events_processed: u64,
    events_dropped: u64,
    alerts_fired: u64,
    queue_backpressure_events: u64,
}

#[derive(Deserialize)]
struct AlertsQuery {
    limit: Option<usize>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/stats", get(stats))
        .route("/alerts", get(alerts))
        .route("/rules", get(rules))
        .route_layer(middleware::from_fn(require_auth));

    Router::new()
        .route("/health", get(health))
        .route("/login", post(login))
        .merge(protected)
        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// Operability endpoint: an on-call responder (or a monitoring system like
/// Prometheus/Grafana in the full deployment) hits this to check the
/// engine is alive and making forward progress, not just "process is up".
async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        events_processed: state.stats.events_processed.load(Ordering::Relaxed),
        events_dropped: state.stats.events_dropped.load(Ordering::Relaxed),
    })
}

async fn stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    Json(StatsResponse {
        events_processed: state.stats.events_processed.load(Ordering::Relaxed),
        events_dropped: state.stats.events_dropped.load(Ordering::Relaxed),
        alerts_fired: state.stats.alerts_fired.load(Ordering::Relaxed),
        queue_backpressure_events: state.stats.events_dropped.load(Ordering::Relaxed),
    })
}

async fn alerts(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AlertsQuery>,
) -> Json<Vec<crate::models::Alert>> {
    let limit = q.limit.unwrap_or(200).min(5000);
    let alerts = state.alerts.lock().expect("alert store poisoned");
    let out: Vec<_> = alerts.iter().rev().take(limit).cloned().collect();
    Json(out)
}

#[derive(Serialize)]
struct RuleSummary {
    name: &'static str,
    detector: &'static str,
    description: &'static str,
}

async fn rules() -> Json<Vec<RuleSummary>> {
    Json(vec![
        RuleSummary {
            name: "path-traversal-passwd",
            detector: "signature",
            description: "Aho-Corasick match on '/etc/passwd' in payload sample",
        },
        RuleSummary {
            name: "sql-injection-union",
            detector: "signature",
            description: "Aho-Corasick match on 'UNION SELECT' in payload sample",
        },
        RuleSummary {
            name: "syn-flood-anomaly",
            detector: "anomaly",
            description: "Count-Min Sketch estimated SYN count per source exceeds threshold within window",
        },
        RuleSummary {
            name: "port-scan-anomaly",
            detector: "anomaly",
            description: "HyperLogLog estimated distinct destination ports per source exceeds threshold within window",
        },
        RuleSummary {
            name: "probe-then-exploit-attempt",
            detector: "cep",
            description: "NFA sequence: SYN probe followed by known-bad payload from same source within 5s window",
        },
    ])
}
