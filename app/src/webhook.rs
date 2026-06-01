use axum::{
    body::Bytes,
    extract::Request,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::runner;

type HmacSha256 = Hmac<Sha256>;

pub async fn handle(headers: HeaderMap, request: Request) -> impl IntoResponse {
    let event = match headers.get("X-GitHub-Event").and_then(|v| v.to_str().ok()) {
        Some(e) => e.to_owned(),
        None => return (StatusCode::BAD_REQUEST, "missing X-GitHub-Event").into_response(),
    };

    let body = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "failed to read body").into_response(),
    };

    if let Some(sig) = headers
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
    {
        if !verify_signature(&body, sig) {
            return (StatusCode::UNAUTHORIZED, "invalid signature").into_response();
        }
    }

    match event.as_str() {
        "push" => handle_push(&body).await,
        "pull_request" => handle_pull_request(&body).await,
        "ping" => StatusCode::OK.into_response(),
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn handle_push(body: &Bytes) -> axum::response::Response {
    let payload: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid JSON").into_response(),
    };

    let repo = payload["repository"]["full_name"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let sha = payload["after"].as_str().unwrap_or("").to_owned();
    let installation_id = payload["installation"]["id"].as_u64().unwrap_or(0);

    if repo.is_empty() || sha.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }

    tracing::info!(%repo, %sha, "push event received");
    tokio::spawn(async move {
        if let Err(e) = runner::run_scan(repo, sha, None, installation_id).await {
            tracing::error!("scan failed: {e:#}");
        }
    });

    StatusCode::ACCEPTED.into_response()
}

async fn handle_pull_request(body: &Bytes) -> axum::response::Response {
    let payload: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid JSON").into_response(),
    };

    let action = payload["action"].as_str().unwrap_or("");
    if !matches!(action, "opened" | "synchronize" | "reopened") {
        return StatusCode::NO_CONTENT.into_response();
    }

    let repo = payload["repository"]["full_name"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let sha = payload["pull_request"]["head"]["sha"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let pr_number = payload["number"].as_u64();
    let installation_id = payload["installation"]["id"].as_u64().unwrap_or(0);

    if repo.is_empty() || sha.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }

    tracing::info!(%repo, %sha, ?pr_number, "pull_request event received");
    tokio::spawn(async move {
        if let Err(e) = runner::run_scan(repo, sha, pr_number, installation_id).await {
            tracing::error!("scan failed: {e:#}");
        }
    });

    StatusCode::ACCEPTED.into_response()
}

fn verify_signature(body: &[u8], signature_header: &str) -> bool {
    let secret = match std::env::var("WEBHOOK_SECRET") {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("WEBHOOK_SECRET not set — skipping signature verification");
            return true;
        }
    };

    let hex_sig = match signature_header.strip_prefix("sha256=") {
        Some(s) => s,
        None => return false,
    };
    let sig_bytes = match hex::decode(hex_sig) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(body);
    mac.verify_slice(&sig_bytes).is_ok()
}
