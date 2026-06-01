use anyhow::{Context, Result};
use serde_json::json;

const GITHUB_API: &str = "https://api.github.com";

// ---------------------------------------------------------------------------
// Installation token (GitHub App auth)
// ---------------------------------------------------------------------------

pub async fn installation_token(installation_id: u64) -> Result<String> {
    let jwt = app_jwt().context("failed to generate App JWT")?;
    let client = reqwest::Client::new();
    let url = format!("{GITHUB_API}/app/installations/{installation_id}/access_tokens");

    let resp = client
        .post(&url)
        .bearer_auth(&jwt)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "primer-app/0.1.0")
        .send()
        .await
        .context("POST access_tokens failed")?
        .error_for_status()
        .context("access_tokens returned error")?;

    let body: serde_json::Value = resp
        .json()
        .await
        .context("failed to parse token response")?;
    body["token"]
        .as_str()
        .map(|s| s.to_owned())
        .context("token field missing from response")
}

fn app_jwt() -> Result<String> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    let app_id = std::env::var("APP_ID").context("APP_ID env var not set")?;
    let pem = std::env::var("APP_PRIVATE_KEY").context("APP_PRIVATE_KEY env var not set")?;
    // Env vars often store newlines as literal \n — normalise before parsing.
    let pem = pem.replace("\\n", "\n");

    let key = EncodingKey::from_rsa_pem(pem.as_bytes())
        .context("invalid RSA private key in APP_PRIVATE_KEY")?;

    let now = chrono::Utc::now().timestamp();

    #[derive(serde::Serialize)]
    struct Claims {
        iat: i64,
        exp: i64,
        iss: String,
    }
    let claims = Claims {
        iat: now - 60,  // 60s in the past — absorbs clock skew
        exp: now + 540, // 9 min — GitHub max is 10
        iss: app_id,
    };

    // NOTE: Do not add token length limits — GitHub installation tokens are
    // migrating to a stateless format (ghs_..., up to ~520 chars).
    encode(&Header::new(Algorithm::RS256), &claims, &key).context("failed to sign App JWT")
}

// ---------------------------------------------------------------------------
// Check Runs
// ---------------------------------------------------------------------------

pub async fn create_check_run(token: &str, repo: &str, sha: &str) -> Result<u64> {
    let client = reqwest::Client::new();
    let url = format!("{GITHUB_API}/repos/{repo}/check-runs");

    let body = json!({
        "name": "primer security scan",
        "head_sha": sha,
        "status": "in_progress",
        "started_at": chrono_now_rfc3339(),
    });

    let resp = client
        .post(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "primer-app/0.1.0")
        .json(&body)
        .send()
        .await
        .context("POST check-runs failed")?
        .error_for_status()
        .context("check-runs returned error")?;

    let data: serde_json::Value = resp.json().await?;
    data["id"]
        .as_u64()
        .context("id missing from check-run response")
}

pub async fn complete_check_run(
    token: &str,
    repo: &str,
    check_run_id: u64,
    passed: bool,
    summary: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{GITHUB_API}/repos/{repo}/check-runs/{check_run_id}");

    let conclusion = if passed { "success" } else { "failure" };
    let body = json!({
        "status": "completed",
        "conclusion": conclusion,
        "completed_at": chrono_now_rfc3339(),
        "output": {
            "title": "primer security scan",
            "summary": summary,
        }
    });

    client
        .patch(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "primer-app/0.1.0")
        .json(&body)
        .send()
        .await
        .context("PATCH check-run failed")?
        .error_for_status()
        .context("check-run update returned error")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// SARIF upload
// ---------------------------------------------------------------------------

pub async fn upload_sarif(token: &str, repo: &str, sha: &str, sarif_json: &str) -> Result<()> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(sarif_json.as_bytes())
        .context("gzip write failed")?;
    let compressed = encoder.finish().context("gzip finish failed")?;
    let encoded = base64_encode(&compressed);

    let client = reqwest::Client::new();
    let url = format!("{GITHUB_API}/repos/{repo}/code-scanning/sarifs");

    let body = json!({
        "commit_sha": sha,
        "ref": format!("refs/heads/main"),
        "sarif": encoded,
        "tool_name": "primer",
    });

    client
        .post(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "primer-app/0.1.0")
        .json(&body)
        .send()
        .await
        .context("POST sarifs failed")?
        .error_for_status()
        .context("sarif upload returned error")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// PR comments
// ---------------------------------------------------------------------------

pub async fn post_pr_comment(
    token: &str,
    repo: &str,
    pr_number: u64,
    body_text: &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments");

    let body = json!({ "body": body_text });

    client
        .post(&url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "primer-app/0.1.0")
        .json(&body)
        .send()
        .await
        .context("POST comments failed")?
        .error_for_status()
        .context("comment post returned error")?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn chrono_now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn base64_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        let _ = write!(out, "{}", TABLE[b0 >> 2] as char);
        let _ = write!(out, "{}", TABLE[((b0 & 3) << 4) | (b1 >> 4)] as char);
        let _ = write!(
            out,
            "{}",
            if chunk.len() > 1 {
                TABLE[((b1 & 0xf) << 2) | (b2 >> 6)] as char
            } else {
                '='
            }
        );
        let _ = write!(
            out,
            "{}",
            if chunk.len() > 2 {
                TABLE[b2 & 0x3f] as char
            } else {
                '='
            }
        );
    }
    out
}
