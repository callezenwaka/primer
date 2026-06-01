use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;

use crate::github;

pub async fn run_scan(
    repo: String,
    sha: String,
    pr_number: Option<u64>,
    installation_id: u64,
) -> Result<()> {
    let token = github::installation_token(installation_id)
        .await
        .context("failed to obtain installation token")?;

    // Post an in-progress Check Run so GitHub shows the spinner immediately.
    let check_run_id = github::create_check_run(&token, &repo, &sha)
        .await
        .context("failed to create check run")?;

    let result = scan_repo(&token, &repo, &sha).await;

    match result {
        Ok(sarif) => {
            github::complete_check_run(&token, &repo, check_run_id, true, "No blocking findings.")
                .await
                .context("failed to complete check run")?;

            if !sarif.is_empty() {
                github::upload_sarif(&token, &repo, &sha, &sarif)
                    .await
                    .context("failed to upload SARIF")?;
            }

            if let Some(pr) = pr_number {
                github::post_pr_comment(
                    &token,
                    &repo,
                    pr,
                    "✅ primer scan passed — no blocking findings.",
                )
                .await
                .context("failed to post PR comment")?;
            }
        }
        Err(e) => {
            let summary = format!("primer scan failed: {e:#}");
            github::complete_check_run(&token, &repo, check_run_id, false, &summary)
                .await
                .context("failed to complete check run")?;

            if let Some(pr) = pr_number {
                github::post_pr_comment(&token, &repo, pr, &format!("❌ {summary}"))
                    .await
                    .context("failed to post PR comment")?;
            }
        }
    }

    Ok(())
}

async fn scan_repo(token: &str, repo: &str, sha: &str) -> Result<String> {
    let work_dir = tempfile::tempdir().context("failed to create temp dir")?;
    let clone_url = format!("https://x-access-token:{token}@github.com/{repo}.git");

    // Shallow clone at the target SHA.
    let status = Command::new("git")
        .args([
            "clone",
            "--depth=1",
            "--filter=blob:none",
            &clone_url,
            work_dir.path().to_str().unwrap_or("."),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("git clone failed")?;

    anyhow::ensure!(status.success(), "git clone exited with {status}");

    // Checkout the exact SHA (shallow clone may have landed on the default branch tip).
    Command::new("git")
        .args(["fetch", "--depth=1", "origin", sha])
        .current_dir(work_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .ok();

    Command::new("git")
        .args(["checkout", sha])
        .current_dir(work_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .ok();

    // Run primer scan and capture SARIF output.
    let output = Command::new("primer")
        .args(["scan", "--format", "sarif"])
        .current_dir(work_dir.path())
        .output()
        .await
        .context("failed to run `primer scan`")?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("primer scan exited with {}: {stderr}", output.status)
    }
}
