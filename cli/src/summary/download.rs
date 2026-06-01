use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use hf_hub::api::tokio::Api;

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MODEL_REPO: &str = "HuggingFaceTB/SmolLM2-135M-Instruct-GGUF";
const DEFAULT_MODEL_FILE: &str = "smollm2-135m-instruct-q4_k_m.gguf";
const DEFAULT_TOKENIZER_REPO: &str = "HuggingFaceTB/SmolLM2-135M-Instruct";
const DEFAULT_TOKENIZER_FILE: &str = "tokenizer.json";

// ---------------------------------------------------------------------------
// Options passed in from the CLI
// ---------------------------------------------------------------------------

pub struct DownloadOptions {
    /// Local GGUF path — skip network, register this file directly.
    pub from: Option<PathBuf>,
    /// Local tokenizer path — paired with `--from`.
    pub tokenizer: Option<PathBuf>,
    /// Custom HF repo (used with `--file`).
    pub repo: Option<String>,
    /// Filename within the HF repo.
    pub file: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(opts: DownloadOptions) -> Result<()> {
    let models_dir = super::models_dir();
    std::fs::create_dir_all(&models_dir)?;

    let model_dest = models_dir.join(
        opts.from
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| DEFAULT_MODEL_FILE.to_string()),
    );
    let tokenizer_dest = models_dir.join(DEFAULT_TOKENIZER_FILE);

    // -- Model --
    if let Some(local) = &opts.from {
        copy_local(local, &model_dest, "model")?;
    } else {
        let repo = opts.repo.as_deref().unwrap_or(DEFAULT_MODEL_REPO);
        let file = opts.file.as_deref().unwrap_or(DEFAULT_MODEL_FILE);
        download_from_hub(repo, file, &model_dest).await?;
    }

    // -- Tokenizer --
    if let Some(local) = &opts.tokenizer {
        copy_local(local, &tokenizer_dest, "tokenizer")?;
    } else if opts.from.is_none() {
        // Only auto-download tokenizer when we also auto-downloaded the model.
        let repo = opts.repo.as_deref().unwrap_or(DEFAULT_TOKENIZER_REPO);
        download_from_hub(repo, DEFAULT_TOKENIZER_FILE, &tokenizer_dest).await?;
    } else {
        eprintln!(
            "  ⚠  No tokenizer provided for local model. Run with --tokenizer <path> or copy\n     {} manually.",
            tokenizer_dest.display()
        );
    }

    // -- Persist active paths to config --
    let mut cfg = crate::config::load().unwrap_or_default();
    cfg.ai.model = Some(model_dest.clone());
    cfg.ai.tokenizer = Some(tokenizer_dest.clone());
    crate::config::save(&cfg)?;

    println!("\n  ✓ Active model:     {}", model_dest.display());
    println!("  ✓ Active tokenizer: {}", tokenizer_dest.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn copy_local(src: &Path, dest: &Path, label: &str) -> Result<()> {
    if dest.exists() {
        println!("  · {} already at destination, skipping copy.", label);
        return Ok(());
    }
    std::fs::copy(src, dest)
        .with_context(|| format!("copying {} from {}", label, src.display()))?;
    println!("  ✓ {} registered from {}", label, src.display());
    Ok(())
}

async fn download_from_hub(repo: &str, filename: &str, dest: &Path) -> Result<()> {
    if dest.exists() {
        println!("  · {} already present, skipping download.", filename);
        return Ok(());
    }

    println!("  Downloading {}/{} …", repo, filename);
    let api = Api::new().context("initialising HF Hub client")?;
    let cached = api
        .model(repo.to_string())
        .get(filename)
        .await
        .with_context(|| format!("downloading {}/{}", repo, filename))?;

    std::fs::copy(&cached, dest)
        .with_context(|| format!("copying {} to {}", cached.display(), dest.display()))?;
    println!("  ✓ Saved to {}", dest.display());
    Ok(())
}
