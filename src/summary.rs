#[cfg(feature = "ai")]
pub mod download;
#[cfg(feature = "ai")]
mod infer;

use std::path::PathBuf;

#[cfg(feature = "ai")]
use crate::engine::osv::Vulnerability;

// ---------------------------------------------------------------------------
// Model paths
// ---------------------------------------------------------------------------

pub fn models_dir() -> PathBuf {
    crate::home::primer_dir().join("models")
}

pub fn default_model_path() -> PathBuf {
    models_dir().join("smollm2-135m-instruct-q4_k_m.gguf")
}

pub fn default_tokenizer_path() -> PathBuf {
    models_dir().join("tokenizer.json")
}

/// Returns (model_path, tokenizer_path) from config, falling back to defaults.
pub fn active_paths() -> (PathBuf, PathBuf) {
    if let Ok(cfg) = crate::config::load() {
        let model = cfg.ai.model.unwrap_or_else(default_model_path);
        let tokenizer = cfg.ai.tokenizer.unwrap_or_else(default_tokenizer_path);
        return (model, tokenizer);
    }
    (default_model_path(), default_tokenizer_path())
}

#[cfg(feature = "ai")]
pub fn model_present() -> bool {
    let (model, tokenizer) = active_paths();
    model.exists() && tokenizer.exists()
}

// ---------------------------------------------------------------------------
// Summary type
// ---------------------------------------------------------------------------

#[cfg(feature = "ai")]
pub struct Summary {
    pub text: String,
}

// ---------------------------------------------------------------------------
// Public entry point — feature-dispatched
// ---------------------------------------------------------------------------

/// Generate a ≤3-sentence summary for the given vulnerabilities.
/// Only available when compiled with `--features ai`.
#[cfg(feature = "ai")]
pub fn generate(vulns: &[Vulnerability]) -> Option<Summary> {
    if !model_present() {
        return None;
    }
    let (model, tokenizer) = active_paths();
    infer::run(vulns, &model, &tokenizer)
        .ok()
        .map(|text| Summary { text })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(feature = "ai")]
    use super::*;
    #[cfg(feature = "ai")]
    use crate::engine::osv::Vulnerability;

    #[test]
    #[cfg(feature = "ai")]
    fn generate_returns_none_when_model_absent() {
        let vulns = vec![Vulnerability {
            id: "GHSA-0001".into(),
            summary: Some("test".into()),
            cvss_vector: None,
            severity: Some("HIGH".into()),
            fixed_version: None,
        }];
        // Without a real model file this must return None, not panic.
        assert!(generate(&vulns).is_none());
    }

    #[test]
    #[cfg(feature = "ai")]
    fn model_present_false_when_dir_missing() {
        let result = std::panic::catch_unwind(model_present);
        assert!(result.is_ok(), "model_present must not panic");
    }
}
