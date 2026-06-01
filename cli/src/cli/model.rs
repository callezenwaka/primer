use std::path::{Path, PathBuf};

use anyhow::Result;
use colored::Colorize;

// ---------------------------------------------------------------------------
// model add
// ---------------------------------------------------------------------------

pub async fn add(
    from: Option<PathBuf>,
    tokenizer: Option<PathBuf>,
    repo: Option<String>,
    file: Option<String>,
) -> Result<()> {
    #[cfg(feature = "ai")]
    {
        let dl = crate::summary::download::DownloadOptions {
            from,
            tokenizer,
            repo,
            file,
        };
        crate::summary::download::run(dl).await?;
    }
    #[cfg(not(feature = "ai"))]
    {
        let _ = (from, tokenizer, repo, file);
        eprintln!(
            "AI features are not compiled in.\n\
             Rebuild with:  cargo install primer --features ai"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// model list
// ---------------------------------------------------------------------------

pub fn list() -> Result<()> {
    let models_dir = crate::summary::models_dir();

    if !models_dir.exists() {
        println!("No models directory found. Run: primer model add");
        return Ok(());
    }

    let cfg = crate::config::load().unwrap_or_default();
    let active_model = cfg
        .ai
        .model
        .as_deref()
        .and_then(|p| p.to_str())
        .unwrap_or("");
    let backend = cfg.ai.backend.as_deref().unwrap_or("local");

    println!("Models: {}\n", models_dir.display());

    let mut found = false;
    let mut entries: Vec<_> = std::fs::read_dir(&models_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "gguf" || ext == "json")
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let is_active = path.to_str().map(|s| s == active_model).unwrap_or(false);
        let marker = if is_active { "* " } else { "  " };
        println!(
            "{}{:<50} {:.1} MB",
            marker,
            path.file_name().unwrap_or_default().to_string_lossy(),
            size as f64 / (1024.0 * 1024.0)
        );
        found = true;
    }

    if !found {
        println!("  (no model files found)");
    }

    if backend == "ollama" {
        println!(
            "\n  * active backend: ollama ({})",
            cfg.ai
                .model
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "(none)".into())
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// model set
// ---------------------------------------------------------------------------

pub fn set(target: &str) -> Result<()> {
    let mut cfg = crate::config::load().unwrap_or_default();

    if let Some(model_name) = target.strip_prefix("ollama:") {
        // Ollama backend
        cfg.ai.backend = Some("ollama".to_string());
        cfg.ai.model = Some(PathBuf::from(model_name));
        crate::config::save(&cfg)?;
        println!("  ✓ backend = ollama");
        println!("  ✓ model   = {}", model_name);
        println!();
        println!("  Inference will be routed to http://localhost:11434");
        println!(
            "  Make sure Ollama is running and '{}' is pulled.",
            model_name
        );
    } else {
        // Local GGUF path
        let path = PathBuf::from(target);
        if !path.exists() {
            anyhow::bail!(
                "model file not found: {}\n  Use `primer model add --from <path>` to import it first.",
                path.display()
            );
        }
        cfg.ai.backend = Some("local".to_string());
        cfg.ai.model = Some(path.clone());
        crate::config::save(&cfg)?;
        println!("  ✓ backend = local");
        println!("  ✓ model   = {}", path.display());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// model remove
// ---------------------------------------------------------------------------

/// Display wrapper so inquire::Select shows a formatted label while we keep
/// the raw key (filename or "ollama:<name>") for the actual removal logic.
struct ModelEntry {
    label: String,
    key: String,
}

impl std::fmt::Display for ModelEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

pub fn remove(names: Vec<String>, all: bool) -> Result<()> {
    let models_dir = crate::summary::models_dir();
    let mut cfg = crate::config::load().unwrap_or_default();

    let targets: Vec<String> = if all {
        collect_managed_targets(&models_dir, &cfg)
    } else if names.is_empty() {
        match interactive_select(&models_dir, &cfg)? {
            Some(t) => t,
            None => return Ok(()),
        }
    } else {
        names
    };

    if targets.is_empty() {
        println!("  No models to remove.");
        return Ok(());
    }

    let mut active_cleared = false;
    for target in &targets {
        active_cleared |= remove_one(target, &models_dir, &mut cfg)?;
    }

    crate::config::save(&cfg)?;

    if active_cleared {
        eprintln!(
            "\n  {} Active model cleared — run `primer model set` to configure a new one.",
            "⚠".yellow()
        );
    }

    Ok(())
}

fn collect_managed_targets(models_dir: &Path, cfg: &crate::config::Config) -> Vec<String> {
    let mut targets = Vec::new();

    if models_dir.exists() {
        let mut entries: Vec<_> = std::fs::read_dir(models_dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "gguf" || ext == "json")
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            targets.push(entry.file_name().to_string_lossy().into_owned());
        }
    }

    if cfg.ai.backend.as_deref() == Some("ollama")
        && let Some(model) = &cfg.ai.model
    {
        targets.push(format!("ollama:{}", model.to_string_lossy()));
    }

    targets
}

fn interactive_select(
    models_dir: &Path,
    cfg: &crate::config::Config,
) -> Result<Option<Vec<String>>> {
    let active_path = cfg
        .ai
        .model
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let backend = cfg.ai.backend.as_deref().unwrap_or("local");

    let mut entries: Vec<ModelEntry> = Vec::new();

    if models_dir.exists() {
        let mut files: Vec<_> = std::fs::read_dir(models_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "gguf" || ext == "json")
            })
            .collect();
        files.sort_by_key(|e| e.file_name());

        for entry in files {
            let path = entry.path();
            let key = entry.file_name().to_string_lossy().into_owned();
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let is_active =
                path.to_str().map(|s| s == active_path).unwrap_or(false) || key == active_path;
            let label = format!(
                "{:<52} {:.1} MB{}",
                key,
                size as f64 / (1024.0 * 1024.0),
                if is_active { "  *active*" } else { "" }
            );
            entries.push(ModelEntry { label, key });
        }
    }

    if backend == "ollama"
        && let Some(model) = &cfg.ai.model
    {
        let key = format!("ollama:{}", model.to_string_lossy());
        let label = format!("{:<52} backend only  *active*", key);
        entries.push(ModelEntry { label, key });
    }

    if entries.is_empty() {
        println!("  No models to remove.");
        return Ok(Some(vec![]));
    }

    entries.push(ModelEntry {
        label: "[ Remove all models ]".to_string(),
        key: "__ALL__".to_string(),
    });

    let choice = match inquire::Select::new("Select model to remove:", entries).prompt() {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };

    if choice.key == "__ALL__" {
        return Ok(Some(collect_managed_targets(models_dir, cfg)));
    }

    Ok(Some(vec![choice.key]))
}

/// Remove a single target. Returns true if the active model config was cleared.
fn remove_one(target: &str, models_dir: &Path, cfg: &mut crate::config::Config) -> Result<bool> {
    let mut active_cleared = false;

    if let Some(ollama_name) = target.strip_prefix("ollama:") {
        let is_active = cfg.ai.backend.as_deref() == Some("ollama")
            && cfg
                .ai
                .model
                .as_ref()
                .and_then(|p| p.to_str())
                .map(|s| s == ollama_name)
                .unwrap_or(false);
        if is_active {
            cfg.ai.backend = None;
            cfg.ai.model = None;
            active_cleared = true;
        }
        println!("  {} Unregistered ollama:{}", "✓".green(), ollama_name);
    } else {
        let path = if PathBuf::from(target).is_absolute() {
            PathBuf::from(target)
        } else {
            models_dir.join(target)
        };

        let is_managed = path.starts_with(models_dir);

        if is_managed && path.exists() {
            std::fs::remove_file(&path)?;
            println!("  {} Removed {}", "✓".green(), target);
        } else if !is_managed {
            println!(
                "  {} Unregistered {} (external file not deleted)",
                "✓".green(),
                target
            );
        } else {
            eprintln!("  {} Not found: {}", "⚠".yellow(), target);
        }

        let active = cfg
            .ai
            .model
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.to_string_lossy() == active
            || path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
                == active
        {
            cfg.ai.backend = None;
            cfg.ai.model = None;
            cfg.ai.tokenizer = None;
            active_cleared = true;
        }
    }

    Ok(active_cleared)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AiConfig, Config};

    fn make_cfg(backend: &str, model: &str) -> Config {
        Config {
            ai: AiConfig {
                backend: Some(backend.to_string()),
                model: Some(PathBuf::from(model)),
                tokenizer: None,
            },
            intercept_restore: false,
            direct_only: false,
            prompt_threshold: None,
        }
    }

    #[test]
    fn collect_managed_targets_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::default();
        let targets = collect_managed_targets(dir.path(), &cfg);
        assert!(targets.is_empty());
    }

    #[test]
    fn collect_managed_targets_includes_gguf_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("model.gguf"), b"").unwrap();
        std::fs::write(dir.path().join("tokenizer.json"), b"{}").unwrap();
        std::fs::write(dir.path().join("README.md"), b"").unwrap();
        let cfg = Config::default();
        let targets = collect_managed_targets(dir.path(), &cfg);
        assert!(targets.contains(&"model.gguf".to_string()));
        assert!(targets.contains(&"tokenizer.json".to_string()));
        assert!(!targets.contains(&"README.md".to_string()));
    }

    #[test]
    fn collect_managed_targets_includes_ollama_when_active() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = make_cfg("ollama", "llama3.2");
        let targets = collect_managed_targets(dir.path(), &cfg);
        assert!(targets.contains(&"ollama:llama3.2".to_string()));
    }

    #[test]
    fn remove_one_deletes_managed_file_and_clears_config() {
        let dir = tempfile::tempdir().unwrap();
        let model_path = dir.path().join("model.gguf");
        std::fs::write(&model_path, b"").unwrap();
        let mut cfg = make_cfg("local", model_path.to_str().unwrap());
        let cleared = remove_one("model.gguf", dir.path(), &mut cfg).unwrap();
        assert!(cleared);
        assert!(!model_path.exists());
        assert!(cfg.ai.model.is_none());
    }

    #[test]
    fn remove_one_ollama_clears_config_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = make_cfg("ollama", "llama3.2");
        let cleared = remove_one("ollama:llama3.2", dir.path(), &mut cfg).unwrap();
        assert!(cleared);
        assert!(cfg.ai.backend.is_none());
    }

    #[test]
    fn remove_one_nonactive_model_does_not_clear_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("other.gguf"), b"").unwrap();
        let active = dir
            .path()
            .join("active.gguf")
            .to_string_lossy()
            .into_owned();
        let mut cfg = make_cfg("local", &active);
        let cleared = remove_one("other.gguf", dir.path(), &mut cfg).unwrap();
        assert!(!cleared);
        assert!(cfg.ai.model.is_some());
    }

    #[test]
    fn remove_all_removes_all_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.gguf"), b"").unwrap();
        std::fs::write(dir.path().join("b.gguf"), b"").unwrap();
        let mut cfg = Config::default();
        let targets = collect_managed_targets(dir.path(), &cfg);
        assert_eq!(targets.len(), 2);
        for t in &targets {
            remove_one(t, dir.path(), &mut cfg).unwrap();
        }
        assert!(!dir.path().join("a.gguf").exists());
        assert!(!dir.path().join("b.gguf").exists());
    }
}
