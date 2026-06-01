use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::Result;
use colored::Colorize;
use notify::{Event, EventKind, RecursiveMode, Watcher};

use crate::manifest;

const WATCHED_MANIFESTS: &[&str] = &[
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "go.mod",
    "Cargo.toml",
];

const DEBOUNCE: Duration = Duration::from_millis(500);

pub async fn run(directory: Option<PathBuf>, scan_on_start: bool) -> Result<()> {
    let dir =
        directory.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let watch_paths: Vec<PathBuf> = WATCHED_MANIFESTS
        .iter()
        .map(|name| dir.join(name))
        .filter(|p| p.exists())
        .collect();

    if watch_paths.is_empty() {
        eprintln!(
            "  {} No watched manifests found in {}",
            "⚠".yellow(),
            dir.display()
        );
        eprintln!("  Watching for: {}", WATCHED_MANIFESTS.join(", "));
    }

    if scan_on_start {
        for path in &watch_paths {
            scan_file(path).await;
        }
    }

    println!(
        "  {} Watching {} for manifest changes (Ctrl+C to exit) …",
        "◉".green(),
        dir.display()
    );

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

    let mut watcher = notify::recommended_watcher(tx)?;
    watcher.watch(&dir, RecursiveMode::NonRecursive)?;

    let mut last_scan: std::collections::HashMap<PathBuf, Instant> =
        std::collections::HashMap::new();

    loop {
        match rx.recv() {
            Ok(Ok(event)) => {
                if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    continue;
                }

                for path in event.paths {
                    let filename = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default();

                    if !WATCHED_MANIFESTS.contains(&filename) {
                        continue;
                    }

                    // Debounce: skip if we scanned this file within DEBOUNCE window.
                    let now = Instant::now();
                    if let Some(&last) = last_scan.get(&path)
                        && now.duration_since(last) < DEBOUNCE
                    {
                        continue;
                    }
                    last_scan.insert(path.clone(), now);

                    println!();
                    println!("  {} {} changed — scanning …", "→".cyan(), filename);
                    scan_file(&path).await;
                }
            }
            Ok(Err(e)) => eprintln!("  {} watcher error: {}", "⚠".yellow(), e),
            Err(_) => break, // channel closed
        }
    }

    Ok(())
}

async fn scan_file(path: &Path) {
    let filename = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return,
    };

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let is_lockfile = crate::lockfile::LOCKFILE_NAMES.contains(&filename);

    let eco = if is_lockfile {
        crate::lockfile::ecosystem_from_lockfile(filename)
    } else {
        manifest::ecosystem_from_filename(filename)
    };

    let eco = match eco {
        Some(e) => e,
        None => {
            eprintln!(
                "  {} Could not infer ecosystem from '{}'",
                "⚠".yellow(),
                filename
            );
            return;
        }
    };

    let packages: Vec<(String, Option<String>)> = if is_lockfile {
        crate::lockfile::parse_lockfile(filename, &content)
            .into_iter()
            .map(|p| (p.name, Some(p.version)))
            .collect()
    } else {
        manifest::parse_file(filename, &content)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect()
    };

    if packages.is_empty() {
        println!("  {} No packages found in {}", "·".dimmed(), filename);
        return;
    }

    println!(
        "  Scanning {} ({}) — {} packages …",
        filename,
        eco,
        packages.len()
    );

    let force = crate::prompt::force_flag();
    let mut any_blocked = false;

    for (name, version) in &packages {
        if crate::allowlist::is_allowed(name, eco) {
            continue;
        }
        match crate::engine::osv::query(name, eco, version.as_deref(), false).await {
            Ok(vulns) if !vulns.is_empty() => {
                match crate::prompt::evaluate(name, eco, &vulns, force) {
                    crate::prompt::Decision::Abort => {
                        any_blocked = true;
                    }
                    crate::prompt::Decision::Proceed => {}
                }
            }
            Ok(_) => {}
            Err(e) => eprintln!("  {} {} scan skipped: {}", "⚠".yellow(), name, e),
        }
    }

    if !any_blocked {
        println!(
            "  {} Scan complete — {} clean.",
            "✓".green(),
            packages.len()
        );
    }
}
