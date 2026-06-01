use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

pub fn run() -> Result<()> {
    let cwd = std::env::current_dir()?;
    run_in(&cwd)
}

pub(crate) fn run_in(cwd: &Path) -> Result<()> {
    // Files that live in the project root → their new name inside .primer/
    const MIGRATIONS: &[(&str, &str)] = &[
        (".primer-ignore", "ignore"),
        (".primer-policy.toml", "policy.toml"),
        ("primer-report.json", "report.json"),
    ];

    let has_old = MIGRATIONS.iter().any(|(old, _)| cwd.join(old).exists());
    if !has_old {
        println!(
            "Nothing to migrate — no legacy primer files found in {}.",
            cwd.display()
        );
        return Ok(());
    }

    println!("primer migrate\n");

    let primer_dir = cwd.join(".primer");
    if !primer_dir.exists() {
        fs::create_dir(&primer_dir).context("could not create .primer/")?;
        println!("  ✓ Created .primer/");
    }

    let in_git = is_git_repo(cwd);

    for (old_name, new_name) in MIGRATIONS {
        let old_path = cwd.join(old_name);
        let new_path = primer_dir.join(new_name);
        if !old_path.exists() {
            continue;
        }
        if new_path.exists() {
            println!(
                "  · .primer/{} already exists, skipping {}",
                new_name, old_name
            );
            continue;
        }
        move_file(cwd, &old_path, &new_path, in_git)
            .with_context(|| format!("migrating {}", old_name))?;
        println!("  ✓ {} → .primer/{}", old_name, new_name);
    }

    update_gitignore(cwd)?;
    check_workflow_paths(cwd);

    println!();
    println!("Migration complete.");
    println!("  Commit .primer/ and the updated .gitignore to share policy with your team.");
    Ok(())
}

fn is_git_repo(dir: &Path) -> bool {
    Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn move_file(cwd: &Path, from: &Path, to: &Path, git: bool) -> Result<()> {
    if git {
        let ok = Command::new("git")
            .args(["mv", from.to_str().unwrap_or(""), to.to_str().unwrap_or("")])
            .current_dir(cwd)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Ok(());
        }
        // git mv failed (file may be untracked) — fall through to fs::rename
    }
    fs::rename(from, to)
        .with_context(|| format!("could not move {} to {}", from.display(), to.display()))
}

fn update_gitignore(cwd: &Path) -> Result<()> {
    let gi_path = cwd.join(".gitignore");
    let contents = if gi_path.exists() {
        fs::read_to_string(&gi_path)?
    } else {
        String::new()
    };

    let mut modified = false;
    let mut new_lines: Vec<String> = Vec::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "primer-report.json" {
            new_lines.push(".primer/report.json".to_string());
            modified = true;
        } else if trimmed == ".primer/" || trimmed == ".primer" {
            // .primer/ must NOT be gitignored — policy files need to be committed.
            println!(
                "  ⚠  Removed .primer/ from .gitignore — .primer/policy.toml and \
                .primer/ignore must be committed"
            );
            modified = true;
            // Drop this line.
        } else {
            new_lines.push(line.to_string());
        }
    }

    // Ensure .primer/report.json appears in .gitignore.
    let report_entry = ".primer/report.json";
    if !new_lines.iter().any(|l| l.trim() == report_entry) {
        new_lines.push(report_entry.to_string());
        modified = true;
    }

    if modified {
        let mut out = new_lines.join("\n");
        if !out.ends_with('\n') {
            out.push('\n');
        }
        fs::write(&gi_path, out)?;
        println!("  ✓ Updated .gitignore");
    }

    Ok(())
}

fn check_workflow_paths(cwd: &Path) {
    let workflows_dir = cwd.join(".github").join("workflows");
    if !workflows_dir.is_dir() {
        return;
    }
    const STALE: &[&str] = &[
        "primer-report.json",
        ".primer-ignore",
        ".primer-policy.toml",
    ];
    let Ok(entries) = fs::read_dir(&workflows_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .map(|e| e == "yml" || e == "yaml")
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for pattern in STALE {
            if text.contains(pattern) {
                println!(
                    "  ⚠  {} references {} — update to use .primer/ paths",
                    path.file_name().unwrap_or_default().to_string_lossy(),
                    pattern
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn nothing_to_migrate_when_dir_is_empty() {
        let dir = tempdir().unwrap();
        let result = run_in(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn migrates_primer_ignore_to_primer_dir() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".primer-ignore"), "requests\n").unwrap();
        run_in(dir.path()).unwrap();
        assert!(dir.path().join(".primer").join("ignore").exists());
        assert!(!dir.path().join(".primer-ignore").exists());
    }

    #[test]
    fn migrates_policy_toml_to_primer_dir() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(".primer-policy.toml"),
            "[policy]\nthreshold = \"high\"\n",
        )
        .unwrap();
        run_in(dir.path()).unwrap();
        assert!(dir.path().join(".primer").join("policy.toml").exists());
        assert!(!dir.path().join(".primer-policy.toml").exists());
    }

    #[test]
    fn migrates_report_json_to_primer_dir() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("primer-report.json"), "{}").unwrap();
        run_in(dir.path()).unwrap();
        assert!(dir.path().join(".primer").join("report.json").exists());
        assert!(!dir.path().join("primer-report.json").exists());
    }

    #[test]
    fn gitignore_updated_to_use_primer_dir_path() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".primer-ignore"), "requests\n").unwrap();
        fs::write(dir.path().join(".gitignore"), "primer-report.json\n").unwrap();
        run_in(dir.path()).unwrap();
        let gi = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(gi.contains(".primer/report.json"));
        assert!(!gi.contains("primer-report.json\n"));
    }

    #[test]
    fn skips_already_migrated_files() {
        let dir = tempdir().unwrap();
        let primer_dir = dir.path().join(".primer");
        fs::create_dir(&primer_dir).unwrap();
        // Both old and new exist — new should be kept, old should NOT be moved again.
        fs::write(dir.path().join(".primer-ignore"), "requests\n").unwrap();
        fs::write(primer_dir.join("ignore"), "flask\n").unwrap();
        run_in(dir.path()).unwrap();
        // New file content unchanged.
        let contents = fs::read_to_string(primer_dir.join("ignore")).unwrap();
        assert_eq!(contents, "flask\n");
    }
}
