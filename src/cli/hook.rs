#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use colored::Colorize;

use crate::engine::osv;
use crate::manifest::{self, MONITORED_MANIFESTS};
use crate::prompt;

// The hook script delegates all logic back to `primer hook check`.
const HOOK_SCRIPT: &str = "#!/bin/sh
# Rust projects: enforce formatting and lints before commit
if [ -f Cargo.toml ]; then
  # Stash unstaged changes so fmt/clippy see only what is being committed.
  git stash --quiet --keep-index --include-untracked
  cargo fmt --check
  FMT=$?
  git stash pop --quiet
  [ $FMT -eq 0 ] || { echo 'Run cargo fmt and stage the result.'; exit 1; }
  cargo clippy -- -D warnings || exit 1
fi
exec primer hook check
";

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

pub fn install() -> Result<()> {
    let hook_path = git_hooks_dir()?.join("pre-commit");

    std::fs::write(&hook_path, HOOK_SCRIPT)
        .with_context(|| format!("Failed to write hook to {}", hook_path.display()))?;

    // Make executable (Unix only — Git on Windows handles this via core.fileMode)
    #[cfg(unix)]
    std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("Failed to set executable bit on {}", hook_path.display()))?;

    println!("✓ pre-commit hook installed at {}", hook_path.display());
    println!("  Vulnerable package additions will be blocked before commit.");
    Ok(())
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

pub async fn check() -> Result<()> {
    // Warn and block if .primer/ policy files are gitignored (they must be committed).
    if check_primer_files_gitignored()? {
        bail!(
            "primer policy files are gitignored and will not apply in CI. \
            Update .gitignore or run `primer migrate`."
        );
    }

    let new_packages = collect_new_packages()?;

    if new_packages.is_empty() {
        return Ok(());
    }

    let mut blocked = false;

    for (name, version, ecosystem) in &new_packages {
        println!("primer: scanning {} ({}) …", name.bold(), ecosystem);

        match osv::query(name, ecosystem, version.as_deref(), false).await {
            Ok(vulns) if vulns.is_empty() => {
                println!("  {} No vulnerabilities found.", "✓".green());
            }
            Ok(vulns) => match prompt::evaluate(name, ecosystem, &vulns, false) {
                prompt::Decision::Abort => {
                    blocked = true;
                }
                prompt::Decision::Proceed => {}
            },
            Err(e) => {
                eprintln!("  {} Scan skipped: {} (proceeding)", "⚠".yellow(), e);
            }
        }
    }

    if blocked {
        bail!("Commit blocked: Critical/High vulnerabilities found in staged packages.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// .primer/ gitignore check
// ---------------------------------------------------------------------------

/// Returns true (and prints warnings) if any .primer/ policy files are gitignored.
/// Only checks when .primer/ directory exists.
fn check_primer_files_gitignored() -> Result<bool> {
    if !std::path::Path::new(".primer").is_dir() {
        return Ok(false);
    }
    let files = [".primer/policy.toml", ".primer/ignore"];
    let mut any_ignored = false;
    for file in &files {
        let result = std::process::Command::new("git")
            .args(["check-ignore", "-v", file])
            .output();
        if let Ok(out) = result
            && out.status.success()
        {
            eprintln!(
                "primer: {} is gitignored — policy will not apply in CI.",
                file
            );
            any_ignored = true;
        }
    }
    Ok(any_ignored)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run `git diff --cached` for each monitored manifest and collect new packages.
fn collect_new_packages() -> Result<Vec<(String, Option<String>, &'static str)>> {
    collect_new_packages_in(None)
}

pub(crate) fn collect_new_packages_in(
    workdir: Option<&std::path::Path>,
) -> Result<Vec<(String, Option<String>, &'static str)>> {
    let mut all = Vec::new();
    for manifest in MONITORED_MANIFESTS {
        let diff = run_git_diff_in(workdir, manifest)?;
        if diff.is_empty() {
            continue;
        }
        for pkg in manifest::parse_diff(manifest, &diff) {
            all.push((pkg.name, pkg.version, pkg.ecosystem));
        }
    }
    Ok(all)
}

fn run_git_diff_in(workdir: Option<&std::path::Path>, filename: &str) -> Result<String> {
    let mut cmd = Command::new("git");
    if let Some(dir) = workdir {
        cmd.current_dir(dir);
    }
    let output = cmd
        .args(["diff", "--cached", "--unified=0", "--", filename])
        .output()
        .with_context(|| "Failed to run git diff — is this a git repository?")?;

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn git_hooks_dir() -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .context("Failed to locate .git directory — is this a git repository?")?;

    if !output.status.success() {
        bail!("Not inside a git repository.");
    }

    let git_dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(git_dir).join("hooks"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn init_temp_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("git init");
        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir.path())
            .output()
            .expect("git config email");
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir.path())
            .output()
            .expect("git config name");
        dir
    }

    #[test]
    fn detects_new_requirement_in_staged_file() {
        let dir = init_temp_repo();
        let req = dir.path().join("requirements.txt");
        fs::write(&req, "pillow==9.0.0\n").unwrap();

        Command::new("git")
            .args(["add", "requirements.txt"])
            .current_dir(dir.path())
            .output()
            .expect("git add");

        let pkgs = collect_new_packages_in(Some(dir.path())).unwrap();
        assert!(
            pkgs.iter()
                .any(|(name, _, eco)| name == "pillow" && *eco == "PyPI"),
            "expected pillow/PyPI in {:?}",
            pkgs
        );
    }

    #[test]
    fn no_packages_when_nothing_staged() {
        let dir = init_temp_repo();
        let pkgs = collect_new_packages_in(Some(dir.path())).unwrap();
        assert!(pkgs.is_empty());
    }
}
