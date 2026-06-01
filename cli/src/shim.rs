use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use colored::Colorize;

use crate::engine::osv;

// ---------------------------------------------------------------------------
// Package manager detection
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Clone)]
pub enum PackageManager {
    Pip,
    Uv,
    Poetry,
    Npm,
    Yarn,
    Pnpm,
    Go,
    Cargo,
}

impl PackageManager {
    /// Detect which PM we are masquerading as from argv[0].
    pub fn from_argv0(argv0: &str) -> Option<Self> {
        let name = Path::new(argv0)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(argv0);

        match name {
            "pip" | "pip3" => Some(Self::Pip),
            "uv" => Some(Self::Uv),
            "poetry" => Some(Self::Poetry),
            "npm" => Some(Self::Npm),
            "yarn" => Some(Self::Yarn),
            "pnpm" => Some(Self::Pnpm),
            "go" => Some(Self::Go),
            "cargo" => Some(Self::Cargo),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Pip => "pip",
            Self::Uv => "uv",
            Self::Poetry => "poetry",
            Self::Npm => "npm",
            Self::Yarn => "yarn",
            Self::Pnpm => "pnpm",
            Self::Go => "go",
            Self::Cargo => "cargo",
        }
    }

    pub fn ecosystem(&self) -> &'static str {
        match self {
            Self::Pip | Self::Uv | Self::Poetry => "PyPI",
            Self::Npm | Self::Yarn | Self::Pnpm => "npm",
            Self::Go => "Go",
            Self::Cargo => "crates.io",
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::Pip,
            Self::Uv,
            Self::Poetry,
            Self::Npm,
            Self::Yarn,
            Self::Pnpm,
            Self::Go,
            Self::Cargo,
        ]
    }
}

// ---------------------------------------------------------------------------
// Package argument extraction
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub struct PackageArg {
    pub name: String,
    pub version: Option<String>,
}

/// Returns the packages to scan if the args are an install command,
/// or None if the command should pass through immediately (e.g. `pip list`).
pub fn extract_packages(pm: &PackageManager, args: &[String]) -> Option<Vec<PackageArg>> {
    let subcommand = args.first().map(String::as_str)?;

    let is_install = match pm {
        PackageManager::Pip | PackageManager::Uv => subcommand == "install",
        PackageManager::Poetry => subcommand == "add",
        PackageManager::Npm => matches!(subcommand, "install" | "i" | "add"),
        PackageManager::Yarn => subcommand == "add",
        PackageManager::Pnpm => matches!(subcommand, "add" | "install"),
        PackageManager::Go => subcommand == "get",
        PackageManager::Cargo => subcommand == "add",
    };

    if !is_install {
        return None;
    }

    let packages: Vec<PackageArg> = args[1..]
        .iter()
        .filter(|a| !a.starts_with('-'))
        // Skip manifest files passed via -r / --requirements
        .filter(|a| !a.ends_with(".txt") && !a.ends_with(".toml") && !a.ends_with(".json"))
        .map(|spec| parse_package_spec(pm, spec))
        .collect();

    if packages.is_empty() {
        None
    } else {
        Some(packages)
    }
}

fn parse_package_spec(pm: &PackageManager, spec: &str) -> PackageArg {
    match pm {
        PackageManager::Npm
        | PackageManager::Yarn
        | PackageManager::Pnpm
        | PackageManager::Go
        | PackageManager::Cargo => {
            // spec formats: lodash@4.17.21, golang.org/x/net@v0.1.0, serde@1.0
            if let Some((name, ver)) = spec.split_once('@') {
                PackageArg {
                    name: name.to_owned(),
                    version: Some(ver.to_owned()),
                }
            } else {
                PackageArg {
                    name: spec.to_owned(),
                    version: None,
                }
            }
        }
        PackageManager::Pip | PackageManager::Uv | PackageManager::Poetry => {
            // spec formats: requests, requests==2.28.0, requests>=2.0, requests[security]
            let name_end = spec.find(['=', '>', '<', '!', '[']).unwrap_or(spec.len());
            let name = spec[..name_end].trim().to_owned();
            let version = spec.find("==").map(|i| {
                spec[i + 2..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_owned()
            });
            PackageArg { name, version }
        }
    }
}

// ---------------------------------------------------------------------------
// Real binary lookup
// ---------------------------------------------------------------------------

fn primer_bin_dir() -> PathBuf {
    crate::home::primer_bin_dir()
}

/// Find the real PM binary, excluding ~/.primer/bin to avoid loops.
pub fn find_real_binary(name: &str) -> Option<PathBuf> {
    let shim_dir = primer_bin_dir();
    let path_var = env::var_os("PATH")?;

    for dir in env::split_paths(&path_var) {
        if dir == shim_dir {
            continue;
        }
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        // On Windows, also try name.exe and skip .cmd wrappers in primer's own bin dir.
        #[cfg(windows)]
        {
            let exe_candidate = dir.join(format!("{}.exe", name));
            if exe_candidate.is_file() {
                return Some(exe_candidate);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Exec / spawn real binary
// ---------------------------------------------------------------------------

/// Replace the current process with the real binary (Unix exec semantics).
/// Returns an error only if exec itself fails (e.g. binary not found).
#[cfg(unix)]
pub fn exec_real_binary(binary: &Path, args: &[String]) -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(binary).args(args).exec();
    anyhow::Error::from(err)
}

#[cfg(not(unix))]
pub fn exec_real_binary(binary: &Path, args: &[String]) -> anyhow::Error {
    match std::process::Command::new(binary).args(args).status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => anyhow::Error::from(e),
    }
}

/// Spawn the real binary as a child process, wait for completion, and return
/// its exit code.  Used when we need to observe the filesystem state *after*
/// the PM runs (transitive-scan diff path).
pub fn run_child_exit_code(binary: &Path, args: &[String]) -> anyhow::Result<i32> {
    Ok(std::process::Command::new(binary)
        .args(args)
        .status()?
        .code()
        .unwrap_or(1))
}

// ---------------------------------------------------------------------------
// Bare-restore detection
// ---------------------------------------------------------------------------

/// True when the trailing args contain no explicit package names (only flags or
/// manifest file arguments).
fn has_no_pkg_args(rest: &[String]) -> bool {
    !rest.iter().any(|a| {
        !a.starts_with('-')
            && !a.ends_with(".txt")
            && !a.ends_with(".toml")
            && !a.ends_with(".json")
    })
}

/// Returns the primary manifest filename to scan when `args` describe a bare
/// restore command (install-all-deps-from-lockfile, no explicit packages).
/// Returns `None` for commands that should pass through unchanged.
pub fn is_bare_restore(pm: &PackageManager, args: &[String]) -> Option<&'static str> {
    let subcommand = args.first().map(String::as_str).unwrap_or("");

    match pm {
        PackageManager::Pip => {
            if subcommand != "install" {
                return None;
            }
            has_no_pkg_args(&args[1..]).then_some("requirements.txt")
        }
        PackageManager::Uv => {
            if subcommand != "sync" && subcommand != "install" {
                return None;
            }
            has_no_pkg_args(&args[1..]).then_some("requirements.txt")
        }
        // `poetry install` restores from pyproject.toml (unlike `poetry add`)
        PackageManager::Poetry => {
            if subcommand == "install" {
                Some("pyproject.toml")
            } else {
                None
            }
        }
        PackageManager::Npm => {
            if !matches!(subcommand, "install" | "i") {
                return None;
            }
            has_no_pkg_args(&args[1..]).then_some("package.json")
        }
        // bare `yarn` (no subcommand) or `yarn install` always installs from package.json
        PackageManager::Yarn => {
            if subcommand.is_empty() || subcommand == "install" {
                Some("package.json")
            } else {
                None
            }
        }
        PackageManager::Pnpm => {
            if subcommand != "install" {
                return None;
            }
            has_no_pkg_args(&args[1..]).then_some("package.json")
        }
        PackageManager::Go => {
            if subcommand == "mod" && args.get(1).map(String::as_str) == Some("download") {
                Some("go.mod")
            } else {
                None
            }
        }
        // `cargo build` / `cargo fetch` / `cargo check` restore from Cargo.toml
        PackageManager::Cargo => {
            if matches!(subcommand, "build" | "fetch" | "check") {
                Some("Cargo.toml")
            } else {
                None
            }
        }
    }
}

/// Lockfile filenames to try for a given manifest, in preference order.
pub fn lockfile_candidates(manifest: &str) -> &'static [&'static str] {
    match manifest {
        "requirements.txt" | "pyproject.toml" => &["uv.lock", "poetry.lock"],
        "package.json" => &["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "go.mod" => &["go.sum"],
        "Cargo.toml" => &["Cargo.lock"],
        _ => &[],
    }
}

/// Scan a manifest file found in the current directory.
/// When `direct_only` is false (default), also scans transitive deps from the
/// associated lockfile if one exists alongside the manifest.
/// Silently skips if the manifest does not exist or is empty.
async fn intercept_manifest(pm: &PackageManager, primary: &'static str, direct_only: bool) {
    // Resolve the actual manifest path (with Python fallback).
    let (manifest_path, manifest_name): (std::path::PathBuf, &str) = {
        let p = std::path::Path::new(primary);
        if p.exists() {
            (p.to_owned(), primary)
        } else if primary == "requirements.txt" {
            let fallback = std::path::Path::new("pyproject.toml");
            if fallback.exists() {
                (fallback.to_owned(), "pyproject.toml")
            } else {
                return;
            }
        } else {
            return;
        }
    };

    let manifest_content = match std::fs::read_to_string(&manifest_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let direct_pkgs = crate::manifest::parse_file(manifest_name, &manifest_content);
    if direct_pkgs.is_empty() {
        return;
    }

    // Build scan list: lockfile (transitive) when available and allowed,
    // otherwise fall back to manifest packages only.
    let scan_list: Vec<(String, Option<String>)>;
    let direct_count: usize;
    let transitive_count: usize;

    let lockfile_data = if !direct_only {
        lockfile_candidates(manifest_name)
            .iter()
            .find_map(|&lf| {
                std::fs::read_to_string(lf)
                    .ok()
                    .map(|content| (lf, content))
            })
            .and_then(|(lf_name, lf_content)| {
                let pkgs = crate::lockfile::parse_lockfile(lf_name, &lf_content);
                if pkgs.is_empty() { None } else { Some(pkgs) }
            })
    } else {
        None
    };

    if let Some(lf_pkgs) = lockfile_data {
        // Direct names for grouping (manifest declares these explicitly).
        let direct_names: std::collections::HashSet<&str> =
            direct_pkgs.iter().map(|p| p.name.as_str()).collect();

        // Use lockfile version for direct packages when available.
        let direct: Vec<(String, Option<String>)> = direct_pkgs
            .iter()
            .map(|p| {
                let ver = lf_pkgs
                    .iter()
                    .find(|lp| lp.name == p.name)
                    .map(|lp| lp.version.clone())
                    .or_else(|| p.version.clone());
                (p.name.clone(), ver)
            })
            .collect();

        let transitive: Vec<(String, Option<String>)> = lf_pkgs
            .iter()
            .filter(|p| !direct_names.contains(p.name.as_str()))
            .map(|p| (p.name.clone(), Some(p.version.clone())))
            .collect();

        direct_count = direct.len();
        transitive_count = transitive.len();
        scan_list = direct.into_iter().chain(transitive).collect();
    } else {
        direct_count = direct_pkgs.len();
        transitive_count = 0;
        scan_list = direct_pkgs
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
    }

    if scan_list.is_empty() {
        return;
    }

    if transitive_count > 0 {
        eprintln!(
            "  primer: scanning {} — {} direct + {} transitive packages",
            manifest_name, direct_count, transitive_count
        );
    } else {
        eprintln!(
            "  primer: scanning {} ({} packages)",
            manifest_name, direct_count
        );
    }

    let force = crate::prompt::force_flag();

    for (name, version) in &scan_list {
        if crate::allowlist::is_allowed(name, pm.ecosystem()) {
            continue;
        }
        match osv::query(name, pm.ecosystem(), version.as_deref(), false).await {
            Ok(vulns) if !vulns.is_empty() => {
                match crate::prompt::evaluate(name, pm.ecosystem(), &vulns, force) {
                    crate::prompt::Decision::Abort => std::process::exit(1),
                    crate::prompt::Decision::Proceed => {}
                }
            }
            Ok(_) => {}
            Err(e) => eprintln!("⚠  primer: scan skipped ({}) — proceeding", e),
        }
    }
}

// ---------------------------------------------------------------------------
// Transitive dependency scan (post-install lockfile diff)
// ---------------------------------------------------------------------------

/// The lockfile that this PM writes on install (used for post-install diffing).
pub fn canonical_lockfile(pm: &PackageManager) -> Option<&'static str> {
    match pm {
        PackageManager::Npm => Some("package-lock.json"),
        PackageManager::Yarn => Some("yarn.lock"),
        PackageManager::Pnpm => Some("pnpm-lock.yaml"),
        PackageManager::Uv => Some("uv.lock"),
        PackageManager::Poetry => Some("poetry.lock"),
        PackageManager::Go => Some("go.sum"),
        PackageManager::Cargo => Some("Cargo.lock"),
        PackageManager::Pip => None, // pip does not write a lockfile
    }
}

/// Read the canonical lockfile for this PM from the current directory.
/// Returns `None` if the file does not exist or cannot be read.
fn lockfile_snapshot(pm: &PackageManager) -> Option<(String, String)> {
    let name = canonical_lockfile(pm)?;
    let content = std::fs::read_to_string(name).ok()?;
    Some((name.to_owned(), content))
}

/// Compare the current lockfile to `before_snapshot`, scan any packages that
/// were added by the install, and report findings.  Exits 1 if any finding
/// is blocked — install already happened, but the signal is still useful for CI.
async fn scan_transitive_diff(pm: &PackageManager, before: Option<(String, String)>) {
    let lf_name = match canonical_lockfile(pm) {
        Some(n) => n,
        None => return,
    };

    let new_content = match std::fs::read_to_string(lf_name) {
        Ok(c) => c,
        Err(_) => return,
    };

    let new_pkgs = crate::lockfile::parse_lockfile(lf_name, &new_content);
    if new_pkgs.is_empty() {
        return;
    }

    // Packages present in the new lockfile but absent (or at a different
    // version) in the pre-install snapshot are the newly added transitives.
    let added: Vec<_> = if let Some((_, old_content)) = before {
        let old_keys: std::collections::HashSet<String> =
            crate::lockfile::parse_lockfile(lf_name, &old_content)
                .into_iter()
                .map(|p| format!("{}@{}", p.name, p.version))
                .collect();
        new_pkgs
            .into_iter()
            .filter(|p| !old_keys.contains(&format!("{}@{}", p.name, p.version)))
            .collect()
    } else {
        // No prior lockfile — every entry is newly added
        new_pkgs
    };

    if added.is_empty() {
        return;
    }

    eprintln!(
        "  primer: scanning {} new transitive packages …",
        added.len()
    );

    let mut any_blocked = false;

    for pkg in &added {
        if crate::allowlist::is_allowed(&pkg.name, pm.ecosystem()) {
            continue;
        }
        match osv::query(&pkg.name, pm.ecosystem(), Some(&pkg.version), false).await {
            Ok(vulns) if !vulns.is_empty() => {
                if crate::prompt::report_post_install(&pkg.name, pm.ecosystem(), &vulns) {
                    any_blocked = true;
                }
            }
            Ok(_) => {}
            Err(e) => eprintln!("⚠  primer: scan skipped ({}) — proceeding", e),
        }
    }

    if any_blocked {
        std::process::exit(1);
    } else {
        eprintln!("  ✓ transitive scan complete — found 0 vulnerabilities.");
    }
}

// ---------------------------------------------------------------------------
// Shim entry point
// ---------------------------------------------------------------------------

pub async fn run(pm: PackageManager, args: Vec<String>) -> Result<()> {
    let real_bin = find_real_binary(pm.name())
        .ok_or_else(|| anyhow::anyhow!("Could not find real '{}' binary in PATH", pm.name()))?;

    let cfg = crate::config::load().unwrap_or_default();

    if let Some(packages) = extract_packages(&pm, &args) {
        let force = crate::prompt::force_flag();

        // Pre-install: scan explicitly named packages.
        for pkg in &packages {
            if crate::allowlist::is_allowed(&pkg.name, pm.ecosystem()) {
                continue;
            }
            match osv::query(&pkg.name, pm.ecosystem(), pkg.version.as_deref(), false).await {
                Ok(vulns) if !vulns.is_empty() => {
                    match crate::prompt::evaluate(&pkg.name, pm.ecosystem(), &vulns, force) {
                        crate::prompt::Decision::Abort => std::process::exit(1),
                        crate::prompt::Decision::Proceed => {}
                    }
                }
                Ok(_) => {
                    eprintln!("  {} {}: found 0 vulnerabilities.", "✓".green(), pkg.name);
                }
                Err(e) => eprintln!("⚠  primer: scan skipped ({}) — proceeding", e),
            }
        }

        // Transitive scan: snapshot lockfile → run PM → diff → scan new entries.
        if !cfg.direct_only {
            let snapshot = lockfile_snapshot(&pm);
            let exit_code = run_child_exit_code(&real_bin, &args)?;
            if exit_code == 0 {
                scan_transitive_diff(&pm, snapshot).await;
            }
            std::process::exit(exit_code);
        }
    } else if cfg.intercept_restore
        && let Some(manifest) = is_bare_restore(&pm, &args)
    {
        intercept_manifest(&pm, manifest, cfg.direct_only).await;
    }

    // Fast path: exec replaces the current process (no wrapper overhead).
    bail!(exec_real_binary(&real_bin, &args))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- from_argv0 ---

    #[test]
    fn detects_pip_from_full_path() {
        assert_eq!(
            PackageManager::from_argv0("/usr/bin/pip"),
            Some(PackageManager::Pip)
        );
    }

    #[test]
    fn detects_pip3() {
        assert_eq!(
            PackageManager::from_argv0("pip3"),
            Some(PackageManager::Pip)
        );
    }

    #[test]
    fn detects_npm() {
        assert_eq!(PackageManager::from_argv0("npm"), Some(PackageManager::Npm));
    }

    #[test]
    fn detects_cargo() {
        assert_eq!(
            PackageManager::from_argv0("/Users/user/.cargo/bin/cargo"),
            Some(PackageManager::Cargo)
        );
    }

    #[test]
    fn returns_none_for_primer() {
        assert!(PackageManager::from_argv0("primer").is_none());
    }

    #[test]
    fn returns_none_for_unknown() {
        assert!(PackageManager::from_argv0("ruby").is_none());
    }

    // --- extract_packages ---

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn pip_install_single_package() {
        let pkgs = extract_packages(&PackageManager::Pip, &args("install requests")).unwrap();
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, None);
    }

    #[test]
    fn pip_install_with_version() {
        let pkgs =
            extract_packages(&PackageManager::Pip, &args("install requests==2.28.0")).unwrap();
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, Some("2.28.0".into()));
    }

    #[test]
    fn pip_list_passes_through() {
        assert!(extract_packages(&PackageManager::Pip, &args("list")).is_none());
    }

    #[test]
    fn pip_install_flags_only_passes_through() {
        assert!(
            extract_packages(&PackageManager::Pip, &args("install -r requirements.txt")).is_none()
        );
    }

    #[test]
    fn npm_install_with_at_version() {
        let pkgs = extract_packages(&PackageManager::Npm, &args("install lodash@4.17.21")).unwrap();
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, Some("4.17.21".into()));
    }

    #[test]
    fn npm_alias_i() {
        let pkgs = extract_packages(&PackageManager::Npm, &args("i express")).unwrap();
        assert_eq!(pkgs[0].name, "express");
    }

    #[test]
    fn npm_run_passes_through() {
        assert!(extract_packages(&PackageManager::Npm, &args("run build")).is_none());
    }

    #[test]
    fn cargo_add_with_version() {
        let pkgs = extract_packages(&PackageManager::Cargo, &args("add serde@1.0")).unwrap();
        assert_eq!(pkgs[0].name, "serde");
        assert_eq!(pkgs[0].version, Some("1.0".into()));
    }

    #[test]
    fn go_get_module() {
        let pkgs = extract_packages(&PackageManager::Go, &args("get golang.org/x/net")).unwrap();
        assert_eq!(pkgs[0].name, "golang.org/x/net");
    }

    #[test]
    fn go_mod_download_passes_through() {
        assert!(extract_packages(&PackageManager::Go, &args("mod download")).is_none());
    }

    #[test]
    fn pip_install_multiple_packages() {
        let pkgs = extract_packages(&PackageManager::Pip, &args("install requests flask")).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[1].name, "flask");
    }

    // --- is_bare_restore ---

    #[test]
    fn pip_bare_install_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Pip, &args("install")),
            Some("requirements.txt")
        );
    }

    #[test]
    fn pip_install_with_package_not_bare_restore() {
        assert!(is_bare_restore(&PackageManager::Pip, &args("install requests")).is_none());
    }

    #[test]
    fn pip_install_flags_only_is_bare_restore() {
        // `-q` is a flag, not a package
        assert_eq!(
            is_bare_restore(&PackageManager::Pip, &args("install -q")),
            Some("requirements.txt")
        );
    }

    #[test]
    fn pip_list_not_bare_restore() {
        assert!(is_bare_restore(&PackageManager::Pip, &args("list")).is_none());
    }

    #[test]
    fn uv_sync_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Uv, &args("sync")),
            Some("requirements.txt")
        );
    }

    #[test]
    fn uv_install_bare_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Uv, &args("install")),
            Some("requirements.txt")
        );
    }

    #[test]
    fn poetry_install_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Poetry, &args("install")),
            Some("pyproject.toml")
        );
    }

    #[test]
    fn poetry_add_not_bare_restore() {
        assert!(is_bare_restore(&PackageManager::Poetry, &args("add requests")).is_none());
    }

    #[test]
    fn npm_bare_install_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Npm, &args("install")),
            Some("package.json")
        );
    }

    #[test]
    fn npm_i_bare_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Npm, &args("i")),
            Some("package.json")
        );
    }

    #[test]
    fn npm_install_with_package_not_bare_restore() {
        assert!(is_bare_restore(&PackageManager::Npm, &args("install lodash")).is_none());
    }

    #[test]
    fn npm_run_not_bare_restore() {
        assert!(is_bare_restore(&PackageManager::Npm, &args("run build")).is_none());
    }

    #[test]
    fn yarn_bare_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Yarn, &[]),
            Some("package.json")
        );
    }

    #[test]
    fn yarn_install_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Yarn, &args("install")),
            Some("package.json")
        );
    }

    #[test]
    fn yarn_add_not_bare_restore() {
        assert!(is_bare_restore(&PackageManager::Yarn, &args("add lodash")).is_none());
    }

    #[test]
    fn pnpm_install_bare_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Pnpm, &args("install")),
            Some("package.json")
        );
    }

    #[test]
    fn pnpm_add_not_bare_restore() {
        assert!(is_bare_restore(&PackageManager::Pnpm, &args("add lodash")).is_none());
    }

    #[test]
    fn go_mod_download_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Go, &args("mod download")),
            Some("go.mod")
        );
    }

    #[test]
    fn go_get_not_bare_restore() {
        assert!(is_bare_restore(&PackageManager::Go, &args("get golang.org/x/net")).is_none());
    }

    #[test]
    fn cargo_build_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Cargo, &args("build")),
            Some("Cargo.toml")
        );
    }

    #[test]
    fn cargo_fetch_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Cargo, &args("fetch")),
            Some("Cargo.toml")
        );
    }

    #[test]
    fn cargo_check_is_bare_restore() {
        assert_eq!(
            is_bare_restore(&PackageManager::Cargo, &args("check")),
            Some("Cargo.toml")
        );
    }

    #[test]
    fn cargo_add_not_bare_restore() {
        assert!(is_bare_restore(&PackageManager::Cargo, &args("add serde")).is_none());
    }

    // --- lockfile_candidates ---

    #[test]
    fn lockfile_candidates_for_package_json() {
        let c = lockfile_candidates("package.json");
        assert!(c.contains(&"package-lock.json"));
        assert!(c.contains(&"yarn.lock"));
        assert!(c.contains(&"pnpm-lock.yaml"));
    }

    #[test]
    fn lockfile_candidates_for_requirements_txt() {
        let c = lockfile_candidates("requirements.txt");
        assert!(c.contains(&"uv.lock"));
        assert!(c.contains(&"poetry.lock"));
    }

    #[test]
    fn lockfile_candidates_for_pyproject_toml() {
        let c = lockfile_candidates("pyproject.toml");
        assert!(c.contains(&"uv.lock"));
        assert!(c.contains(&"poetry.lock"));
    }

    #[test]
    fn lockfile_candidates_for_go_mod() {
        assert_eq!(lockfile_candidates("go.mod"), &["go.sum"]);
    }

    #[test]
    fn lockfile_candidates_for_cargo_toml() {
        assert_eq!(lockfile_candidates("Cargo.toml"), &["Cargo.lock"]);
    }

    #[test]
    fn lockfile_candidates_unknown_returns_empty() {
        assert!(lockfile_candidates("unknown.txt").is_empty());
    }

    // --- canonical_lockfile ---

    #[test]
    fn canonical_lockfile_npm_is_package_lock() {
        assert_eq!(
            canonical_lockfile(&PackageManager::Npm),
            Some("package-lock.json")
        );
    }

    #[test]
    fn canonical_lockfile_yarn_is_yarn_lock() {
        assert_eq!(canonical_lockfile(&PackageManager::Yarn), Some("yarn.lock"));
    }

    #[test]
    fn canonical_lockfile_pnpm_is_pnpm_lock() {
        assert_eq!(
            canonical_lockfile(&PackageManager::Pnpm),
            Some("pnpm-lock.yaml")
        );
    }

    #[test]
    fn canonical_lockfile_uv_is_uv_lock() {
        assert_eq!(canonical_lockfile(&PackageManager::Uv), Some("uv.lock"));
    }

    #[test]
    fn canonical_lockfile_poetry_is_poetry_lock() {
        assert_eq!(
            canonical_lockfile(&PackageManager::Poetry),
            Some("poetry.lock")
        );
    }

    #[test]
    fn canonical_lockfile_go_is_go_sum() {
        assert_eq!(canonical_lockfile(&PackageManager::Go), Some("go.sum"));
    }

    #[test]
    fn canonical_lockfile_cargo_is_cargo_lock() {
        assert_eq!(
            canonical_lockfile(&PackageManager::Cargo),
            Some("Cargo.lock")
        );
    }

    #[test]
    fn canonical_lockfile_pip_is_none() {
        assert!(canonical_lockfile(&PackageManager::Pip).is_none());
    }
}
