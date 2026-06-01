use std::collections::{HashMap, HashSet};

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A package pinned to an exact version in a lockfile.
#[derive(Debug, PartialEq, Clone)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub ecosystem: &'static str,
}

/// All lockfile filenames recognized by primer.
pub const LOCKFILE_NAMES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "go.sum",
];

/// Parse a lockfile and return all pinned packages.
pub fn parse_lockfile(filename: &str, content: &str) -> Vec<ResolvedPackage> {
    match filename {
        "Cargo.lock" => parse_cargo_lock(content),
        "package-lock.json" => parse_package_lock_json(content),
        "yarn.lock" => parse_yarn_lock(content),
        "pnpm-lock.yaml" => parse_pnpm_lock(content),
        "poetry.lock" => parse_poetry_lock(content),
        "uv.lock" => parse_uv_lock(content),
        "go.sum" => parse_go_sum(content),
        _ => vec![],
    }
}

/// Returns the OSV ecosystem string for a lockfile filename.
pub fn ecosystem_from_lockfile(filename: &str) -> Option<&'static str> {
    match filename {
        "Cargo.lock" => Some("crates.io"),
        "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" => Some("npm"),
        "poetry.lock" | "uv.lock" => Some("PyPI"),
        "go.sum" => Some("Go"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Cargo.lock  (TOML)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CargoLock {
    package: Option<Vec<CargoPackage>>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    source: Option<String>,
}

fn parse_cargo_lock(content: &str) -> Vec<ResolvedPackage> {
    let lock: CargoLock = match toml::from_str(content) {
        Ok(l) => l,
        Err(_) => return vec![],
    };
    lock.package
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.source.is_some()) // skip workspace members (no source)
        .map(|p| ResolvedPackage {
            name: p.name,
            version: p.version,
            ecosystem: "crates.io",
        })
        .collect()
}

// ---------------------------------------------------------------------------
// package-lock.json  (JSON v1 / v2 / v3)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PackageLock {
    #[serde(rename = "lockfileVersion", default)]
    lockfile_version: u32,
    packages: Option<HashMap<String, PackageLockEntry>>,
    dependencies: Option<HashMap<String, DepEntry>>,
}

#[derive(Deserialize)]
struct PackageLockEntry {
    version: Option<String>,
    #[serde(default)]
    link: bool, // symlink entries — not real packages
}

#[derive(Deserialize)]
struct DepEntry {
    version: String,
}

fn parse_package_lock_json(content: &str) -> Vec<ResolvedPackage> {
    let lock: PackageLock = match serde_json::from_str(content) {
        Ok(l) => l,
        Err(_) => return vec![],
    };

    if lock.lockfile_version >= 2 {
        // v2 / v3: `packages` map with "node_modules/express" keys
        lock.packages
            .unwrap_or_default()
            .into_iter()
            .filter(|(k, e)| !k.is_empty() && !e.link)
            .filter_map(|(key, entry)| {
                let version = entry.version?;
                let name = last_node_modules_segment(&key).to_owned();
                if name.is_empty() {
                    return None;
                }
                Some(ResolvedPackage {
                    name,
                    version,
                    ecosystem: "npm",
                })
            })
            .collect()
    } else {
        // v1: flat `dependencies` map
        lock.dependencies
            .unwrap_or_default()
            .into_iter()
            .map(|(name, entry)| ResolvedPackage {
                name,
                version: entry.version,
                ecosystem: "npm",
            })
            .collect()
    }
}

/// Strip all `node_modules/` prefixes, returning the rightmost package name.
/// `"node_modules/@types/node"` → `"@types/node"`
/// `"node_modules/foo/node_modules/bar"` → `"bar"`
fn last_node_modules_segment(key: &str) -> &str {
    const PREFIX: &str = "node_modules/";
    if let Some(last_pos) = key.rfind(PREFIX) {
        &key[last_pos + PREFIX.len()..]
    } else {
        key
    }
}

// ---------------------------------------------------------------------------
// yarn.lock  (custom format)
// ---------------------------------------------------------------------------

fn parse_yarn_lock(content: &str) -> Vec<ResolvedPackage> {
    let mut packages = Vec::new();
    let mut current_name: Option<String> = None;

    for line in content.lines() {
        let line_trimmed = line.trim();

        // Blank lines or comments reset the current block
        if line_trimmed.is_empty() || line_trimmed.starts_with('#') {
            current_name = None;
            continue;
        }

        // Block header: unindented, ends with ':'
        // e.g.  express@^4.18.2:  or  "lodash@^4.17.0, lodash@^4.0.0":
        if !line.starts_with(' ') && !line.starts_with('\t') {
            let header = line.trim_end_matches(':');
            let first_descriptor = header.split(',').next().unwrap_or(header).trim();
            let first_descriptor = first_descriptor.trim_matches('"');
            current_name = extract_yarn_name(first_descriptor);
            continue;
        }

        // Indented `version` field inside a block
        if let Some(ref name) = current_name
            && let Some(ver_raw) = line_trimmed.strip_prefix("version ")
        {
            let version = ver_raw.trim().trim_matches('"').to_owned();
            packages.push(ResolvedPackage {
                name: name.clone(),
                version,
                ecosystem: "npm",
            });
            current_name = None; // one version per block
        }
    }

    packages
}

/// Extract the bare package name from a yarn descriptor.
/// `"express@^4.18.2"` → `Some("express")`
/// `"@types/node@^18.0.0"` → `Some("@types/node")`
fn extract_yarn_name(descriptor: &str) -> Option<String> {
    if let Some(rest) = descriptor.strip_prefix('@') {
        // Scoped: @scope/name@version — split on the second '@'
        let at = rest.find('@')?;
        Some(format!("@{}", &rest[..at]))
    } else {
        let at = descriptor.find('@')?;
        Some(descriptor[..at].to_owned())
    }
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml  (line-based, handles v5 / v6 / v9)
// ---------------------------------------------------------------------------

fn parse_pnpm_lock(content: &str) -> Vec<ResolvedPackage> {
    let mut packages = Vec::new();
    let mut in_packages = false;

    for line in content.lines() {
        // Top-level `packages:` section header
        if line == "packages:" {
            in_packages = true;
            continue;
        }
        // Another unindented section header ends the packages block
        if !line.starts_with(' ') && !line.is_empty() && line.ends_with(':') {
            in_packages = false;
        }
        if !in_packages {
            continue;
        }
        // Package entries are indented by exactly 2 spaces
        if !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let key = line.trim().trim_end_matches(':');
        if key.is_empty() || key.starts_with('#') {
            continue;
        }
        if let Some(pkg) = parse_pnpm_key(key) {
            packages.push(pkg);
        }
    }

    packages
}

/// Parse a pnpm lock key into a `ResolvedPackage`.
///
/// v5:  `/express/4.18.2`  `/express/4.18.2_peer`
/// v6:  `/express@4.18.2`  `/@types/node@18.0.0`
/// v9:  `express@4.18.2`   `@types/node@18.0.0`
fn parse_pnpm_key(key: &str) -> Option<ResolvedPackage> {
    let key = key.trim_start_matches('/');

    let (name, version) = if let Some(rest) = key.strip_prefix('@') {
        // Scoped package
        if let Some(at_pos) = rest.find('@') {
            // v6/v9: @scope/name@version
            let full_name = format!("@{}", &rest[..at_pos]);
            let ver_part = &rest[at_pos + 1..];
            let version = ver_part.split(['_', '(']).next().unwrap_or(ver_part);
            (full_name, version.to_owned())
        } else {
            // v5: @scope/name/version
            let slash1 = rest.find('/')?;
            let after = &rest[slash1 + 1..];
            let slash2 = after.find('/')?;
            let name_part = &after[..slash2];
            let ver_part = &after[slash2 + 1..];
            let version = ver_part.split(['_', '(']).next().unwrap_or(ver_part);
            (
                format!("@{}/{}", &rest[..slash1], name_part),
                version.to_owned(),
            )
        }
    } else if let Some(at_pos) = key.find('@') {
        // v6/v9 unscoped: name@version
        let name = &key[..at_pos];
        let ver_part = &key[at_pos + 1..];
        let version = ver_part.split(['_', '(']).next().unwrap_or(ver_part);
        (name.to_owned(), version.to_owned())
    } else if let Some(slash_pos) = key.find('/') {
        // v5 unscoped: name/version
        let name = &key[..slash_pos];
        let ver_part = &key[slash_pos + 1..];
        let version = ver_part.split(['_', '(']).next().unwrap_or(ver_part);
        (name.to_owned(), version.to_owned())
    } else {
        return None;
    };

    // Require name and a semver-looking version (starts with digit)
    if name.is_empty() || version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }

    Some(ResolvedPackage {
        name,
        version,
        ecosystem: "npm",
    })
}

// ---------------------------------------------------------------------------
// poetry.lock  (TOML)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PoetryLock {
    package: Option<Vec<PoetryPackage>>,
}

#[derive(Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
}

fn parse_poetry_lock(content: &str) -> Vec<ResolvedPackage> {
    let lock: PoetryLock = match toml::from_str(content) {
        Ok(l) => l,
        Err(_) => return vec![],
    };
    lock.package
        .unwrap_or_default()
        .into_iter()
        .map(|p| ResolvedPackage {
            name: p.name,
            version: p.version,
            ecosystem: "PyPI",
        })
        .collect()
}

// ---------------------------------------------------------------------------
// uv.lock  (TOML — same [[package]] structure as poetry.lock)
// ---------------------------------------------------------------------------

fn parse_uv_lock(content: &str) -> Vec<ResolvedPackage> {
    let lock: PoetryLock = match toml::from_str(content) {
        Ok(l) => l,
        Err(_) => return vec![],
    };
    lock.package
        .unwrap_or_default()
        .into_iter()
        .map(|p| ResolvedPackage {
            name: p.name,
            version: p.version,
            ecosystem: "PyPI",
        })
        .collect()
}

// ---------------------------------------------------------------------------
// go.sum  (line-based)
// ---------------------------------------------------------------------------

fn parse_go_sum(content: &str) -> Vec<ResolvedPackage> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut packages = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let module = parts.next().unwrap_or("");
        let version_raw = parts.next().unwrap_or("");

        // Skip go.mod-only entries: "v1.2.3/go.mod"
        if version_raw.ends_with("/go.mod") {
            continue;
        }

        // Strip leading 'v' from semver
        let version = version_raw.trim_start_matches('v');
        if module.is_empty() || version.is_empty() {
            continue;
        }

        let key = format!("{}/{}", module, version);
        if seen.insert(key) {
            packages.push(ResolvedPackage {
                name: module.to_owned(),
                version: version.to_owned(),
                ecosystem: "Go",
            });
        }
    }

    packages
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Cargo.lock ---

    #[test]
    fn cargo_lock_parses_registry_packages() {
        let content = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
"#;
        let pkgs = parse_cargo_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
        assert_eq!(pkgs[0].version, "1.0.193");
        assert_eq!(pkgs[0].ecosystem, "crates.io");
    }

    #[test]
    fn cargo_lock_skips_workspace_members() {
        let content = r#"
version = 4

[[package]]
name = "myapp"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
"#;
        let pkgs = parse_cargo_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
    }

    #[test]
    fn cargo_lock_empty_returns_empty() {
        assert!(parse_cargo_lock("version = 4\n").is_empty());
    }

    // --- package-lock.json ---

    #[test]
    fn package_lock_v3_parses_packages() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "myapp", "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.2" },
    "node_modules/@types/node": { "version": "18.0.0" }
  }
}"#;
        let pkgs = parse_package_lock_json(content);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"@types/node"));
        assert!(!names.contains(&"")); // root skipped
    }

    #[test]
    fn package_lock_v3_skips_link_entries() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/linked": { "version": "1.0.0", "link": true },
    "node_modules/real": { "version": "2.0.0" }
  }
}"#;
        let pkgs = parse_package_lock_json(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "real");
    }

    #[test]
    fn package_lock_v1_parses_dependencies() {
        let content = r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "express": { "version": "4.18.2", "resolved": "...", "integrity": "..." },
    "lodash":  { "version": "4.17.21", "resolved": "...", "integrity": "..." }
  }
}"#;
        let pkgs = parse_package_lock_json(content);
        assert_eq!(pkgs.len(), 2);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"lodash"));
    }

    #[test]
    fn package_lock_nested_node_modules_takes_last_segment() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/foo/node_modules/bar": { "version": "1.0.0" }
  }
}"#;
        let pkgs = parse_package_lock_json(content);
        assert_eq!(pkgs[0].name, "bar");
    }

    // --- yarn.lock ---

    #[test]
    fn yarn_lock_parses_packages() {
        let content = r#"# yarn lockfile v1

express@^4.18.2:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
  integrity sha512-abc
"#;
        let pkgs = parse_yarn_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "express");
        assert_eq!(pkgs[0].version, "4.18.2");
    }

    #[test]
    fn yarn_lock_handles_scoped_packages() {
        let content = r#"
"@types/node@^18.0.0":
  version "18.19.0"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-18.19.0.tgz"
"#;
        let pkgs = parse_yarn_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "@types/node");
        assert_eq!(pkgs[0].version, "18.19.0");
    }

    #[test]
    fn yarn_lock_handles_multiple_descriptors_per_block() {
        // Yarn deduplicates by writing one block for multiple matching ranges
        let content = r#"
"lodash@^4.0.0, lodash@^4.17.0":
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
"#;
        let pkgs = parse_yarn_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
    }

    // --- pnpm-lock.yaml ---

    #[test]
    fn pnpm_lock_v5_parses_packages() {
        let content = "packages:\n  /express/4.18.2:\n    resolution: {integrity: sha512-abc}\n";
        let pkgs = parse_pnpm_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "express");
        assert_eq!(pkgs[0].version, "4.18.2");
    }

    #[test]
    fn pnpm_lock_v6_parses_packages() {
        let content = "packages:\n  /express@4.18.2:\n    resolution: {integrity: sha512-abc}\n";
        let pkgs = parse_pnpm_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "express");
        assert_eq!(pkgs[0].version, "4.18.2");
    }

    #[test]
    fn pnpm_lock_v9_parses_packages() {
        let content = "packages:\n  express@4.18.2:\n    resolution: {integrity: sha512-abc}\n";
        let pkgs = parse_pnpm_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "express");
        assert_eq!(pkgs[0].version, "4.18.2");
    }

    #[test]
    fn pnpm_lock_handles_scoped_packages() {
        let content =
            "packages:\n  /@types/node@18.0.0:\n    resolution: {integrity: sha512-abc}\n";
        let pkgs = parse_pnpm_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "@types/node");
        assert_eq!(pkgs[0].version, "18.0.0");
    }

    #[test]
    fn pnpm_lock_ignores_other_sections() {
        let content = "importers:\n  .:\n    dependencies:\n      express: 4.18.2\npackages:\n  express@4.18.2:\n    resolution: {integrity: sha512-abc}\n";
        let pkgs = parse_pnpm_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "express");
    }

    // --- poetry.lock ---

    #[test]
    fn poetry_lock_parses_packages() {
        let content = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = "HTTP library"
optional = false
python-versions = ">=3.7"

[[package]]
name = "certifi"
version = "2024.2.2"
description = "Provides Mozilla CA bundle"
optional = false
python-versions = ">=3.6"
"#;
        let pkgs = parse_poetry_lock(content);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[1].name, "certifi");
        assert_eq!(pkgs[0].ecosystem, "PyPI");
    }

    // --- uv.lock ---

    #[test]
    fn uv_lock_parses_packages() {
        let content = r#"
version = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let pkgs = parse_uv_lock(content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, "2.31.0");
        assert_eq!(pkgs[0].ecosystem, "PyPI");
    }

    // --- go.sum ---

    #[test]
    fn go_sum_parses_packages() {
        let content = "\
github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=\n\
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL7YrpYKXt5YId3A/Tnip5kqbEAP+KLuI3SUcPTeU=\n\
golang.org/x/net v0.20.0 h1:aCL9BSgETF1k+blQaYUBx9hJ9LOGP3gAVemcZlf1Ews=\n\
golang.org/x/net v0.20.0/go.mod h1:z8BVo6PvndSri0LbOE3hAn0apkU+1YvI6E70E9jsnvY=\n";
        let pkgs = parse_go_sum(content);
        assert_eq!(pkgs.len(), 2);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"github.com/gin-gonic/gin"));
        assert!(names.contains(&"golang.org/x/net"));
    }

    #[test]
    fn go_sum_deduplicates_entries() {
        let content = "\
github.com/foo/bar v1.0.0 h1:abc=\n\
github.com/foo/bar v1.0.0/go.mod h1:xyz=\n";
        let pkgs = parse_go_sum(content);
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn go_sum_strips_leading_v() {
        let content = "github.com/foo/bar v1.2.3 h1:abc=\n";
        let pkgs = parse_go_sum(content);
        assert_eq!(pkgs[0].version, "1.2.3");
    }

    // --- ecosystem_from_lockfile ---

    #[test]
    fn ecosystem_from_lockfile_covers_all_formats() {
        assert_eq!(ecosystem_from_lockfile("Cargo.lock"), Some("crates.io"));
        assert_eq!(ecosystem_from_lockfile("package-lock.json"), Some("npm"));
        assert_eq!(ecosystem_from_lockfile("yarn.lock"), Some("npm"));
        assert_eq!(ecosystem_from_lockfile("pnpm-lock.yaml"), Some("npm"));
        assert_eq!(ecosystem_from_lockfile("poetry.lock"), Some("PyPI"));
        assert_eq!(ecosystem_from_lockfile("uv.lock"), Some("PyPI"));
        assert_eq!(ecosystem_from_lockfile("go.sum"), Some("Go"));
        assert!(ecosystem_from_lockfile("unknown.lock").is_none());
    }
}
