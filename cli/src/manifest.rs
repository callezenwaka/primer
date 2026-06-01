/// A newly added package extracted from a staged manifest diff.
#[derive(Debug, PartialEq)]
pub struct NewPackage {
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: &'static str,
}

/// All manifest filenames that the hook monitors.
pub const MONITORED_MANIFESTS: &[&str] = &[
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "go.mod",
    "Cargo.toml",
];

/// Parse `git diff --cached` output for a single manifest file and return
/// packages that were newly added (lines beginning with `+` that are not the
/// diff header).
pub fn parse_diff(filename: &str, diff_text: &str) -> Vec<NewPackage> {
    match filename {
        "requirements.txt" => parse_requirements(diff_text),
        "pyproject.toml" => parse_pyproject_toml(diff_text),
        "package.json" => parse_package_json(diff_text),
        "go.mod" => parse_go_mod(diff_text),
        "Cargo.toml" => parse_cargo_toml(diff_text),
        _ => vec![],
    }
}

/// Parse a full manifest file (not a diff) and return all declared packages.
pub fn parse_file(filename: &str, content: &str) -> Vec<NewPackage> {
    match filename {
        "requirements.txt" => parse_requirements_file(content),
        "pyproject.toml" => parse_pyproject_toml_file(content),
        "package.json" => parse_package_json_file(content),
        "go.mod" => parse_go_mod_file(content),
        "Cargo.toml" => parse_cargo_toml_file(content),
        _ => vec![],
    }
}

/// Infer the OSV ecosystem string from a manifest filename.
pub fn ecosystem_from_filename(filename: &str) -> Option<&'static str> {
    match filename {
        "requirements.txt" | "pyproject.toml" => Some("PyPI"),
        "package.json" => Some("npm"),
        "go.mod" => Some("Go"),
        "Cargo.toml" => Some("crates.io"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// requirements.txt
// ---------------------------------------------------------------------------

fn parse_requirements(diff: &str) -> Vec<NewPackage> {
    diff.lines()
        .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
        .filter_map(|l| {
            let line = l[1..].trim();
            // Skip comments, blank lines, -r includes, options
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                return None;
            }
            // Split on first version specifier character: ==, >=, <=, ~=, !=, >
            let (name, version) = split_requirement(line);
            Some(NewPackage {
                name: name.trim().to_lowercase(),
                version: version.map(|v| v.trim().to_string()),
                ecosystem: "PyPI",
            })
        })
        .collect()
}

/// Split `name==1.0` into `("name", Some("1.0"))`.
fn split_requirement(s: &str) -> (&str, Option<&str>) {
    // Find the first occurrence of a version specifier operator
    let ops = ["==", ">=", "<=", "~=", "!=", ">", "<", "@"];
    let mut split_at = s.len();
    let mut op_len = 0;
    for op in ops {
        if let Some(pos) = s.find(op)
            && pos < split_at
        {
            split_at = pos;
            op_len = op.len();
        }
    }
    if split_at == s.len() {
        (s, None)
    } else {
        (&s[..split_at], Some(&s[split_at + op_len..]))
    }
}

// ---------------------------------------------------------------------------
// package.json
// ---------------------------------------------------------------------------

fn parse_package_json(diff: &str) -> Vec<NewPackage> {
    let mut results = Vec::new();
    // Match lines like:  +    "package-name": "^1.2.3",
    // We are in a dependencies/devDependencies block when we see such lines.
    for line in diff.lines() {
        if !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }
        let trimmed = line[1..].trim();
        // Expect: "name": "version"
        if let Some((name, version)) = parse_json_dep_line(trimmed) {
            results.push(NewPackage {
                name,
                version: Some(version),
                ecosystem: "npm",
            });
        }
    }
    results
}

/// Parse `"name": "version",` → `("name", "version")`.
fn parse_json_dep_line(s: &str) -> Option<(String, String)> {
    // Must start with a quoted key
    let s = s.strip_prefix('"')?;
    let (name, rest) = s.split_once('"')?;
    // Skip colon + whitespace
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    // Version value in quotes
    let rest = rest.strip_prefix('"')?;
    let (raw_ver, _) = rest.split_once('"')?;
    // Strip semver range prefixes (^, ~, >=, etc.)
    let version = raw_ver
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .to_string();
    Some((name.to_string(), version))
}

// ---------------------------------------------------------------------------
// go.mod
// ---------------------------------------------------------------------------

fn parse_go_mod(diff: &str) -> Vec<NewPackage> {
    diff.lines()
        .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
        .filter_map(|l| {
            let line = l[1..].trim();
            // Lines inside a require block: "module/path v1.2.3"
            // or inline: "require module/path v1.2.3"
            let line = line
                .strip_prefix("require")
                .map(|s| s.trim())
                .unwrap_or(line);
            // Skip blank, comments, go directive, module directive, opening parens
            if line.is_empty()
                || line.starts_with("//")
                || line.starts_with("go ")
                || line.starts_with("module ")
                || line == "("
                || line == ")"
            {
                return None;
            }
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let version = parts.next().map(|v| v.trim_start_matches('v').to_string());
            Some(NewPackage {
                name: name.to_string(),
                version,
                ecosystem: "Go",
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Cargo.toml
// ---------------------------------------------------------------------------

fn parse_cargo_toml(diff: &str) -> Vec<NewPackage> {
    let mut results = Vec::new();
    let mut in_deps = false;

    for line in diff.lines() {
        // Track section headers (unchanged or added)
        let bare = if line.starts_with('+') || line.starts_with(' ') {
            &line[1..]
        } else {
            continue;
        };
        let trimmed = bare.trim();

        if trimmed.starts_with('[') {
            in_deps = trimmed == "[dependencies]"
                || trimmed == "[dev-dependencies]"
                || trimmed == "[build-dependencies]";
            continue;
        }

        if !in_deps || !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }

        if let Some((name, version)) = parse_cargo_dep_line(trimmed) {
            results.push(NewPackage {
                name,
                version,
                ecosystem: "crates.io",
            });
        }
    }
    results
}

/// Parse `name = "1.0"` or `name = { version = "1.0", ... }`.
fn parse_cargo_dep_line(s: &str) -> Option<(String, Option<String>)> {
    let (name, rest) = s.split_once('=')?;
    let name = name.trim().to_string();
    if name.is_empty() || name.starts_with('#') {
        return None;
    }
    let rest = rest.trim();

    // Simple string form: "1.0.0"
    if rest.starts_with('"') {
        let version = rest.trim_matches('"').to_string();
        return Some((name, Some(version)));
    }

    // Table form: { version = "1.0", ... }
    if rest.starts_with('{') {
        if let Some(ver) = extract_version_from_table(rest) {
            return Some((name, Some(ver)));
        }
        return Some((name, None));
    }

    None
}

fn extract_version_from_table(s: &str) -> Option<String> {
    // Find version = "..."
    let after = s.find("version")? + "version".len();
    let rest = s[after..].trim_start();
    let rest = rest.strip_prefix('=')?;
    let rest = rest.trim_start().strip_prefix('"')?;
    let (ver, _) = rest.split_once('"')?;
    Some(ver.to_string())
}

// ---------------------------------------------------------------------------
// pyproject.toml  (diff)
// ---------------------------------------------------------------------------

fn parse_pyproject_toml(diff: &str) -> Vec<NewPackage> {
    let mut results = Vec::new();
    let mut in_poetry_deps = false;
    let mut in_pep621_deps = false;

    for line in diff.lines() {
        let bare = if line.starts_with('+') || line.starts_with(' ') {
            &line[1..]
        } else {
            continue;
        };
        let trimmed = bare.trim();

        if trimmed.starts_with('[') {
            in_poetry_deps = trimmed == "[tool.poetry.dependencies]"
                || trimmed == "[tool.poetry.dev-dependencies]";
            in_pep621_deps = trimmed == "[project]";
            continue;
        }

        if !line.starts_with('+') || line.starts_with("+++") {
            continue;
        }

        if in_poetry_deps {
            if trimmed.starts_with("python") {
                continue;
            }
            if let Some((name, version)) = parse_cargo_dep_line(trimmed) {
                let clean_ver = version.map(|v| {
                    v.trim_start_matches(|c: char| !c.is_ascii_digit())
                        .to_string()
                });
                results.push(NewPackage {
                    name: name.to_lowercase(),
                    version: clean_ver,
                    ecosystem: "PyPI",
                });
            }
        } else if in_pep621_deps {
            // Only process quoted PEP 508 strings inside the array, not the key line itself
            if !trimmed.starts_with('"') && !trimmed.starts_with('\'') {
                continue;
            }
            let dep = trimmed.trim_matches(|c| c == '"' || c == '\'' || c == ',');
            if dep.is_empty() || dep.starts_with('#') {
                continue;
            }
            let (name, version) = split_requirement(dep);
            if !name.is_empty() && name != "python" {
                results.push(NewPackage {
                    name: name.trim().to_lowercase(),
                    version: version.map(|v| v.trim().to_string()),
                    ecosystem: "PyPI",
                });
            }
        }
    }
    results
}

// ---------------------------------------------------------------------------
// File parsers (full manifest, no diff prefix)
// ---------------------------------------------------------------------------

fn parse_requirements_file(content: &str) -> Vec<NewPackage> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                return None;
            }
            let (name, version) = split_requirement(line);
            Some(NewPackage {
                name: name.trim().to_lowercase(),
                version: version.map(|v| v.trim().to_string()),
                ecosystem: "PyPI",
            })
        })
        .collect()
}

fn parse_pyproject_toml_file(content: &str) -> Vec<NewPackage> {
    let Ok(parsed) = toml::from_str::<toml::Value>(content) else {
        return vec![];
    };

    let mut results = Vec::new();

    // Poetry: [tool.poetry.dependencies] and [tool.poetry.dev-dependencies]
    for section in &["dependencies", "dev-dependencies"] {
        if let Some(deps) = parsed
            .get("tool")
            .and_then(|t| t.get("poetry"))
            .and_then(|p| p.get(section))
            .and_then(|d| d.as_table())
        {
            for (name, value) in deps {
                if name == "python" {
                    continue;
                }
                let version = match value {
                    toml::Value::String(s) => {
                        let v = s.trim_start_matches(|c: char| !c.is_ascii_digit());
                        if v.is_empty() {
                            None
                        } else {
                            Some(v.to_string())
                        }
                    }
                    toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()).map(|s| {
                        s.trim_start_matches(|c: char| !c.is_ascii_digit())
                            .to_string()
                    }),
                    _ => None,
                };
                results.push(NewPackage {
                    name: name.to_lowercase(),
                    version,
                    ecosystem: "PyPI",
                });
            }
        }
    }

    // PEP 621: [project] dependencies = ["requests>=2.28.0", ...]
    if let Some(pep621) = parsed
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        for dep in pep621 {
            if let Some(s) = dep.as_str() {
                let (name, version) = split_requirement(s);
                if !name.is_empty() && name != "python" {
                    results.push(NewPackage {
                        name: name.trim().to_lowercase(),
                        version: version.map(|v| v.trim().to_string()),
                        ecosystem: "PyPI",
                    });
                }
            }
        }
    }

    results
}

fn parse_package_json_file(content: &str) -> Vec<NewPackage> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        return vec![];
    };

    let mut results = Vec::new();
    for section in &[
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(deps) = json.get(section).and_then(|v| v.as_object()) {
            for (name, version) in deps {
                let raw = version.as_str().unwrap_or("");
                let clean = raw
                    .trim_start_matches(|c: char| !c.is_ascii_digit())
                    .to_string();
                results.push(NewPackage {
                    name: name.clone(),
                    version: if clean.is_empty() { None } else { Some(clean) },
                    ecosystem: "npm",
                });
            }
        }
    }
    results
}

fn parse_go_mod_file(content: &str) -> Vec<NewPackage> {
    content
        .lines()
        .filter_map(|l| {
            let line = l.trim();
            let line = line
                .strip_prefix("require")
                .map(|s| s.trim())
                .unwrap_or(line);
            if line.is_empty()
                || line.starts_with("//")
                || line.starts_with("go ")
                || line.starts_with("module ")
                || line == "("
                || line == ")"
            {
                return None;
            }
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let version = parts.next().map(|v| v.trim_start_matches('v').to_string());
            Some(NewPackage {
                name: name.to_string(),
                version,
                ecosystem: "Go",
            })
        })
        .collect()
}

fn parse_cargo_toml_file(content: &str) -> Vec<NewPackage> {
    let mut results = Vec::new();
    let mut in_deps = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') {
            in_deps = trimmed == "[dependencies]"
                || trimmed == "[dev-dependencies]"
                || trimmed == "[build-dependencies]";
            continue;
        }

        if !in_deps || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((name, version)) = parse_cargo_dep_line(trimmed) {
            results.push(NewPackage {
                name,
                version,
                ecosystem: "crates.io",
            });
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- requirements.txt ---

    #[test]
    fn requirements_simple_pinned() {
        let diff = "+requests==2.25.1\n";
        let pkgs = parse_diff("requirements.txt", diff);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version.as_deref(), Some("2.25.1"));
        assert_eq!(pkgs[0].ecosystem, "PyPI");
    }

    #[test]
    fn requirements_ge_specifier() {
        let diff = "+pillow>=9.0.0\n";
        let pkgs = parse_diff("requirements.txt", diff);
        assert_eq!(pkgs[0].name, "pillow");
        assert_eq!(pkgs[0].version.as_deref(), Some("9.0.0"));
    }

    #[test]
    fn requirements_no_version() {
        let diff = "+flask\n";
        let pkgs = parse_diff("requirements.txt", diff);
        assert_eq!(pkgs[0].name, "flask");
        assert_eq!(pkgs[0].version, None);
    }

    #[test]
    fn requirements_skips_comments_and_blank() {
        let diff = "+# comment\n+\n+requests==2.28.0\n";
        let pkgs = parse_diff("requirements.txt", diff);
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn requirements_skips_diff_header() {
        let diff = "+++ b/requirements.txt\n+requests==2.28.0\n";
        let pkgs = parse_diff("requirements.txt", diff);
        assert_eq!(pkgs.len(), 1);
    }

    // --- package.json ---

    #[test]
    fn package_json_caret_version() {
        let diff = "+    \"express\": \"^4.18.2\",\n";
        let pkgs = parse_diff("package.json", diff);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "express");
        assert_eq!(pkgs[0].version.as_deref(), Some("4.18.2"));
        assert_eq!(pkgs[0].ecosystem, "npm");
    }

    #[test]
    fn package_json_tilde_version() {
        let diff = "+    \"lodash\": \"~4.17.21\",\n";
        let pkgs = parse_diff("package.json", diff);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn package_json_skips_unchanged() {
        let diff = " \"react\": \"^18.0.0\",\n+\"axios\": \"^1.4.0\",\n";
        let pkgs = parse_diff("package.json", diff);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "axios");
    }

    // --- go.mod ---

    #[test]
    fn go_mod_inline_require() {
        let diff = "+require github.com/gin-gonic/gin v1.9.1\n";
        let pkgs = parse_diff("go.mod", diff);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "github.com/gin-gonic/gin");
        assert_eq!(pkgs[0].version.as_deref(), Some("1.9.1"));
        assert_eq!(pkgs[0].ecosystem, "Go");
    }

    #[test]
    fn go_mod_block_entry() {
        let diff = "+\tgithub.com/stretchr/testify v1.8.4\n";
        let pkgs = parse_diff("go.mod", diff);
        assert_eq!(pkgs[0].name, "github.com/stretchr/testify");
        assert_eq!(pkgs[0].version.as_deref(), Some("1.8.4"));
    }

    #[test]
    fn go_mod_skips_directives() {
        let diff = "+go 1.21\n+module myapp\n+require golang.org/x/net v0.17.0\n";
        let pkgs = parse_diff("go.mod", diff);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "golang.org/x/net");
    }

    // --- Cargo.toml ---

    #[test]
    fn cargo_toml_simple_string() {
        let diff = " [dependencies]\n+serde = \"1.0\"\n";
        let pkgs = parse_diff("Cargo.toml", diff);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
        assert_eq!(pkgs[0].version.as_deref(), Some("1.0"));
        assert_eq!(pkgs[0].ecosystem, "crates.io");
    }

    #[test]
    fn cargo_toml_table_form() {
        let diff = " [dependencies]\n+tokio = { version = \"1.35\", features = [\"full\"] }\n";
        let pkgs = parse_diff("Cargo.toml", diff);
        assert_eq!(pkgs[0].name, "tokio");
        assert_eq!(pkgs[0].version.as_deref(), Some("1.35"));
    }

    #[test]
    fn cargo_toml_ignores_non_deps_section() {
        let diff = " [package]\n+name = \"myapp\"\n [dependencies]\n+anyhow = \"1.0\"\n";
        let pkgs = parse_diff("Cargo.toml", diff);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "anyhow");
    }

    #[test]
    fn unknown_manifest_returns_empty() {
        let pkgs = parse_diff("poetry.lock", "+foo = \"1.0\"\n");
        assert!(pkgs.is_empty());
    }

    // --- pyproject.toml diff ---

    #[test]
    fn pyproject_poetry_deps_diff() {
        let diff = " [tool.poetry.dependencies]\n+requests = \"^2.28.0\"\n";
        let pkgs = parse_diff("pyproject.toml", diff);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version.as_deref(), Some("2.28.0"));
        assert_eq!(pkgs[0].ecosystem, "PyPI");
    }

    #[test]
    fn pyproject_poetry_skips_python_constraint() {
        let diff = " [tool.poetry.dependencies]\n+python = \"^3.11\"\n+pillow = \"9.0.0\"\n";
        let pkgs = parse_diff("pyproject.toml", diff);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "pillow");
    }

    #[test]
    fn pyproject_pep621_deps_diff() {
        let diff = " [project]\n+dependencies = [\n+  \"flask>=2.0\",\n+]\n";
        let pkgs = parse_diff("pyproject.toml", diff);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "flask");
        assert_eq!(pkgs[0].version.as_deref(), Some("2.0"));
    }

    // --- parse_file: requirements.txt ---

    #[test]
    fn file_requirements_pinned() {
        let content = "requests==2.25.1\npillow>=9.0.0\n# comment\n\nflask\n";
        let pkgs = parse_file("requirements.txt", content);
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version.as_deref(), Some("2.25.1"));
        assert_eq!(pkgs[1].name, "pillow");
        assert_eq!(pkgs[2].name, "flask");
        assert_eq!(pkgs[2].version, None);
    }

    #[test]
    fn file_requirements_skips_options_and_comments() {
        let content =
            "# top comment\n-r base.txt\n--index-url https://pypi.org\nrequests==2.28.0\n";
        let pkgs = parse_file("requirements.txt", content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
    }

    // --- parse_file: pyproject.toml ---

    #[test]
    fn file_pyproject_poetry() {
        let content = "[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"^2.28.0\"\npillow = { version = \"9.0.0\", extras = [\"jpeg\"] }\n";
        let pkgs = parse_file("pyproject.toml", content);
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "requests"));
        assert!(
            pkgs.iter()
                .any(|p| p.name == "pillow" && p.version.as_deref() == Some("9.0.0"))
        );
    }

    #[test]
    fn file_pyproject_pep621() {
        let content =
            "[project]\ndependencies = [\n  \"flask>=2.0\",\n  \"sqlalchemy==2.0.0\",\n]\n";
        let pkgs = parse_file("pyproject.toml", content);
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "flask"));
        assert!(
            pkgs.iter()
                .any(|p| p.name == "sqlalchemy" && p.version.as_deref() == Some("2.0.0"))
        );
    }

    // --- parse_file: package.json ---

    #[test]
    fn file_package_json_deps_and_dev_deps() {
        let content =
            r#"{"dependencies":{"express":"^4.18.2"},"devDependencies":{"jest":"^29.0.0"}}"#;
        let pkgs = parse_file("package.json", content);
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "express" && p.version.as_deref() == Some("4.18.2"))
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "jest" && p.version.as_deref() == Some("29.0.0"))
        );
    }

    #[test]
    fn file_package_json_invalid_returns_empty() {
        let pkgs = parse_file("package.json", "not json");
        assert!(pkgs.is_empty());
    }

    // --- parse_file: go.mod ---

    #[test]
    fn file_go_mod_require_block() {
        let content = "module myapp\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/net v0.17.0\n)\n";
        let pkgs = parse_file("go.mod", content);
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "github.com/gin-gonic/gin"
                    && p.version.as_deref() == Some("1.9.1"))
        );
    }

    // --- parse_file: Cargo.toml ---

    #[test]
    fn file_cargo_toml_deps_section() {
        let content = "[package]\nname = \"myapp\"\n\n[dependencies]\nserde = \"1.0\"\ntokio = { version = \"1.35\", features = [\"full\"] }\n";
        let pkgs = parse_file("Cargo.toml", content);
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.name == "serde" && p.version.as_deref() == Some("1.0"))
        );
        assert!(
            pkgs.iter()
                .any(|p| p.name == "tokio" && p.version.as_deref() == Some("1.35"))
        );
    }

    #[test]
    fn file_cargo_toml_ignores_package_section() {
        let content = "[package]\nname = \"myapp\"\nversion = \"0.1.0\"\n\n[dependencies]\nanyhow = \"1.0\"\n";
        let pkgs = parse_file("Cargo.toml", content);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "anyhow");
    }

    // --- ecosystem_from_filename ---

    #[test]
    fn ecosystem_inference() {
        assert_eq!(ecosystem_from_filename("requirements.txt"), Some("PyPI"));
        assert_eq!(ecosystem_from_filename("pyproject.toml"), Some("PyPI"));
        assert_eq!(ecosystem_from_filename("package.json"), Some("npm"));
        assert_eq!(ecosystem_from_filename("go.mod"), Some("Go"));
        assert_eq!(ecosystem_from_filename("Cargo.toml"), Some("crates.io"));
        assert_eq!(ecosystem_from_filename("yarn.lock"), None);
    }

    // --- parse_file: unknown filename ---

    #[test]
    fn file_unknown_filename_returns_empty() {
        let pkgs = parse_file("poetry.lock", "foo = \"1.0\"\n");
        assert!(pkgs.is_empty());
    }
}
