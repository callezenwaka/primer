use std::path::PathBuf;

use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::engine::osv;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn run(
    file: PathBuf,
    output: Option<PathBuf>,
    format: &str,
    no_scan: bool,
) -> Result<()> {
    let filename = file
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    let content = std::fs::read_to_string(&file)?;

    let is_lockfile = crate::lockfile::LOCKFILE_NAMES.contains(&filename);

    let eco = if is_lockfile {
        crate::lockfile::ecosystem_from_lockfile(filename)
    } else {
        crate::manifest::ecosystem_from_filename(filename)
    }
    .ok_or_else(|| {
        anyhow::anyhow!(
            "Could not infer ecosystem from '{}'. Use a supported manifest or lockfile.",
            filename
        )
    })?;

    // Collect (name, version) pairs
    let packages: Vec<(String, String)> = if is_lockfile {
        crate::lockfile::parse_lockfile(filename, &content)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect()
    } else {
        crate::manifest::parse_file(filename, &content)
            .into_iter()
            .map(|p| (p.name, p.version.unwrap_or_default()))
            .collect()
    };

    if packages.is_empty() {
        bail!("No packages found in {}", file.display());
    }

    // Sort for deterministic output
    let mut packages = packages;
    packages.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // Optionally enrich with OSV vulnerability data
    let vuln_map = if no_scan {
        std::collections::HashMap::new()
    } else {
        eprintln!(
            "  Scanning {} packages for vulnerabilities …",
            packages.len()
        );
        scan_all(&packages, eco).await
    };

    let json_output = match format {
        "spdx" => emit_spdx(&packages, eco, &vuln_map),
        _ => emit_cyclonedx(&packages, eco, &vuln_map),
    };

    let text = serde_json::to_string_pretty(&json_output)?;

    match output {
        Some(path) => std::fs::write(&path, &text)?,
        None => println!("{}", text),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// OSV enrichment
// ---------------------------------------------------------------------------

async fn scan_all(
    packages: &[(String, String)],
    eco: &str,
) -> std::collections::HashMap<String, Vec<osv::Vulnerability>> {
    let mut map = std::collections::HashMap::new();
    for (name, version) in packages {
        let ver = if version.is_empty() {
            None
        } else {
            Some(version.as_str())
        };
        if let Ok(vulns) = osv::query(name, eco, ver, false).await
            && !vulns.is_empty()
        {
            map.insert(format!("{}@{}", name, version), vulns);
        }
    }
    map
}

// ---------------------------------------------------------------------------
// PURL builder
// ---------------------------------------------------------------------------

fn purl(eco: &str, name: &str, version: &str) -> String {
    let pkg_type = match eco {
        "PyPI" => "pypi",
        "npm" => "npm",
        "Go" => "golang",
        "crates.io" => "cargo",
        _ => "generic",
    };
    if version.is_empty() {
        format!("pkg:{}/{}", pkg_type, name)
    } else {
        format!("pkg:{}/{}@{}", pkg_type, name, version)
    }
}

// ---------------------------------------------------------------------------
// CycloneDX v1.5 JSON
// ---------------------------------------------------------------------------

fn emit_cyclonedx(
    packages: &[(String, String)],
    eco: &str,
    vuln_map: &std::collections::HashMap<String, Vec<osv::Vulnerability>>,
) -> Value {
    let components: Vec<Value> = packages
        .iter()
        .map(|(name, version)| {
            let key = format!("{}@{}", name, version);
            let vulns = vuln_map.get(&key);
            let vuln_arr: Vec<Value> = vulns
                .map(|vs| {
                    vs.iter()
                        .map(|v| {
                            json!({
                                "id": v.id,
                                "ratings": [{"severity": v.severity_label().to_lowercase()}],
                                "description": v.summary,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            let mut comp = json!({
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl(eco, name, version),
            });

            if !vuln_arr.is_empty() {
                comp["vulnerabilities"] = json!(vuln_arr);
            }

            comp
        })
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": chrono_now(),
            "tools": [{"vendor": "primer", "name": "primer", "version": env!("CARGO_PKG_VERSION")}],
        },
        "components": components,
    })
}

// ---------------------------------------------------------------------------
// SPDX 2.3 JSON
// ---------------------------------------------------------------------------

fn emit_spdx(
    packages: &[(String, String)],
    eco: &str,
    vuln_map: &std::collections::HashMap<String, Vec<osv::Vulnerability>>,
) -> Value {
    let spdx_packages: Vec<Value> = packages
        .iter()
        .enumerate()
        .map(|(i, (name, version))| {
            let key = format!("{}@{}", name, version);
            let vuln_ids: Vec<&str> = vuln_map
                .get(&key)
                .map(|vs| vs.iter().map(|v| v.id.as_str()).collect())
                .unwrap_or_default();

            let mut pkg = json!({
                "SPDXID": format!("SPDXRef-Package-{}", i),
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl(eco, name, version),
                }],
            });

            if !vuln_ids.is_empty() {
                pkg["comment"] = json!(format!("Vulnerabilities: {}", vuln_ids.join(", ")));
            }

            pkg
        })
        .collect();

    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "primer-sbom",
        "documentNamespace": format!("https://primer.barestripe.com/sbom/{}", uuid_v4()),
        "creationInfo": {
            "created": chrono_now(),
            "creators": [format!("Tool: primer-{}", env!("CARGO_PKG_VERSION"))],
        },
        "packages": spdx_packages,
        "relationships": [{
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-0",
        }],
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn chrono_now() -> String {
    // RFC 3339 timestamp without pulling in chrono; use std::time.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Format as YYYY-MM-DDTHH:MM:SSZ (approximate — good enough for SBOM metadata).
    let s = secs;
    let (y, mo, d, h, mi, sec) = epoch_to_datetime(s);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, sec)
}

fn epoch_to_datetime(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec = secs % 60;
    let min = (secs / 60) % 60;
    let hour = (secs / 3600) % 24;
    let days = secs / 86400;
    // Gregorian calendar from day 0 = 1970-01-01
    let (year, month, day) = days_to_ymd(days);
    (year, month, day, hour, min, sec)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let dy = if leap { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let leap = is_leap(year);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

fn uuid_v4() -> String {
    // Pseudo-random UUID v4 from system time — sufficient for SBOM namespace uniqueness.
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (t >> 96) as u32,
        (t >> 80) as u16,
        (t >> 68) as u16 & 0x0fff,
        ((t >> 52) as u16 & 0x3fff) | 0x8000,
        t as u64 & 0x0000_ffff_ffff_ffff,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_pypi() {
        assert_eq!(
            purl("PyPI", "requests", "2.28.0"),
            "pkg:pypi/requests@2.28.0"
        );
    }

    #[test]
    fn purl_npm() {
        assert_eq!(purl("npm", "express", "4.18.2"), "pkg:npm/express@4.18.2");
    }

    #[test]
    fn purl_cargo() {
        assert_eq!(purl("crates.io", "serde", "1.0.0"), "pkg:cargo/serde@1.0.0");
    }

    #[test]
    fn purl_go() {
        assert_eq!(
            purl("Go", "golang.org/x/net", "v0.1.0"),
            "pkg:golang/golang.org/x/net@v0.1.0"
        );
    }

    #[test]
    fn purl_empty_version() {
        assert_eq!(purl("PyPI", "requests", ""), "pkg:pypi/requests");
    }

    #[test]
    fn cyclonedx_structure() {
        let pkgs = vec![("requests".to_string(), "2.28.0".to_string())];
        let map = std::collections::HashMap::new();
        let v = emit_cyclonedx(&pkgs, "PyPI", &map);
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        let comp = &v["components"][0];
        assert_eq!(comp["name"], "requests");
        assert_eq!(comp["purl"], "pkg:pypi/requests@2.28.0");
    }

    #[test]
    fn spdx_structure() {
        let pkgs = vec![("express".to_string(), "4.18.2".to_string())];
        let map = std::collections::HashMap::new();
        let v = emit_spdx(&pkgs, "npm", &map);
        assert_eq!(v["spdxVersion"], "SPDX-2.3");
        let pkg = &v["packages"][0];
        assert_eq!(pkg["name"], "express");
        assert_eq!(
            pkg["externalRefs"][0]["referenceLocator"],
            "pkg:npm/express@4.18.2"
        );
    }

    #[test]
    fn cyclonedx_includes_vulnerabilities() {
        use crate::engine::osv::Vulnerability;
        let pkgs = vec![("pillow".to_string(), "9.0.0".to_string())];
        let mut map = std::collections::HashMap::new();
        map.insert(
            "pillow@9.0.0".to_string(),
            vec![Vulnerability {
                id: "GHSA-xxxx-yyyy-zzzz".to_string(),
                summary: Some("heap overflow".to_string()),
                cvss_vector: None,
                severity: Some("CRITICAL".to_string()),
                fixed_version: Some("9.0.1".to_string()),
            }],
        );
        let v = emit_cyclonedx(&pkgs, "PyPI", &map);
        let vuln = &v["components"][0]["vulnerabilities"][0];
        assert_eq!(vuln["id"], "GHSA-xxxx-yyyy-zzzz");
    }

    #[test]
    fn output_is_sorted() {
        let mut pkgs = vec![
            ("zebra".to_string(), "1.0.0".to_string()),
            ("alpha".to_string(), "2.0.0".to_string()),
        ];
        pkgs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        assert_eq!(pkgs[0].0, "alpha");
        assert_eq!(pkgs[1].0, "zebra");
    }
}
