use std::fs;

use anyhow::Result;
use serde::Serialize;

use crate::engine::osv::Vulnerability;

const REPORT_FILE: &str = "primer-report.json";

#[derive(Serialize)]
struct Report<'a> {
    package: &'a str,
    ecosystem: &'a str,
    blocked: bool,
    findings: Vec<Finding<'a>>,
}

#[derive(Serialize)]
struct Finding<'a> {
    id: &'a str,
    severity: &'a str,
    summary: Option<&'a str>,
    cvss_vector: Option<&'a str>,
}

/// Write findings to `.primer/report.json` when `.primer/` exists, else `primer-report.json`.
pub fn write(package: &str, ecosystem: &str, vulns: &[Vulnerability]) -> Result<()> {
    let primer_dir = std::path::Path::new(".primer");
    if primer_dir.is_dir() {
        return write_named(primer_dir, "report.json", package, ecosystem, vulns);
    }
    write_to_dir(std::path::Path::new("."), package, ecosystem, vulns)
}

fn write_named(
    dir: &std::path::Path,
    filename: &str,
    package: &str,
    ecosystem: &str,
    vulns: &[Vulnerability],
) -> Result<()> {
    let blocked = vulns
        .iter()
        .any(|v| matches!(v.severity_label(), "CRITICAL" | "HIGH"));
    let findings = vulns
        .iter()
        .map(|v| Finding {
            id: &v.id,
            severity: v.severity_label(),
            summary: v.summary.as_deref(),
            cvss_vector: v.cvss_vector.as_deref(),
        })
        .collect();
    let report = Report {
        package,
        ecosystem,
        blocked,
        findings,
    };
    fs::write(dir.join(filename), serde_json::to_string_pretty(&report)?)?;
    Ok(())
}

pub(crate) fn write_to_dir(
    dir: &std::path::Path,
    package: &str,
    ecosystem: &str,
    vulns: &[Vulnerability],
) -> Result<()> {
    let blocked = vulns
        .iter()
        .any(|v| matches!(v.severity_label(), "CRITICAL" | "HIGH"));

    let findings = vulns
        .iter()
        .map(|v| Finding {
            id: &v.id,
            severity: v.severity_label(),
            summary: v.summary.as_deref(),
            cvss_vector: v.cvss_vector.as_deref(),
        })
        .collect();

    let report = Report {
        package,
        ecosystem,
        blocked,
        findings,
    };
    fs::write(
        dir.join(REPORT_FILE),
        serde_json::to_string_pretty(&report)?,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::osv::Vulnerability;

    fn vuln(id: &str, severity: &str) -> Vulnerability {
        Vulnerability {
            id: id.to_owned(),
            summary: Some("test".into()),
            cvss_vector: None,
            severity: Some(severity.to_owned()),
            fixed_version: None,
        }
    }

    #[test]
    fn report_serialises_correctly() {
        let vulns = vec![vuln("GHSA-0001", "CRITICAL"), vuln("GHSA-0002", "LOW")];
        let dir = tempfile::tempdir().unwrap();

        write_to_dir(dir.path(), "requests", "PyPI", &vulns).unwrap();

        let contents = std::fs::read_to_string(dir.path().join(REPORT_FILE)).unwrap();
        let json: serde_json::Value = serde_json::from_str(&contents).unwrap();

        assert_eq!(json["package"], "requests");
        assert_eq!(json["ecosystem"], "PyPI");
        assert_eq!(json["blocked"], true);
        assert_eq!(json["findings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn report_not_blocked_when_no_critical_or_high() {
        let vulns = vec![vuln("GHSA-0001", "LOW")];
        let dir = tempfile::tempdir().unwrap();

        write_to_dir(dir.path(), "pkg", "PyPI", &vulns).unwrap();

        let contents = std::fs::read_to_string(dir.path().join(REPORT_FILE)).unwrap();
        let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(json["blocked"], false);
    }

    #[test]
    fn write_named_creates_file_at_given_name() {
        let vulns = vec![vuln("GHSA-0001", "HIGH")];
        let dir = tempfile::tempdir().unwrap();

        write_named(dir.path(), "report.json", "lodash", "npm", &vulns).unwrap();

        // File is at report.json, not primer-report.json.
        assert!(dir.path().join("report.json").exists());
        assert!(!dir.path().join(REPORT_FILE).exists());

        let contents = std::fs::read_to_string(dir.path().join("report.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(json["package"], "lodash");
        assert_eq!(json["blocked"], true);
    }
}
