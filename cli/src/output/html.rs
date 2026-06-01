use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const TEMPLATE: &str = include_str!("report_template.html");
const PLACEHOLDER: &str = "__REPORT_JSON__";

/// Read `report_path`, inject its contents into the HTML template, write to a
/// temp file, and return the temp file path.  The caller is responsible for
/// keeping the returned path alive long enough for the browser to load it.
pub fn generate(report_path: &Path) -> Result<PathBuf> {
    let json = std::fs::read_to_string(report_path)
        .with_context(|| format!("Cannot read report file: {}", report_path.display()))?;

    if !TEMPLATE.contains(PLACEHOLDER) {
        bail!(
            "report_template.html is missing the {} placeholder",
            PLACEHOLDER
        );
    }

    let html = TEMPLATE.replace(PLACEHOLDER, &json);

    let mut tmp = std::env::temp_dir();
    tmp.push("primer-report.html");
    std::fs::write(&tmp, html)
        .with_context(|| format!("Cannot write HTML report to {}", tmp.display()))?;

    Ok(tmp)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_report(dir: &Path, content: &str) -> PathBuf {
        let p = dir.join("report.json");
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn generate_produces_valid_html() {
        let dir = tempdir().unwrap();
        let json = r#"{"package":"lodash","ecosystem":"npm","blocked":true,"findings":[{"id":"GHSA-0001","severity":"HIGH","summary":"prototype pollution","cvss_vector":null}]}"#;
        let report = write_report(dir.path(), json);

        let html_path = generate(&report).unwrap();
        let html = std::fs::read_to_string(&html_path).unwrap();

        assert!(
            html.contains("<!DOCTYPE html>"),
            "should be a valid HTML document"
        );
        assert!(html.contains("GHSA-0001"), "JSON injected into HTML");
        assert!(!html.contains(PLACEHOLDER), "placeholder must be replaced");
    }

    #[test]
    fn generate_errors_when_report_missing() {
        let dir = tempdir().unwrap();
        let result = generate(&dir.path().join("nonexistent.json"));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("Cannot read report file"));
    }
}
