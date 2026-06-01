use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::output::html;

const REPORT_NEW: &str = ".primer/report.json";
const REPORT_OLD: &str = "primer-report.json";

pub fn run(path: Option<&Path>) -> Result<()> {
    let report = match path {
        Some(p) => p.to_path_buf(),
        None => resolve_report()?,
    };

    let html_path = html::generate(&report)?;

    println!("Opening {} …", html_path.display());
    open::that(&html_path).map_err(|e| anyhow::anyhow!("Failed to open browser: {e}"))?;

    Ok(())
}

fn resolve_report() -> Result<PathBuf> {
    let new = Path::new(REPORT_NEW);
    if new.exists() {
        return Ok(new.to_path_buf());
    }
    let old = Path::new(REPORT_OLD);
    if old.exists() {
        return Ok(old.to_path_buf());
    }
    bail!(
        "No report found. Run `primer scan --file <manifest>` first, \
        or pass an explicit path: `primer open <path>`."
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn open_errors_when_no_report_found() {
        // run() with a path that does not exist should propagate an error from
        // html::generate, not panic.
        let dir = tempdir().unwrap();
        let missing = dir.path().join("no-such-report.json");
        let result = run(Some(&missing));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("Cannot read report file") || msg.contains("no-such-report"));
    }

    #[test]
    fn open_uses_explicit_path_when_given() {
        let dir = tempdir().unwrap();
        let json = r#"{"package":"react","ecosystem":"npm","blocked":false,"findings":[]}"#;
        let report = dir.path().join("my-report.json");
        std::fs::write(&report, json).unwrap();

        // We can't open a browser in CI, so just verify generate() succeeds
        // when given a valid explicit path (run() would call open::that next).
        let html_path = crate::output::html::generate(&report).unwrap();
        let html = std::fs::read_to_string(&html_path).unwrap();
        assert!(html.contains("react"));
    }
}
