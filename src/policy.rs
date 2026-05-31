use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;
use serde::Deserialize;

use crate::engine::osv::Vulnerability;

// ---------------------------------------------------------------------------
// Policy file types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct PolicyFile {
    #[serde(default)]
    pub policy: PolicyGlobal,
    #[serde(rename = "ignore", default)]
    pub ignore: Vec<IgnoreRule>,
    #[serde(rename = "override", default)]
    pub overrides: Vec<OverrideRule>,
    #[serde(rename = "deny", default)]
    pub deny: Vec<DenyRule>,
}

#[derive(Debug, Deserialize, Default)]
pub struct PolicyGlobal {
    pub threshold: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IgnoreRule {
    pub cve: Option<String>,
    pub package: Option<String>,
    pub expires: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OverrideRule {
    pub package: String,
    pub threshold: String,
}

#[derive(Debug, Deserialize)]
pub struct DenyRule {
    pub package: String,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Evaluation result
// ---------------------------------------------------------------------------

pub struct PolicyDecision {
    pub denied: bool,
    pub deny_reason: Option<String>,
    /// Vulnerabilities after [[ignore]] rules are applied.
    pub filtered_vulns: Vec<Vulnerability>,
    /// Effective threshold for this package (from [[override]], [policy], or base).
    pub threshold: String,
    /// Warnings for expired [[ignore]] rules that re-activated findings.
    pub expired_warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

pub fn load() -> PolicyFile {
    let cwd = std::env::current_dir().unwrap_or_default();
    // .primer/policy.toml takes priority over .primer-policy.toml.
    let new_path = cwd.join(".primer").join("policy.toml");
    if new_path.exists() {
        return load_from(&new_path).unwrap_or_default();
    }
    let old_path = cwd.join(".primer-policy.toml");
    if old_path.exists() {
        eprintln!(
            "⚠  .primer-policy.toml is deprecated; run `primer migrate` to move it to .primer/policy.toml"
        );
    }
    load_from(&old_path).unwrap_or_default()
}

pub fn load_from(path: &Path) -> Result<PolicyFile> {
    if !path.exists() {
        return Ok(PolicyFile::default());
    }
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

/// Apply policy rules to a package + its vulnerabilities.
/// Evaluation order: [[deny]] → [[ignore]] → [[override]] → global threshold.
pub fn evaluate(
    policy: &PolicyFile,
    package: &str,
    vulns: &[Vulnerability],
    base_threshold: &str,
) -> PolicyDecision {
    // 1. [[deny]] — hard block by package name regardless of CVE status.
    if let Some(rule) = policy
        .deny
        .iter()
        .find(|r| r.package.eq_ignore_ascii_case(package))
    {
        return PolicyDecision {
            denied: true,
            deny_reason: rule.reason.clone(),
            filtered_vulns: vulns.to_vec(),
            threshold: base_threshold.to_string(),
            expired_warnings: vec![],
        };
    }

    // 2. [[ignore]] — suppress specific CVEs; re-activate if expired.
    let today = today_str();
    let mut filtered_vulns = Vec::new();
    let mut expired_warnings = Vec::new();

    for vuln in vulns {
        let matching = policy.ignore.iter().find(|r| {
            let cve_match = r
                .cve
                .as_deref()
                .map(|c| c.eq_ignore_ascii_case(&vuln.id))
                .unwrap_or(true);
            let pkg_match = r
                .package
                .as_deref()
                .map(|p| p.eq_ignore_ascii_case(package))
                .unwrap_or(true);
            cve_match && pkg_match
        });

        match matching {
            Some(rule) => {
                if let Some(expires) = &rule.expires
                    && expires.as_str() < today.as_str()
                {
                    expired_warnings.push(format!(
                        "⚠ ignore rule for {} expired {} — finding re-activated",
                        vuln.id, expires
                    ));
                    filtered_vulns.push(vuln.clone());
                    // Not expired — suppress the finding.
                }
                // No expiry field → suppress indefinitely.
            }
            None => filtered_vulns.push(vuln.clone()),
        }
    }

    // 3. [[override]] → [policy].threshold → base_threshold.
    let threshold = policy
        .overrides
        .iter()
        .find(|r| r.package.eq_ignore_ascii_case(package))
        .map(|r| r.threshold.clone())
        .or_else(|| policy.policy.threshold.clone())
        .unwrap_or_else(|| base_threshold.to_string());

    PolicyDecision {
        denied: false,
        deny_reason: None,
        filtered_vulns,
        threshold,
        expired_warnings,
    }
}

// ---------------------------------------------------------------------------
// primer policy list
// ---------------------------------------------------------------------------

pub fn list_rules(policy: &PolicyFile) {
    let today = today_str();
    println!("Policy rules  (.primer-policy.toml)\n");

    // Global threshold
    if let Some(t) = &policy.policy.threshold {
        println!("Global threshold: {}", t.bold());
    } else {
        println!(
            "Global threshold: {} (inherited from config)",
            "unset".dimmed()
        );
    }

    // [[deny]]
    println!();
    if policy.deny.is_empty() {
        println!("{}", "Deny rules: none".dimmed());
    } else {
        println!("Deny rules ({}):", policy.deny.len());
        for r in &policy.deny {
            let reason = r
                .reason
                .as_deref()
                .map(|s| format!("  — {}", s))
                .unwrap_or_default();
            println!("  {} {}{}", "✗".red().bold(), r.package.bold(), reason);
        }
    }

    // [[ignore]]
    println!();
    if policy.ignore.is_empty() {
        println!("{}", "Ignore rules: none".dimmed());
    } else {
        println!("Ignore rules ({}):", policy.ignore.len());
        for r in &policy.ignore {
            let target = match (&r.cve, &r.package) {
                (Some(c), Some(p)) => format!("{} ({})", c, p),
                (Some(c), None) => c.clone(),
                (None, Some(p)) => format!("all CVEs in {}", p),
                (None, None) => "all CVEs in all packages".to_string(),
            };
            let expiry_str = match &r.expires {
                None => "no expiry".dimmed().to_string(),
                Some(e) => {
                    if e.as_str() < today.as_str() {
                        format!(
                            "expired {}  {}",
                            e,
                            "[EXPIRED — finding re-activated]".red()
                        )
                    } else {
                        format!("expires {}", e)
                    }
                }
            };
            let reason = r
                .reason
                .as_deref()
                .map(|s| format!("  — {}", s))
                .unwrap_or_default();
            println!("  {} {}  {}{}", "·".dimmed(), target, expiry_str, reason);
        }
    }

    // [[override]]
    println!();
    if policy.overrides.is_empty() {
        println!("{}", "Override rules: none".dimmed());
    } else {
        println!("Override rules ({}):", policy.overrides.len());
        for r in &policy.overrides {
            println!(
                "  {} {} → threshold: {}",
                "·".dimmed(),
                r.package.bold(),
                r.threshold.yellow()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// primer policy check
// ---------------------------------------------------------------------------

const VALID_THRESHOLDS: &[&str] = &["critical", "high", "medium", "low"];

pub fn check_file(path: &Path) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("{} not found", path.display());
    }
    let policy = load_from(path)?;
    let mut errors: Vec<String> = Vec::new();

    // Global threshold
    if let Some(t) = &policy.policy.threshold
        && !VALID_THRESHOLDS.contains(&t.as_str())
    {
        errors.push(format!(
            "[policy] threshold = {:?} — must be one of: {}",
            t,
            VALID_THRESHOLDS.join(", ")
        ));
    }

    // [[ignore]] expires format
    for (i, r) in policy.ignore.iter().enumerate() {
        if let Some(e) = &r.expires
            && !is_valid_date(e)
        {
            errors.push(format!(
                "[[ignore]][{}] expires = {:?} — must be YYYY-MM-DD",
                i, e
            ));
        }
        if r.cve.is_none() && r.package.is_none() {
            errors.push(format!(
                "[[ignore]][{}] — at least one of `cve` or `package` should be set",
                i
            ));
        }
    }

    // [[override]] threshold
    for (i, r) in policy.overrides.iter().enumerate() {
        if r.package.is_empty() {
            errors.push(format!("[[override]][{}] package must not be empty", i));
        }
        if !VALID_THRESHOLDS.contains(&r.threshold.as_str()) {
            errors.push(format!(
                "[[override]][{}] threshold = {:?} — must be one of: {}",
                i,
                r.threshold,
                VALID_THRESHOLDS.join(", ")
            ));
        }
    }

    // [[deny]] package
    for (i, r) in policy.deny.iter().enumerate() {
        if r.package.is_empty() {
            errors.push(format!("[[deny]][{}] package must not be empty", i));
        }
    }

    if errors.is_empty() {
        println!("{} {} is valid", "✓".green().bold(), path.display());
        Ok(())
    } else {
        for e in &errors {
            eprintln!("{} {}", "✗".red().bold(), e);
        }
        anyhow::bail!("{} error(s) found in {}", errors.len(), path.display())
    }
}

// ---------------------------------------------------------------------------
// Date helpers (no external crate needed — ISO 8601 strings compare correctly)
// ---------------------------------------------------------------------------

fn today_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = days_to_ymd(secs / 86400);
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn is_valid_date(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let parts: Vec<&str> = s.splitn(3, '-').collect();
    if parts.len() != 3 {
        return false;
    }
    parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
}

fn days_to_ymd(mut days: u64) -> (u32, u32, u32) {
    let mut year = 1970u32;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let dim = [
        31u64,
        if is_leap(year) { 29 } else { 28 },
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
    let mut month = 1u32;
    for &d in &dim {
        if days < d {
            break;
        }
        days -= d;
        month += 1;
    }
    (year, month, days as u32 + 1)
}

fn is_leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
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
            id: id.to_string(),
            summary: None,
            cvss_vector: None,
            severity: Some(severity.to_string()),
            fixed_version: None,
        }
    }

    #[test]
    fn deny_blocks_regardless_of_vulns() {
        let policy: PolicyFile = toml::from_str(
            r#"
            [[deny]]
            package = "event-stream"
            reason = "supply chain"
            "#,
        )
        .unwrap();
        let pd = evaluate(&policy, "event-stream", &[], "high");
        assert!(pd.denied);
        assert_eq!(pd.deny_reason.as_deref(), Some("supply chain"));
    }

    #[test]
    fn deny_is_case_insensitive() {
        let policy: PolicyFile = toml::from_str(
            r#"
            [[deny]]
            package = "Event-Stream"
            "#,
        )
        .unwrap();
        let pd = evaluate(&policy, "event-stream", &[], "high");
        assert!(pd.denied);
    }

    #[test]
    fn ignore_suppresses_cve() {
        let policy: PolicyFile = toml::from_str(
            r#"
            [[ignore]]
            cve = "CVE-2023-1234"
            "#,
        )
        .unwrap();
        let vulns = vec![vuln("CVE-2023-1234", "HIGH"), vuln("CVE-2024-0001", "LOW")];
        let pd = evaluate(&policy, "requests", &vulns, "high");
        assert!(!pd.denied);
        assert_eq!(pd.filtered_vulns.len(), 1);
        assert_eq!(pd.filtered_vulns[0].id, "CVE-2024-0001");
    }

    #[test]
    fn expired_ignore_reactivates_finding() {
        let policy: PolicyFile = toml::from_str(
            r#"
            [[ignore]]
            cve = "CVE-2023-1234"
            expires = "2020-01-01"
            "#,
        )
        .unwrap();
        let vulns = vec![vuln("CVE-2023-1234", "HIGH")];
        let pd = evaluate(&policy, "requests", &vulns, "high");
        assert_eq!(pd.filtered_vulns.len(), 1);
        assert_eq!(pd.expired_warnings.len(), 1);
        assert!(pd.expired_warnings[0].contains("re-activated"));
    }

    #[test]
    fn override_sets_package_threshold() {
        let policy: PolicyFile = toml::from_str(
            r#"
            [[override]]
            package = "requests"
            threshold = "critical"
            "#,
        )
        .unwrap();
        let pd = evaluate(&policy, "requests", &[], "high");
        assert_eq!(pd.threshold, "critical");
    }

    #[test]
    fn global_policy_threshold_overrides_base() {
        let policy: PolicyFile = toml::from_str(
            r#"
            [policy]
            threshold = "medium"
            "#,
        )
        .unwrap();
        let pd = evaluate(&policy, "anything", &[], "high");
        assert_eq!(pd.threshold, "medium");
    }

    #[test]
    fn override_takes_precedence_over_global() {
        let policy: PolicyFile = toml::from_str(
            r#"
            [policy]
            threshold = "medium"

            [[override]]
            package = "requests"
            threshold = "critical"
            "#,
        )
        .unwrap();
        let pd = evaluate(&policy, "requests", &[], "high");
        assert_eq!(pd.threshold, "critical");
    }

    #[test]
    fn today_str_looks_like_iso_date() {
        let d = today_str();
        assert_eq!(d.len(), 10);
        assert!(d.chars().nth(4) == Some('-'));
        assert!(d.chars().nth(7) == Some('-'));
    }

    #[test]
    fn is_valid_date_rejects_bad_formats() {
        assert!(!is_valid_date("2024/01/01"));
        assert!(!is_valid_date("24-01-01"));
        assert!(!is_valid_date("2024-1-1"));
        assert!(is_valid_date("2024-01-01"));
        assert!(is_valid_date("2030-12-31"));
    }

    #[test]
    fn check_file_rejects_invalid_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".primer-policy.toml");
        std::fs::write(&path, "[policy]\nthreshold = \"extreme\"\n").unwrap();
        assert!(check_file(&path).is_err());
    }

    #[test]
    fn check_file_accepts_valid_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".primer-policy.toml");
        std::fs::write(
            &path,
            r#"
[policy]
threshold = "medium"

[[ignore]]
cve = "CVE-2023-1234"
expires = "2030-01-01"

[[deny]]
package = "event-stream"

[[override]]
package = "requests"
threshold = "critical"
"#,
        )
        .unwrap();
        assert!(check_file(&path).is_ok());
    }
}
