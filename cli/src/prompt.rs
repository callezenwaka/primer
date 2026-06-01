use colored::Colorize;
use inquire::Confirm;

use crate::engine::osv::Vulnerability;

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum Decision {
    Proceed,
    Abort,
}

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

/// True when stdin is not a TTY or CI=true is set.
pub fn is_ci() -> bool {
    use std::io::IsTerminal;
    std::env::var("CI").is_ok() || !std::io::stdin().is_terminal()
}

pub fn ci_allow_all() -> bool {
    std::env::var("PRIMER_CI_MODE")
        .map(|v| v.to_lowercase() == "allow-all")
        .unwrap_or(false)
}

pub fn force_flag() -> bool {
    std::env::var("PRIMER_FORCE").is_ok()
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

/// Returns the effective threshold string from config, defaulting to "high".
pub fn effective_threshold() -> String {
    crate::config::load()
        .unwrap_or_default()
        .prompt_threshold
        .unwrap_or_else(|| "high".to_string())
}

fn is_blocking_at(label: &str, threshold: &str) -> bool {
    match threshold {
        "critical" => matches!(label, "CRITICAL"),
        "medium" => matches!(label, "CRITICAL" | "HIGH" | "MEDIUM"),
        "low" => matches!(label, "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"),
        _ => matches!(label, "CRITICAL" | "HIGH"), // "high" + unknown → default
    }
}

fn is_blocking(label: &str) -> bool {
    is_blocking_at(label, &effective_threshold())
}

fn severity_rank(label: &str) -> u8 {
    match label {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4, // UNSCORED last
    }
}

fn sorted_vulns(vulns: &[Vulnerability]) -> Vec<&Vulnerability> {
    let mut sorted: Vec<&Vulnerability> = vulns.iter().collect();
    sorted.sort_by_key(|v| severity_rank(v.severity_label()));
    sorted
}

fn color_severity(label: &str) -> colored::ColoredString {
    match label {
        "CRITICAL" => label.red().bold(),
        "HIGH" => label.yellow().bold(),
        "MEDIUM" => label.blue().bold(),
        "LOW" => label.green().bold(),
        _ => label.white().dimmed(), // UNSCORED and any future unknown values
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Evaluate findings and return whether the install should proceed.
/// Handles force, CI, and interactive modes.
pub fn evaluate(package: &str, ecosystem: &str, vulns: &[Vulnerability], force: bool) -> Decision {
    let policy = crate::policy::load();
    let pd = crate::policy::evaluate(&policy, package, vulns, &effective_threshold());

    for w in &pd.expired_warnings {
        eprintln!("{}", w.yellow());
    }

    if pd.denied {
        if let Some(reason) = &pd.deny_reason {
            eprintln!(
                "{} {} is denied by policy: {}",
                "✗".red().bold(),
                package.bold(),
                reason
            );
        } else {
            eprintln!(
                "{} {} is denied by policy (.primer-policy.toml)",
                "✗".red().bold(),
                package.bold()
            );
        }
        return Decision::Abort;
    }

    evaluate_inner(
        package,
        ecosystem,
        &pd.filtered_vulns,
        force || force_flag(),
        is_ci(),
        ci_allow_all(),
        &pd.threshold,
    )
}

/// Testable inner function with explicit flags instead of env var reads.
pub(crate) fn evaluate_inner(
    package: &str,
    ecosystem: &str,
    vulns: &[Vulnerability],
    force: bool,
    ci: bool,
    allow_all: bool,
    threshold: &str,
) -> Decision {
    if vulns.is_empty() {
        return Decision::Proceed;
    }

    let blocking: Vec<&Vulnerability> = vulns
        .iter()
        .filter(|v| is_blocking_at(v.severity_label(), threshold))
        .collect();

    if force {
        eprintln!(
            "{} {} {} {} — proceeding (--force)",
            "⚠".yellow(),
            blocking.len(),
            if blocking.len() == 1 {
                "blocking vulnerability"
            } else {
                "blocking vulnerabilities"
            },
            format!("in {}", package).bold(),
        );
        return Decision::Proceed;
    }

    if ci {
        return ci_decision_inner(package, ecosystem, vulns, &blocking, allow_all);
    }

    interactive_decision(package, ecosystem, vulns, &blocking)
}

// ---------------------------------------------------------------------------
// CI mode
// ---------------------------------------------------------------------------

fn ci_decision_inner(
    package: &str,
    ecosystem: &str,
    vulns: &[Vulnerability],
    blocking: &[&Vulnerability],
    allow_all: bool,
) -> Decision {
    if allow_all {
        eprintln!(
            "primer: PRIMER_CI_MODE=allow-all — scan skipped for {}",
            package
        );
        return Decision::Proceed;
    }

    // Print findings to stderr for CI logs.
    print_findings(package, ecosystem, vulns);

    if !blocking.is_empty() {
        // Write JSON report then block.
        if let Err(e) = crate::report::write(package, ecosystem, vulns) {
            eprintln!("primer: could not write report: {}", e);
        }
        eprintln!(
            "{} Blocking install of {} ({} CRITICAL/HIGH {}). Report: primer-report.json",
            "✗".red().bold(),
            package.bold(),
            blocking.len(),
            if blocking.len() == 1 {
                "finding"
            } else {
                "findings"
            },
        );
        return Decision::Abort;
    }

    Decision::Proceed
}

// ---------------------------------------------------------------------------
// Interactive mode
// ---------------------------------------------------------------------------

fn pm_install_hint(ecosystem: &str) -> &'static str {
    match ecosystem {
        "PyPI" => "pip install",
        "npm" => "npm install",
        "Go" => "go get",
        "crates.io" => "cargo add",
        _ => "install",
    }
}

fn fix_command(ecosystem: &str, package: &str, fixed_version: &str) -> String {
    match ecosystem {
        "PyPI" => format!("pip install \"{}>={}\"", package, fixed_version),
        "npm" => format!("npm install {}@{}", package, fixed_version),
        "Go" => format!("go get {}@v{}", package, fixed_version),
        "crates.io" => format!("cargo update -p {} --precise {}", package, fixed_version),
        _ => format!("install {}@{}", package, fixed_version),
    }
}

fn interactive_decision(
    package: &str,
    ecosystem: &str,
    vulns: &[Vulnerability],
    blocking: &[&Vulnerability],
) -> Decision {
    // Header.
    eprintln!();
    eprintln!(
        "{} {} {} found for {}",
        "⚠".yellow().bold(),
        vulns.len(),
        if vulns.len() == 1 {
            "vulnerability"
        } else {
            "vulnerabilities"
        },
        package.bold(),
    );
    eprintln!();

    // Show top-level CVE list sorted CRITICAL → HIGH → MEDIUM → LOW → UNSCORED.
    let sorted = sorted_vulns(vulns);
    for v in sorted.iter().take(5) {
        let id_link = crate::output::hyperlink::cve_link(&v.id);
        eprintln!("  [{}] {}", color_severity(v.severity_label()), id_link);
        if let Some(s) = &v.summary {
            eprintln!("       {}", s.dimmed());
        }
    }
    if vulns.len() > 5 {
        eprintln!("  … and {} more", vulns.len() - 5);
    }
    eprintln!();

    // Prompt 1: offer full details.
    let show_details = Confirm::new("View full vulnerability details?")
        .with_default(false)
        .prompt()
        .unwrap_or(false);

    if show_details {
        eprintln!();
        print_findings(package, ecosystem, vulns);
    }

    if blocking.is_empty() {
        // No blocking findings — no need to prompt further.
        return Decision::Proceed;
    }

    eprintln!();
    eprintln!(
        "  {} {} CRITICAL/HIGH {} detected.",
        "!".red().bold(),
        blocking.len(),
        if blocking.len() == 1 {
            "vulnerability"
        } else {
            "vulnerabilities"
        },
    );
    eprintln!();

    // Prompt 2: continue or abort.
    let proceed = Confirm::new("Continue install anyway?")
        .with_default(false)
        .prompt()
        .unwrap_or(false);

    eprintln!();

    if proceed {
        Decision::Proceed
    } else {
        // Show the fix command for the highest-severity blocking vuln that has one.
        let mut sorted_blocking = blocking.to_vec();
        sorted_blocking.sort_by_key(|v| severity_rank(v.severity_label()));
        let fix_hint = sorted_blocking.into_iter().find_map(|v| {
            v.fixed_version
                .as_deref()
                .map(|fv| fix_command(ecosystem, package, fv))
        });
        if let Some(cmd) = fix_hint {
            eprintln!("  Fix:     {}", cmd.green().bold());
        }
        eprintln!(
            "  Aborted. To bypass: {} {} {}",
            "PRIMER_FORCE=1".dimmed(),
            pm_install_hint(ecosystem),
            package,
        );
        Decision::Abort
    }
}

// ---------------------------------------------------------------------------
// Audit summary mode (scan --file: collect all findings, print table, no prompts)
// ---------------------------------------------------------------------------

pub struct AuditFinding {
    pub package: String,
    pub ecosystem: String,
    pub vulns: Vec<Vulnerability>,
}

/// Print a consolidated findings table and return whether any are blocking.
/// No interactive prompts — used by `primer scan --file`.
pub fn audit_summary(findings: &[AuditFinding]) -> Decision {
    let base_threshold = effective_threshold();
    let policy = crate::policy::load();
    let mut any_blocking = false;

    let has_findings = findings.iter().any(|f| !f.vulns.is_empty());
    if !has_findings {
        return Decision::Proceed;
    }

    eprintln!();
    for f in findings {
        if f.vulns.is_empty() {
            continue;
        }

        let pd = crate::policy::evaluate(&policy, &f.package, &f.vulns, &base_threshold);

        for w in &pd.expired_warnings {
            eprintln!("{}", w.yellow());
        }

        if pd.denied {
            any_blocking = true;
            if let Some(reason) = &pd.deny_reason {
                eprintln!(
                    "{} {} is denied by policy: {}",
                    "✗".red().bold(),
                    f.package.bold(),
                    reason
                );
            } else {
                eprintln!(
                    "{} {} is denied by policy (.primer-policy.toml)",
                    "✗".red().bold(),
                    f.package.bold()
                );
            }
            eprintln!();
            continue;
        }

        if pd.filtered_vulns.is_empty() {
            continue;
        }

        let threshold = &pd.threshold;
        let blocking_count = pd
            .filtered_vulns
            .iter()
            .filter(|v| is_blocking_at(v.severity_label(), threshold))
            .count();
        if blocking_count > 0 {
            any_blocking = true;
        }
        eprintln!(
            "{} {} ({}) — {} {}",
            "⚠".yellow().bold(),
            f.package.bold(),
            f.ecosystem,
            pd.filtered_vulns.len(),
            if pd.filtered_vulns.len() == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            },
        );
        for v in sorted_vulns(&pd.filtered_vulns) {
            let blocking_marker = if is_blocking_at(v.severity_label(), threshold) {
                " BLOCKS".red().bold().to_string()
            } else {
                String::new()
            };
            let id_link = crate::output::hyperlink::cve_link(&v.id);
            eprintln!(
                "  [{}]{} {}",
                color_severity(v.severity_label()),
                blocking_marker,
                id_link.bold(),
            );
            if let Some(s) = &v.summary {
                eprintln!("       {}", s.dimmed());
            }
            if let Some(fv) = &v.fixed_version {
                eprintln!(
                    "       Fix: {}",
                    fix_command(&f.ecosystem, &f.package, fv).green().bold()
                );
            }
        }
        eprintln!();
    }

    if any_blocking {
        eprintln!(
            "{} Blocking findings detected. Resolve before proceeding.",
            "✗".red().bold()
        );
        Decision::Abort
    } else {
        Decision::Proceed
    }
}

// ---------------------------------------------------------------------------
// Numbered finding navigation (scan --file, TTY + non-CI only)
// ---------------------------------------------------------------------------

/// After `audit_summary`, offer a numbered pick-list so the user can drill into
/// individual findings.  Skipped silently in CI or when stdin is not a TTY.
pub fn audit_navigate(findings: &[AuditFinding]) {
    use std::io::IsTerminal;
    if is_ci() || !std::io::stdin().is_terminal() {
        return;
    }
    let with_vulns: Vec<&AuditFinding> = findings.iter().filter(|f| !f.vulns.is_empty()).collect();
    if with_vulns.is_empty() {
        return;
    }

    eprintln!();
    eprintln!("  Findings:");
    for (i, f) in with_vulns.iter().enumerate() {
        eprintln!(
            "  [{}] {} — {} {}",
            i + 1,
            f.package,
            f.vulns.len(),
            if f.vulns.len() == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            }
        );
    }
    eprintln!();

    loop {
        eprint!("  Enter number for details, [a]ll, [q]uit: ");
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            break;
        }
        let input = input.trim();
        match input {
            "q" | "Q" | "" => break,
            "a" | "A" => {
                for f in &with_vulns {
                    print_findings(&f.package, &f.ecosystem, &f.vulns);
                }
                break;
            }
            s => {
                if let Ok(n) = s.parse::<usize>() {
                    if n >= 1 && n <= with_vulns.len() {
                        let f = with_vulns[n - 1];
                        print_findings(&f.package, &f.ecosystem, &f.vulns);
                    } else {
                        eprintln!(
                            "  Invalid number. Enter 1–{}, [a]ll, or [q]uit.",
                            with_vulns.len()
                        );
                    }
                } else {
                    eprintln!("  Unknown input. Enter a number, [a]ll, or [q]uit.");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Post-install report (no prompt — package already installed)
// ---------------------------------------------------------------------------

fn pm_remove_hint(ecosystem: &str) -> &'static str {
    match ecosystem {
        "PyPI" => "pip uninstall",
        "npm" => "npm uninstall",
        "Go" => "go mod edit -droprequire",
        "crates.io" => "cargo remove",
        _ => "uninstall",
    }
}

/// Report vulnerabilities found in a post-install transitive package without
/// prompting (since the package is already installed).  Returns `true` if
/// blocking (CRITICAL/HIGH) findings were detected.
pub fn report_post_install(package: &str, ecosystem: &str, vulns: &[Vulnerability]) -> bool {
    if vulns.is_empty() {
        return false;
    }

    let blocking: Vec<&Vulnerability> = vulns
        .iter()
        .filter(|v| is_blocking(v.severity_label()))
        .collect();

    print_findings(package, ecosystem, vulns);

    if !blocking.is_empty() {
        eprintln!(
            "  {} {} is installed but has {} CRITICAL/HIGH {}.",
            "⚠".yellow(),
            package.bold(),
            blocking.len(),
            if blocking.len() == 1 {
                "vulnerability"
            } else {
                "vulnerabilities"
            },
        );
        eprintln!("  Consider: {} {}", pm_remove_hint(ecosystem), package);
        eprintln!();
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// Shared display
// ---------------------------------------------------------------------------

fn print_findings(package: &str, ecosystem: &str, vulns: &[Vulnerability]) {
    let pkg_display = crate::output::hyperlink::package_link(package, ecosystem);
    eprintln!("  Security findings for {}:\n", pkg_display.bold());
    for v in sorted_vulns(vulns) {
        let id_link = crate::output::hyperlink::cve_link(&v.id);
        eprintln!(
            "  [{}] {}",
            color_severity(v.severity_label()),
            id_link.bold()
        );
        if let Some(s) = &v.summary {
            eprintln!("       {}", s);
        }
        if let Some(cv) = &v.cvss_vector {
            eprintln!("       CVSS: {}", cv.dimmed());
        }
        if let Some(fv) = &v.fixed_version {
            eprintln!("       Fixed in: {}", fv.green());
            eprintln!(
                "       Fix:      {}",
                fix_command(ecosystem, package, fv).green().bold()
            );
        }
        eprintln!();
    }
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
            summary: Some(format!("Test vuln {}", id)),
            cvss_vector: None,
            severity: Some(severity.to_owned()),
            fixed_version: None,
        }
    }

    #[test]
    fn empty_vulns_always_proceeds() {
        assert_eq!(evaluate("pkg", "PyPI", &[], false), Decision::Proceed);
    }

    #[test]
    fn force_true_proceeds_despite_critical() {
        let vulns = vec![vuln("GHSA-0001", "CRITICAL")];
        assert_eq!(evaluate("pkg", "PyPI", &vulns, true), Decision::Proceed);
    }

    #[test]
    fn ci_allow_all_proceeds() {
        let vulns = vec![vuln("GHSA-0001", "CRITICAL")];
        assert_eq!(
            evaluate_inner("pkg", "PyPI", &vulns, false, true, true, "high"),
            Decision::Proceed
        );
    }

    #[test]
    fn ci_blocks_on_critical() {
        let vulns = vec![vuln("GHSA-0001", "CRITICAL")];
        assert_eq!(
            evaluate_inner("pkg", "PyPI", &vulns, false, true, false, "high"),
            Decision::Abort
        );
    }

    #[test]
    fn ci_proceeds_on_low_only() {
        let vulns = vec![vuln("GHSA-0001", "LOW")];
        assert_eq!(
            evaluate_inner("pkg", "PyPI", &vulns, false, true, false, "high"),
            Decision::Proceed
        );
    }

    #[test]
    fn ci_proceeds_on_medium_only() {
        let vulns = vec![vuln("GHSA-0001", "MEDIUM")];
        assert_eq!(
            evaluate_inner("pkg", "PyPI", &vulns, false, true, false, "high"),
            Decision::Proceed
        );
    }

    #[test]
    fn threshold_medium_blocks_medium() {
        let vulns = vec![vuln("GHSA-0001", "MEDIUM")];
        assert_eq!(
            evaluate_inner("pkg", "PyPI", &vulns, false, true, false, "medium"),
            Decision::Abort
        );
    }

    #[test]
    fn threshold_critical_passes_high() {
        let vulns = vec![vuln("GHSA-0001", "HIGH")];
        assert_eq!(
            evaluate_inner("pkg", "PyPI", &vulns, false, true, false, "critical"),
            Decision::Proceed
        );
    }

    #[test]
    fn threshold_low_blocks_low() {
        let vulns = vec![vuln("GHSA-0001", "LOW")];
        assert_eq!(
            evaluate_inner("pkg", "PyPI", &vulns, false, true, false, "low"),
            Decision::Abort
        );
    }

    #[test]
    fn is_blocking_at_high_threshold() {
        assert!(is_blocking_at("CRITICAL", "high"));
        assert!(is_blocking_at("HIGH", "high"));
        assert!(!is_blocking_at("MEDIUM", "high"));
        assert!(!is_blocking_at("LOW", "high"));
        assert!(!is_blocking_at("UNSCORED", "high"));
    }

    #[test]
    fn is_blocking_at_critical_threshold() {
        assert!(is_blocking_at("CRITICAL", "critical"));
        assert!(!is_blocking_at("HIGH", "critical"));
        assert!(!is_blocking_at("MEDIUM", "critical"));
    }

    #[test]
    fn is_blocking_at_medium_threshold() {
        assert!(is_blocking_at("CRITICAL", "medium"));
        assert!(is_blocking_at("HIGH", "medium"));
        assert!(is_blocking_at("MEDIUM", "medium"));
        assert!(!is_blocking_at("LOW", "medium"));
    }

    #[test]
    fn is_blocking_at_low_threshold() {
        assert!(is_blocking_at("LOW", "low"));
        assert!(is_blocking_at("MEDIUM", "low"));
    }

    #[test]
    fn audit_navigate_skips_when_no_findings() {
        // audit_navigate should return immediately (no panic, no I/O) when
        // all findings have empty vuln lists — in CI stdin is never a TTY.
        let findings: Vec<AuditFinding> = vec![AuditFinding {
            package: "clean-pkg".into(),
            ecosystem: "npm".into(),
            vulns: vec![],
        }];
        audit_navigate(&findings); // must not block or panic
    }

    #[test]
    fn audit_navigate_skips_in_ci_environment() {
        // In the test environment stdin is not a TTY, so audit_navigate must
        // return without attempting to read input.
        let vulns = vec![Vulnerability {
            id: "GHSA-0001".into(),
            summary: Some("test".into()),
            cvss_vector: None,
            severity: Some("HIGH".into()),
            fixed_version: None,
        }];
        let findings = vec![AuditFinding {
            package: "vuln-pkg".into(),
            ecosystem: "npm".into(),
            vulns,
        }];
        audit_navigate(&findings); // must not block
    }
}
