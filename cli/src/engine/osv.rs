use anyhow::Result;
use serde::{Deserialize, Serialize};

const OSV_API_BASE: &str = "https://api.osv.dev/v1";

#[derive(Debug, Serialize)]
struct OsvRequest<'a> {
    package: OsvPackage<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct OsvPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    database_specific: Option<OsvDbSpecific>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvDbSpecific {
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
}

/// A normalised vulnerability returned to callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: Option<String>,
    pub cvss_vector: Option<String>,
    /// Plain-text severity from database_specific (e.g. "CRITICAL", "HIGH").
    pub severity: Option<String>,
    /// First fixed version found in affected[].ranges[].events, if any.
    #[serde(default)]
    pub fixed_version: Option<String>,
}

impl Vulnerability {
    pub fn severity_label(&self) -> &str {
        match self.severity.as_deref().map(|s| s.to_uppercase()) {
            Some(ref s) if s == "CRITICAL" => "CRITICAL",
            Some(ref s) if s == "HIGH" => "HIGH",
            Some(ref s) if s == "MODERATE" || s == "MEDIUM" => "MEDIUM",
            Some(ref s) if s == "LOW" => "LOW",
            _ => "UNSCORED",
        }
    }
}

/// Query OSV for vulnerabilities affecting `package` in `ecosystem`.
/// Checks the local cache first; writes results back on a network hit.
/// Falls back to stale cache if the network is unreachable.
/// Returns `Err` only when both network and cache are unavailable.
pub async fn query(
    package: &str,
    ecosystem: &str,
    version: Option<&str>,
    verbose: bool,
) -> Result<Vec<Vulnerability>> {
    query_inner(
        OSV_API_BASE,
        &crate::cache::cache_dir(),
        package,
        ecosystem,
        version,
        verbose,
    )
    .await
}

/// Testable variant — accepts injectable base URL and cache directory.
pub(crate) async fn query_inner(
    base_url: &str,
    cache_dir: &std::path::Path,
    package: &str,
    ecosystem: &str,
    version: Option<&str>,
    verbose: bool,
) -> Result<Vec<Vulnerability>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Some(vulns) = crate::cache::get_from_dir(cache_dir, package, ecosystem, version, now) {
        if verbose {
            eprintln!("primer: cache hit — {} ({})", package, ecosystem);
        }
        return Ok(vulns);
    }

    if verbose {
        eprintln!("primer: fetching {} ({}) from OSV", package, ecosystem);
    }

    match query_with_base(base_url, package, ecosystem, version).await {
        Ok(vulns) => {
            if let Err(e) =
                crate::cache::put_to_dir(cache_dir, package, ecosystem, version, &vulns, now)
            {
                eprintln!("primer: cache write failed: {}", e);
            }
            Ok(vulns)
        }
        Err(e) => {
            if let Some(vulns) =
                crate::cache::get_stale_from_dir(cache_dir, package, ecosystem, version)
            {
                eprintln!(
                    "⚠  primer: OSV unreachable ({}), using stale cache for {}",
                    e, package
                );
                return Ok(vulns);
            }
            Err(e)
        }
    }
}

/// Same as `query` but accepts a custom base URL — used in tests.
pub async fn query_with_base(
    base_url: &str,
    package: &str,
    ecosystem: &str,
    version: Option<&str>,
) -> Result<Vec<Vulnerability>> {
    let client = reqwest::Client::new();

    let body = OsvRequest {
        package: OsvPackage {
            name: package,
            ecosystem,
        },
        version,
    };

    let url = format!("{}/query", base_url.trim_end_matches('/'));

    let resp: OsvResponse = client
        .post(&url)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let vulns = resp
        .vulns
        .into_iter()
        .map(|v| {
            let fixed_version = v
                .affected
                .iter()
                .flat_map(|a| a.ranges.iter())
                .flat_map(|r| r.events.iter())
                .find_map(|e| e.fixed.clone());
            Vulnerability {
                id: v.id,
                summary: v.summary,
                cvss_vector: v
                    .severity
                    .into_iter()
                    .find(|s| s.kind.starts_with("CVSS"))
                    .map(|s| s.score),
                severity: v.database_specific.and_then(|d| d.severity),
                fixed_version,
            }
        })
        .collect();

    Ok(vulns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn vuln(severity: Option<&str>) -> Vulnerability {
        Vulnerability {
            id: "GHSA-test-0000-0000".into(),
            summary: Some("Test vulnerability".into()),
            cvss_vector: None,
            severity: severity.map(str::to_owned),
            fixed_version: None,
        }
    }

    // --- severity_label unit tests ---

    #[test]
    fn severity_critical() {
        assert_eq!(vuln(Some("CRITICAL")).severity_label(), "CRITICAL");
    }

    #[test]
    fn severity_high() {
        assert_eq!(vuln(Some("HIGH")).severity_label(), "HIGH");
    }

    #[test]
    fn severity_moderate_maps_to_medium() {
        assert_eq!(vuln(Some("MODERATE")).severity_label(), "MEDIUM");
    }

    #[test]
    fn severity_medium() {
        assert_eq!(vuln(Some("MEDIUM")).severity_label(), "MEDIUM");
    }

    #[test]
    fn severity_low() {
        assert_eq!(vuln(Some("LOW")).severity_label(), "LOW");
    }

    #[test]
    fn severity_none_is_unscored() {
        assert_eq!(vuln(None).severity_label(), "UNSCORED");
    }

    #[test]
    fn severity_label_is_case_insensitive() {
        assert_eq!(vuln(Some("critical")).severity_label(), "CRITICAL");
        assert_eq!(vuln(Some("High")).severity_label(), "HIGH");
        assert_eq!(vuln(Some("moderate")).severity_label(), "MEDIUM");
    }

    // --- HTTP layer tests (mockito) ---

    #[tokio::test]
    async fn returns_empty_vec_when_osv_has_no_vulns() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("POST", "/query")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{}"#)
            .create_async()
            .await;

        let result = query_with_base(&server.url(), "safe-package", "PyPI", None).await;
        mock.assert_async().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn parses_vulnerability_fields_correctly() {
        let mut server = Server::new_async().await;
        let body = r#"{
            "vulns": [{
                "id": "GHSA-test-1234-5678",
                "summary": "Remote code execution in test-pkg",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "database_specific": {"severity": "CRITICAL"}
            }]
        }"#;

        let mock = server
            .mock("POST", "/query")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let vulns = query_with_base(&server.url(), "test-pkg", "PyPI", None)
            .await
            .unwrap();
        mock.assert_async().await;

        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].id, "GHSA-test-1234-5678");
        assert_eq!(
            vulns[0].summary.as_deref(),
            Some("Remote code execution in test-pkg")
        );
        assert_eq!(vulns[0].severity.as_deref(), Some("CRITICAL"));
        assert!(
            vulns[0]
                .cvss_vector
                .as_deref()
                .unwrap()
                .starts_with("CVSS:3.1")
        );
        assert_eq!(vulns[0].severity_label(), "CRITICAL");
    }

    #[tokio::test]
    async fn pysec_entries_without_database_specific_show_unscored() {
        let mut server = Server::new_async().await;
        let body = r#"{
            "vulns": [{
                "id": "PYSEC-2023-74",
                "summary": null,
                "severity": [],
                "database_specific": null
            }]
        }"#;

        let mock = server
            .mock("POST", "/query")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let vulns = query_with_base(&server.url(), "requests", "PyPI", None)
            .await
            .unwrap();
        mock.assert_async().await;

        assert_eq!(vulns[0].severity_label(), "UNSCORED");
    }

    #[tokio::test]
    async fn extracts_fixed_version_from_affected_ranges() {
        let mut server = Server::new_async().await;
        let body = r#"{
            "vulns": [{
                "id": "GHSA-fixed-0001",
                "summary": "Test",
                "severity": [],
                "database_specific": {"severity": "HIGH"},
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "9.1.0"}
                        ]
                    }]
                }]
            }]
        }"#;
        let mock = server
            .mock("POST", "/query")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let vulns = query_with_base(&server.url(), "test-pkg", "PyPI", None)
            .await
            .unwrap();
        mock.assert_async().await;

        assert_eq!(vulns[0].fixed_version.as_deref(), Some("9.1.0"));
    }

    #[tokio::test]
    async fn fixed_version_is_none_when_not_present() {
        let mut server = Server::new_async().await;
        let body = r#"{"vulns":[{"id":"GHSA-no-fix","summary":null,"severity":[],"database_specific":{"severity":"HIGH"}}]}"#;
        let mock = server
            .mock("POST", "/query")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let vulns = query_with_base(&server.url(), "test-pkg", "PyPI", None)
            .await
            .unwrap();
        mock.assert_async().await;

        assert!(vulns[0].fixed_version.is_none());
    }

    #[tokio::test]
    async fn returns_err_on_network_failure() {
        // Point at a port nothing is listening on.
        let result = query_with_base("http://127.0.0.1:1", "requests", "PyPI", None).await;
        assert!(result.is_err());
    }

    // --- Cache integration tests ---

    #[tokio::test]
    async fn query_inner_returns_cached_result_without_hitting_network() {
        let dir = tempfile::tempdir().unwrap();
        let cached = vec![Vulnerability {
            id: "GHSA-cached".into(),
            summary: None,
            cvss_vector: None,
            severity: Some("HIGH".into()),
            fixed_version: None,
        }];
        crate::cache::put_to_dir(dir.path(), "requests", "PyPI", None, &cached, 1000).unwrap();

        // Dead URL — would error if network were reached.
        let result = query_inner(
            "http://127.0.0.1:1",
            dir.path(),
            "requests",
            "PyPI",
            None,
            false,
        )
        .await
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "GHSA-cached");
    }

    #[tokio::test]
    async fn query_inner_uses_stale_cache_on_network_failure() {
        let dir = tempfile::tempdir().unwrap();
        let stale = vec![Vulnerability {
            id: "GHSA-stale".into(),
            summary: None,
            cvss_vector: None,
            severity: Some("CRITICAL".into()),
            fixed_version: None,
        }];
        // Write with timestamp=0 so entry is expired (age >> TTL).
        crate::cache::put_to_dir(dir.path(), "requests", "PyPI", None, &stale, 0).unwrap();

        // Dead URL triggers network error → should fall back to stale entry.
        let result = query_inner(
            "http://127.0.0.1:1",
            dir.path(),
            "requests",
            "PyPI",
            None,
            false,
        )
        .await
        .unwrap();

        assert_eq!(result[0].id, "GHSA-stale");
    }

    #[tokio::test]
    async fn query_inner_writes_network_result_to_cache() {
        let mut server = Server::new_async().await;
        let body = r#"{"vulns":[{"id":"GHSA-net-0001","summary":null,"severity":[],"database_specific":{"severity":"LOW"}}]}"#;
        let mock = server
            .mock("POST", "/query")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;

        let dir = tempfile::tempdir().unwrap();
        let result = query_inner(&server.url(), dir.path(), "newpkg", "PyPI", None, false)
            .await
            .unwrap();
        mock.assert_async().await;

        assert_eq!(result[0].id, "GHSA-net-0001");

        // Verify the entry was written to cache.
        let cached = crate::cache::get_stale_from_dir(dir.path(), "newpkg", "PyPI", None);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap()[0].id, "GHSA-net-0001");
    }

    // --- Live API tests (opt-in, not run in CI) ---

    #[tokio::test]
    #[ignore = "hits live OSV API — run with: cargo test -- --ignored"]
    async fn live_pillow_9_0_0_has_critical_vulns() {
        let vulns = query("pillow", "PyPI", Some("9.0.0"), false).await.unwrap();
        assert!(
            !vulns.is_empty(),
            "expected vulnerabilities for pillow 9.0.0"
        );
        let has_critical = vulns.iter().any(|v| v.severity_label() == "CRITICAL");
        assert!(has_critical, "expected at least one CRITICAL finding");
    }

    #[tokio::test]
    #[ignore = "hits live OSV API — run with: cargo test -- --ignored"]
    async fn live_nonexistent_package_returns_empty() {
        let vulns = query("zzz-nonexistent-pkg-primer", "PyPI", None, false)
            .await
            .unwrap();
        assert!(vulns.is_empty());
    }
}
