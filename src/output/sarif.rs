use serde_json::{Value, json};

use crate::prompt::AuditFinding;

fn severity_to_level(label: &str) -> &'static str {
    match label {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        _ => "note",
    }
}

/// Build a SARIF 2.1.0 JSON value from audit findings.
pub fn build(findings: &[AuditFinding], manifest_path: &str) -> Value {
    let mut rules: Vec<Value> = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();

    for f in findings {
        for v in &f.vulns {
            if seen_rules.insert(v.id.clone()) {
                rules.push(json!({
                    "id": v.id,
                    "shortDescription": {
                        "text": v.summary.as_deref().unwrap_or(v.id.as_str())
                    },
                    "helpUri": format!("https://osv.dev/vulnerability/{}", v.id),
                    "properties": {
                        "severity": v.severity_label()
                    }
                }));
            }
        }
    }

    let mut results: Vec<Value> = Vec::new();
    for f in findings {
        for v in &f.vulns {
            let mut result = json!({
                "ruleId": v.id,
                "level": severity_to_level(v.severity_label()),
                "message": {
                    "text": format!(
                        "{} found in {} ({}){}",
                        v.id,
                        f.package,
                        f.ecosystem,
                        v.summary.as_deref()
                            .map(|s| format!(": {}", s))
                            .unwrap_or_default()
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": manifest_path,
                            "uriBaseId": "%SRCROOT%"
                        }
                    }
                }]
            });

            if let Some(fv) = &v.fixed_version {
                result["fixes"] = json!([{
                    "description": {
                        "text": format!("Upgrade {} to {}", f.package, fv)
                    },
                    "artifactChanges": []
                }]);
            }

            results.push(result);
        }
    }

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "primer",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/barestripehq/primer",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

/// Returns true if any result in the SARIF document has level "error" (CRITICAL/HIGH).
pub fn has_blocking(sarif: &Value) -> bool {
    sarif["runs"][0]["results"]
        .as_array()
        .map(|r| r.iter().any(|res| res["level"] == "error"))
        .unwrap_or(false)
}
