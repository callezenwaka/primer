use anyhow::Result;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run() -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // EOF — host closed the pipe
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(resp) = dispatch(trimmed).await {
            stdout.write_all(resp.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 dispatcher
// ---------------------------------------------------------------------------

async fn dispatch(input: &str) -> Option<String> {
    let msg: Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(_) => return Some(json_error(Value::Null, -32700, "Parse error")),
    };

    let method = match msg["method"].as_str() {
        Some(m) => m,
        None => {
            return Some(json_error(
                msg.get("id").cloned().unwrap_or(Value::Null),
                -32600,
                "Invalid request: missing method",
            ));
        }
    };

    let id = msg.get("id").cloned();

    match method {
        "initialize" => {
            let id = id?;
            Some(json_ok(
                id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "primer",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                }),
            ))
        }

        // Notifications — no response
        "notifications/initialized" | "notifications/cancelled" => None,

        "tools/list" => {
            let id = id?;
            Some(json_ok(id, json!({"tools": [tool_def()]})))
        }

        "tools/call" => {
            let id = id?;
            let params = &msg["params"];
            let tool_name = params["name"].as_str().unwrap_or("");

            if tool_name != "scan_package" {
                return Some(json_error(id, -32601, "Unknown tool"));
            }

            let args = &params["arguments"];
            let name = match args["name"].as_str() {
                Some(n) => n,
                None => return Some(json_error(id, -32602, "Missing required argument: name")),
            };
            let ecosystem = match args["ecosystem"].as_str() {
                Some(e) => e,
                None => {
                    return Some(json_error(
                        id,
                        -32602,
                        "Missing required argument: ecosystem",
                    ));
                }
            };
            let version = args["version"].as_str();

            let result = call_scan_package(name, ecosystem, version).await;
            Some(json_ok(id, result))
        }

        _ => id.map(|i| json_error(i, -32601, "Method not found")),
    }
}

// ---------------------------------------------------------------------------
// scan_package tool
// ---------------------------------------------------------------------------

async fn call_scan_package(name: &str, ecosystem: &str, version: Option<&str>) -> Value {
    let ver_label = version.map(|v| format!(" {}", v)).unwrap_or_default();

    match crate::engine::osv::query(name, ecosystem, version, false).await {
        Ok(vulns) if vulns.is_empty() => {
            json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "✓ {}{} ({}): found 0 vulnerabilities — safe to install.",
                        name, ver_label, ecosystem,
                    ),
                }],
                "vulnerabilities": [],
                "summary": {"total": 0, "critical": 0, "high": 0, "blocking": false},
            })
        }

        Ok(vulns) => {
            let total = vulns.len();
            let critical = vulns
                .iter()
                .filter(|v| v.severity_label() == "CRITICAL")
                .count();
            let high = vulns
                .iter()
                .filter(|v| v.severity_label() == "HIGH")
                .count();

            let mut lines = vec![format!(
                "⚠ {}{} ({}) — found {} vulnerabilit{}:",
                name,
                ver_label,
                ecosystem,
                total,
                if total == 1 { "y" } else { "ies" },
            )];
            for v in &vulns {
                let mut line = format!("  [{}] {}", v.severity_label(), v.id);
                if let Some(s) = &v.summary {
                    line.push_str(&format!(" — {}", s));
                }
                if let Some(f) = &v.fixed_version {
                    line.push_str(&format!(" (Fixed in: {})", f));
                }
                lines.push(line);
            }

            let vuln_list: Vec<Value> = vulns
                .iter()
                .map(|v| {
                    json!({
                        "id": v.id,
                        "severity": v.severity_label(),
                        "summary": v.summary,
                        "fixed_version": v.fixed_version,
                    })
                })
                .collect();

            json!({
                "content": [{"type": "text", "text": lines.join("\n")}],
                "vulnerabilities": vuln_list,
                "summary": {
                    "total": total,
                    "critical": critical,
                    "high": high,
                    "blocking": critical + high > 0,
                },
            })
        }

        Err(e) => {
            json!({
                "content": [{
                    "type": "text",
                    "text": format!("⚠ Scan failed for {} ({}): {}", name, ecosystem, e),
                }],
                "isError": true,
            })
        }
    }
}

fn tool_def() -> Value {
    json!({
        "name": "scan_package",
        "description": "Scan a package for known vulnerabilities using the OSV database. Call this before installing any package to check if it has known CVEs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Package name (e.g. 'requests', 'express', 'lodash')",
                },
                "ecosystem": {
                    "type": "string",
                    "enum": ["PyPI", "npm", "Go", "crates.io"],
                    "description": "Package ecosystem",
                },
                "version": {
                    "type": "string",
                    "description": "Specific version to check (optional — omit to check latest)",
                },
            },
            "required": ["name", "ecosystem"],
        },
    })
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers
// ---------------------------------------------------------------------------

fn json_ok(id: Value, result: Value) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    }))
    .unwrap_or_default()
}

fn json_error(id: Value, code: i32, message: &str) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message},
    }))
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: u64, method: &str, params: Value) -> String {
        serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .unwrap()
    }

    fn notif(method: &str) -> String {
        serde_json::to_string(&json!({"jsonrpc": "2.0", "method": method})).unwrap()
    }

    #[tokio::test]
    async fn initialize_returns_server_info() {
        let input = req(
            1,
            "initialize",
            json!({"protocolVersion": "2024-11-05", "capabilities": {}}),
        );
        let resp = dispatch(&input).await.unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["serverInfo"]["name"], "primer");
        assert_eq!(v["id"], 1);
    }

    #[tokio::test]
    async fn initialize_includes_capabilities() {
        let input = req(1, "initialize", json!({}));
        let resp = dispatch(&input).await.unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v["result"]["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn tools_list_returns_scan_package() {
        let input = req(2, "tools/list", json!({}));
        let resp = dispatch(&input).await.unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        let tools = v["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "scan_package");
    }

    #[tokio::test]
    async fn tools_list_includes_input_schema() {
        let input = req(2, "tools/list", json!({}));
        let resp = dispatch(&input).await.unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        let schema = &v["result"]["tools"][0]["inputSchema"];
        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("name")));
        assert!(required.contains(&json!("ecosystem")));
    }

    #[tokio::test]
    async fn initialized_notification_returns_none() {
        assert!(
            dispatch(&notif("notifications/initialized"))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn cancelled_notification_returns_none() {
        assert!(dispatch(&notif("notifications/cancelled")).await.is_none());
    }

    #[tokio::test]
    async fn unknown_tool_returns_error() {
        let input = req(
            3,
            "tools/call",
            json!({"name": "unknown_tool", "arguments": {}}),
        );
        let resp = dispatch(&input).await.unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Unknown tool")
        );
    }

    #[tokio::test]
    async fn missing_name_argument_returns_error() {
        let input = req(
            4,
            "tools/call",
            json!({"name": "scan_package", "arguments": {"ecosystem": "PyPI"}}),
        );
        let resp = dispatch(&input).await.unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v["error"].is_object());
        assert!(v["error"]["message"].as_str().unwrap().contains("name"));
    }

    #[tokio::test]
    async fn missing_ecosystem_argument_returns_error() {
        let input = req(
            4,
            "tools/call",
            json!({"name": "scan_package", "arguments": {"name": "requests"}}),
        );
        let resp = dispatch(&input).await.unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("ecosystem")
        );
    }

    #[tokio::test]
    async fn parse_error_returns_code_32700() {
        let resp = dispatch("not valid json { at all").await.unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn unknown_method_returns_code_32601() {
        let input = req(5, "unknown/method", json!({}));
        let resp = dispatch(&input).await.unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn unknown_notification_returns_none() {
        let input = notif("notifications/unknown");
        // unknown notifications have no id, so we return None
        assert!(dispatch(&input).await.is_none());
    }

    #[test]
    fn tool_def_schema_is_valid() {
        let def = tool_def();
        assert_eq!(def["name"], "scan_package");
        assert!(def["description"].as_str().unwrap().len() > 10);
        let props = &def["inputSchema"]["properties"];
        assert!(props["name"].is_object());
        assert!(props["ecosystem"].is_object());
        assert!(props["version"].is_object());
    }
}
