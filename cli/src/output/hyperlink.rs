use std::io::IsTerminal;

fn is_tty() -> bool {
    std::io::stdout().is_terminal()
}

/// Wrap `text` in an OSC 8 terminal hyperlink pointing to `url`.
/// Returns plain `text` unchanged when stdout is not a TTY (CI, pipes, JSON).
pub fn hyperlink(text: &str, url: &str) -> String {
    if !is_tty() {
        return text.to_string();
    }
    format!("\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\", url, text)
}

/// CVE / GHSA ID → OSC 8 hyperlink (for iTerm2/Warp) plus plain URL (for Terminal.app
/// and any other terminal that auto-detects URLs but ignores OSC 8 escape sequences).
pub fn cve_link(id: &str) -> String {
    let url = format!("https://osv.dev/vulnerability/{}", id);
    if !is_tty() {
        return id.to_string();
    }
    let linked_id = format!("\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\", url, id);
    // Dim the URL so it is present but doesn't compete with the severity label.
    format!("{}  \x1b[2m{}\x1b[0m", linked_id, url)
}

/// Package name → clickable link to the ecosystem's registry page.
/// Returns plain `name` for unknown ecosystems.
pub fn package_link(name: &str, ecosystem: &str) -> String {
    let url = match ecosystem {
        "PyPI" => format!("https://pypi.org/project/{}/", name),
        "npm" => format!("https://www.npmjs.com/package/{}", name),
        "Go" => format!("https://pkg.go.dev/{}", name),
        "crates.io" => format!("https://crates.io/crates/{}", name),
        _ => return name.to_string(),
    };
    hyperlink(name, &url)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hyperlink_always_contains_text() {
        // In tests stdout is not a TTY — plain text is returned.
        let result = hyperlink(
            "CVE-2023-1234",
            "https://osv.dev/vulnerability/CVE-2023-1234",
        );
        assert!(result.contains("CVE-2023-1234"));
    }

    #[test]
    fn cve_link_contains_id() {
        let result = cve_link("GHSA-0001-0002-0003");
        assert!(result.contains("GHSA-0001-0002-0003"));
    }

    #[test]
    fn package_link_returns_name_for_unknown_ecosystem() {
        let result = package_link("somepkg", "rubygems");
        assert_eq!(result, "somepkg");
    }

    #[test]
    fn package_link_contains_name_for_known_ecosystems() {
        for eco in &["PyPI", "npm", "Go", "crates.io"] {
            let result = package_link("mypkg", eco);
            assert!(
                result.contains("mypkg"),
                "ecosystem {eco} did not include package name"
            );
        }
    }
}
