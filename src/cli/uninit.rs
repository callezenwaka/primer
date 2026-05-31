use std::fs;
use std::path::PathBuf;

use anyhow::Result;

use crate::shim::PackageManager;

const MARKER: &str = "# primer";

pub fn run(purge: bool) -> Result<()> {
    println!("Removing primer shims...\n");

    let ms_bin = primer_bin_dir();

    // Remove shims (symlinks on Unix, .cmd wrappers on Windows).
    let mut removed = 0;
    for pm in PackageManager::all() {
        #[cfg(windows)]
        let shim = ms_bin.join(pm.name()).with_extension("cmd");
        #[cfg(not(windows))]
        let shim = ms_bin.join(pm.name());

        if shim.exists() || shim.symlink_metadata().is_ok() {
            fs::remove_file(&shim)?;
            println!("  ✓ Removed {}", shim.display());
            removed += 1;
        }
    }

    // On Windows also remove primer-shim.exe.
    #[cfg(windows)]
    {
        let shim_exe = ms_bin.join("primer-shim.exe");
        if shim_exe.exists() {
            fs::remove_file(&shim_exe)?;
            println!("  ✓ Removed {}", shim_exe.display());
        }
    }

    if removed == 0 {
        println!("  · No shims found.");
    }

    // Remove PATH entries from shell configs.
    println!("\nCleaning shell configs...\n");
    remove_path_lines()?;

    // Optionally purge cache and models.
    if purge {
        let ms_home = ms_bin.parent().unwrap().to_path_buf();
        for subdir in &["cache", "models"] {
            let dir = ms_home.join(subdir);
            if dir.exists() {
                fs::remove_dir_all(&dir)?;
                println!("  ✓ Purged {}", dir.display());
            }
        }
    }

    #[cfg(not(windows))]
    println!("\nDone. Restart your shell to complete removal.");
    #[cfg(windows)]
    println!("\nDone. Open a new terminal for PATH changes to take effect.");

    Ok(())
}

fn remove_path_lines() -> Result<()> {
    #[cfg(windows)]
    return remove_path_lines_windows();

    #[cfg(not(windows))]
    {
        let home = crate::home::home_dir();

        let candidates = [
            ".zshenv",
            ".zshrc",
            ".bashrc",
            ".bash_profile",
            ".config/fish/config.fish",
        ];

        for file in &candidates {
            let path = home.join(file);
            if !path.exists() {
                continue;
            }
            match strip_marker_block(&path) {
                Ok(true) => println!("  ✓ Cleaned {}", path.display()),
                Ok(false) => {}
                Err(e) => println!("  ✗ Could not clean {}: {}", path.display(), e),
            }
        }

        Ok(())
    }
}

#[cfg(windows)]
fn remove_path_lines_windows() -> Result<()> {
    let ms_bin = primer_bin_dir();
    let bin_str = ms_bin.to_string_lossy().to_string();

    // 1. Strip from current user PATH via SETX.
    let current_path = std::env::var("PATH").unwrap_or_default();
    let new_path: String = current_path
        .split(';')
        .filter(|p| !p.eq_ignore_ascii_case(&bin_str))
        .collect::<Vec<_>>()
        .join(";");

    if new_path != current_path {
        let status = std::process::Command::new("setx")
            .args(["PATH", &new_path])
            .status();
        match status {
            Ok(s) if s.success() => println!("  ✓ Removed {} from user PATH", bin_str),
            _ => println!(
                "  ✗ Could not update PATH via SETX — remove {} manually",
                bin_str
            ),
        }
    } else {
        println!("  · {} was not in PATH", bin_str);
    }

    // 2. Strip # primer block from PowerShell profile.
    let home = crate::home::home_dir();
    let profile = home
        .join("Documents")
        .join("PowerShell")
        .join("Microsoft.PowerShell_profile.ps1");
    if profile.exists() {
        match strip_marker_block(&profile) {
            Ok(true) => println!("  ✓ Cleaned PowerShell profile ({})", profile.display()),
            Ok(false) => {}
            Err(e) => println!("  ✗ Could not clean PowerShell profile: {}", e),
        }
    }

    Ok(())
}

/// Remove the `# primer` block from a config file.
/// Returns true if the file was modified.
fn strip_marker_block(path: &std::path::Path) -> Result<bool> {
    let contents = fs::read_to_string(path)?;
    if !contents.contains(MARKER) {
        return Ok(false);
    }

    // Drop lines from the marker through the next blank line.
    let mut filtered = Vec::new();
    let mut skip = false;
    for line in contents.lines() {
        if line.trim() == MARKER {
            skip = true;
            continue;
        }
        if skip && line.trim().is_empty() {
            skip = false;
            continue;
        }
        if !skip {
            filtered.push(line);
        }
    }

    fs::write(path, filtered.join("\n") + "\n")?;
    Ok(true)
}

fn primer_bin_dir() -> PathBuf {
    crate::home::primer_bin_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn temp_file(content: &str) -> (tempfile::NamedTempFile, PathBuf) {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "{}", content).unwrap();
        let path = f.path().to_path_buf();
        (f, path)
    }

    #[test]
    fn strips_marker_block_from_config() {
        let content = "# existing\nexport FOO=bar\n\n# primer\nexport PATH=\"$HOME/.primer/bin:$PATH\"\n\n# after\n";
        let (_f, path) = temp_file(content);
        let result = strip_marker_block(&path).unwrap();
        assert!(result, "should return true (file modified)");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains(MARKER));
        assert!(!contents.contains(".primer"));
        assert!(contents.contains("export FOO=bar"));
        assert!(contents.contains("# after"));
    }

    #[test]
    fn strip_is_noop_when_marker_absent() {
        let content = "# my config\nexport BAR=baz\n";
        let (_f, path) = temp_file(content);
        let result = strip_marker_block(&path).unwrap();
        assert!(!result, "should return false (nothing to remove)");
        assert_eq!(fs::read_to_string(&path).unwrap(), content);
    }

    #[test]
    fn strip_and_re_append_roundtrips_cleanly() {
        use crate::cli::init::append_path_line;
        let original = "# my zshrc\nexport FOO=bar\n";
        let (_f, path) = temp_file(original);

        append_path_line(&path, &PathBuf::new()).unwrap();
        strip_marker_block(&path).unwrap();

        let after = fs::read_to_string(&path).unwrap();
        assert!(!after.contains(MARKER), "marker should be gone after strip");
        assert!(
            after.contains("export FOO=bar"),
            "original content preserved"
        );
    }
}
