use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::shim::PackageManager;

pub fn run() -> Result<()> {
    let ms_bin = primer_bin_dir();
    let self_path = env::current_exe().context("could not determine primer binary path")?;

    fs::create_dir_all(&ms_bin)
        .with_context(|| format!("could not create {}", ms_bin.display()))?;

    println!("Initialising primer...\n");

    // On Windows, copy primer.exe → primer-shim.exe once so .cmd wrappers can call it.
    #[cfg(windows)]
    {
        let shim_exe = ms_bin.join("primer-shim.exe");
        if !shim_exe.exists() {
            fs::copy(&self_path, &shim_exe)
                .context("could not copy primer.exe to primer-shim.exe")?;
            println!("  ✓ primer-shim.exe created");
        }
    }

    // Create one shim per PM that is installed on this system.
    let mut created = 0;
    for pm in PackageManager::all() {
        if let Some(real) = crate::shim::find_real_binary(pm.name()) {
            let shim_path = ms_bin.join(pm.name());
            create_shim(&self_path, &shim_path, pm.name(), &real)?;
            created += 1;
        }
    }

    if created == 0 {
        println!("No supported package managers found — nothing to shim.");
        return Ok(());
    }

    println!("\nUpdating shell configs...\n");
    update_shell_configs(&ms_bin)?;

    #[cfg(not(windows))]
    println!(
        "Done. Restart your shell or run:\n\n  source ~/.zshenv   # zsh\n  source ~/.bashrc   # bash\n"
    );
    #[cfg(windows)]
    println!("Done. Open a new terminal for PATH changes to take effect.\n");

    Ok(())
}

// ---------------------------------------------------------------------------
// Shim creation
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn create_shim(self_path: &Path, shim_path: &Path, name: &str, real: &Path) -> Result<()> {
    // Remove stale shim if it exists.
    if shim_path.exists() || shim_path.symlink_metadata().is_ok() {
        fs::remove_file(shim_path)?;
    }
    std::os::unix::fs::symlink(self_path, shim_path)
        .with_context(|| format!("could not create shim for {}", name))?;
    println!(
        "  ✓ {} → {} (real: {})",
        shim_path.display(),
        self_path.display(),
        real.display()
    );
    Ok(())
}

#[cfg(windows)]
fn create_shim(_self_path: &Path, shim_path: &Path, name: &str, real: &Path) -> Result<()> {
    // Write a .cmd wrapper that delegates to primer-shim.exe, passing the PM
    // name as argv[1] so main.rs can dispatch to the correct shim handler.
    let cmd_path = shim_path.with_extension("cmd");
    let content = format!("@echo off\r\n\"%~dp0primer-shim.exe\" {} %*\r\n", name);
    fs::write(&cmd_path, content)
        .with_context(|| format!("could not create .cmd wrapper for {}", name))?;
    println!("  ✓ {} (real: {})", cmd_path.display(), real.display());
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_shim(_self_path: &Path, shim_path: &Path, name: &str, real: &Path) -> Result<()> {
    anyhow::bail!("Unsupported platform — cannot create shim for {}", name);
}

// ---------------------------------------------------------------------------
// Shell config update
// ---------------------------------------------------------------------------

const PATH_LINE: &str = r#"export PATH="$HOME/.primer/bin:$PATH""#;
const MARKER: &str = "# primer";

fn update_shell_configs(ms_bin: &Path) -> Result<()> {
    #[cfg(windows)]
    return update_shell_configs_windows(ms_bin);

    #[cfg(not(windows))]
    {
        let home = crate::home::home_dir();

        let candidates: &[(&str, &str)] = &[
            (".zshenv", "zsh (all shells)"),
            (".zshrc", "zsh (interactive)"),
            (".bashrc", "bash"),
            (".bash_profile", "bash login"),
            (".config/fish/config.fish", "fish"),
        ];

        for (file, label) in candidates {
            let path = home.join(file);
            if !path.exists() {
                continue;
            }
            match append_path_line(&path, ms_bin) {
                Ok(true) => println!("  ✓ Updated {} ({})", path.display(), label),
                Ok(false) => {
                    println!("  · Already configured in {} ({})", path.display(), label)
                }
                Err(e) => println!("  ✗ Could not update {}: {}", path.display(), e),
            }
        }

        Ok(())
    }
}

#[cfg(windows)]
fn update_shell_configs_windows(ms_bin: &Path) -> Result<()> {
    let bin_str = ms_bin.to_string_lossy();

    // 1. Update user PATH via SETX (user-scope, avoids the 1024-char truncation
    //    bug by reading the current value and prepending rather than letting SETX
    //    expand %PATH% itself).
    let current_path = std::env::var("PATH").unwrap_or_default();
    if !current_path
        .split(';')
        .any(|p| p.eq_ignore_ascii_case(&*bin_str))
    {
        let new_path = format!("{};{}", bin_str, current_path);
        let status = std::process::Command::new("setx")
            .args(["PATH", &new_path])
            .status();
        match status {
            Ok(s) if s.success() => println!("  ✓ Added {} to user PATH (SETX)", bin_str),
            Ok(_) => println!("  ✗ SETX failed — add {} to PATH manually", bin_str),
            Err(_) => println!("  ✗ SETX not found — add {} to PATH manually", bin_str),
        }
    } else {
        println!("  · {} already in PATH", bin_str);
    }

    // 2. Inject into PowerShell $PROFILE for users who launch PowerShell 7+.
    if let Some(profile_path) = powershell_profile_path() {
        if let Some(parent) = profile_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match append_path_line_ps(&profile_path, ms_bin) {
            Ok(true) => println!(
                "  ✓ Updated PowerShell profile ({})",
                profile_path.display()
            ),
            Ok(false) => println!(
                "  · PowerShell profile already configured ({})",
                profile_path.display()
            ),
            Err(e) => println!("  ✗ Could not update PowerShell profile: {}", e),
        }
    }

    Ok(())
}

#[cfg(windows)]
fn powershell_profile_path() -> Option<std::path::PathBuf> {
    // PowerShell 7 profile: $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
    let home = crate::home::home_dir();
    Some(
        home.join("Documents")
            .join("PowerShell")
            .join("Microsoft.PowerShell_profile.ps1"),
    )
}

#[cfg(windows)]
const PS_MARKER: &str = "# primer";

#[cfg(windows)]
fn append_path_line_ps(profile: &Path, ms_bin: &Path) -> Result<bool> {
    let contents = if profile.exists() {
        fs::read_to_string(profile)?
    } else {
        String::new()
    };
    if contents.contains(PS_MARKER) {
        return Ok(false);
    }
    let bin_str = ms_bin.to_string_lossy();
    let addition = format!("\r\n{PS_MARKER}\r\n$env:PATH = \"{bin_str};$env:PATH\"\r\n");
    fs::write(profile, format!("{contents}{addition}"))?;
    Ok(true)
}

/// Append the PATH export to `config_file` if not already present.
/// Returns true if the file was modified, false if already configured.
pub(crate) fn append_path_line(config_file: &Path, _ms_bin: &Path) -> Result<bool> {
    let contents = fs::read_to_string(config_file)?;
    if contents.contains(MARKER) {
        return Ok(false);
    }

    let addition = if config_file
        .extension()
        .map(|e| e == "fish")
        .unwrap_or(false)
    {
        // fish uses set -gx instead of export
        format!("\n{MARKER}\nfish_add_path \"$HOME/.primer/bin\"\n")
    } else {
        format!("\n{MARKER}\n{PATH_LINE}\n")
    };

    fs::write(config_file, format!("{contents}{addition}"))?;
    Ok(true)
}

pub fn primer_bin_dir() -> PathBuf {
    crate::home::primer_bin_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_file(content: &str) -> (tempfile::NamedTempFile, PathBuf) {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "{}", content).unwrap();
        let path = f.path().to_path_buf();
        (f, path)
    }

    #[test]
    fn appends_path_line_to_empty_file() {
        let (_f, path) = temp_file("");
        let result = append_path_line(&path, &PathBuf::new()).unwrap();
        assert!(result, "should return true (file modified)");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains(MARKER));
        assert!(contents.contains(PATH_LINE));
    }

    #[test]
    fn append_is_idempotent() {
        let (_f, path) = temp_file("# existing content\n");
        append_path_line(&path, &PathBuf::new()).unwrap();
        let result = append_path_line(&path, &PathBuf::new()).unwrap();
        assert!(
            !result,
            "second call should return false (already configured)"
        );
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents.matches(MARKER).count(),
            1,
            "marker should appear exactly once"
        );
    }

    #[test]
    fn appends_fish_syntax_for_fish_files() {
        let (_f, path) = temp_file("# fish config\n");
        // Rename to .fish so the extension check triggers.
        let fish_path = path.with_extension("fish");
        fs::copy(&path, &fish_path).unwrap();
        append_path_line(&fish_path, &PathBuf::new()).unwrap();
        let contents = fs::read_to_string(&fish_path).unwrap();
        assert!(contents.contains("fish_add_path"));
        assert!(!contents.contains("export PATH"));
        let _ = fs::remove_file(&fish_path);
    }

    #[test]
    fn preserves_existing_content() {
        let original = "# my zshrc\nexport FOO=bar\n";
        let (_f, path) = temp_file(original);
        append_path_line(&path, &PathBuf::new()).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with(original));
    }

    #[cfg(windows)]
    #[test]
    fn windows_cmd_wrapper_contains_pm_name() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let shim_path = dir.path().join("npm");
        let real = std::path::Path::new("C:\\Program Files\\nodejs\\npm.cmd");
        create_shim(&PathBuf::new(), &shim_path, "npm", real).unwrap();
        let cmd_path = shim_path.with_extension("cmd");
        assert!(cmd_path.exists());
        let contents = fs::read_to_string(&cmd_path).unwrap();
        assert!(contents.contains("primer-shim.exe"));
        assert!(contents.contains("npm"));
    }

    #[cfg(windows)]
    #[test]
    fn powershell_profile_injection_is_idempotent() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let profile = dir.path().join("profile.ps1");
        let bin = PathBuf::from(r"C:\Users\test\.primer\bin");
        append_path_line_ps(&profile, &bin).unwrap();
        let result = append_path_line_ps(&profile, &bin).unwrap();
        assert!(!result, "second call should return false");
        let contents = fs::read_to_string(&profile).unwrap();
        assert_eq!(contents.matches(PS_MARKER).count(), 1);
    }
}
