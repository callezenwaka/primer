use std::path::PathBuf;

/// Returns the current user's home directory.
/// On Windows reads `USERPROFILE`; on Unix reads `HOME`.
pub fn home_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .or_else(|_| {
                std::env::var("HOMEDRIVE")
                    .and_then(|d| std::env::var("HOMEPATH").map(|p| format!("{}{}", d, p)))
            })
            .unwrap_or_else(|_| "C:\\Users\\default".to_string())
            .into()
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .unwrap_or_else(|_| "/tmp".to_string())
            .into()
    }
}

/// Returns `~/.primer` (or `%USERPROFILE%\.primer` on Windows).
pub fn primer_dir() -> PathBuf {
    home_dir().join(".primer")
}

/// Returns `~/.primer/bin`.
pub fn primer_bin_dir() -> PathBuf {
    primer_dir().join("bin")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_dir_is_non_empty() {
        let h = home_dir();
        assert!(!h.as_os_str().is_empty());
    }

    #[test]
    fn primer_dir_ends_with_primer() {
        let d = primer_dir();
        assert_eq!(d.file_name().unwrap(), ".primer");
    }

    #[test]
    fn primer_bin_dir_ends_with_bin() {
        let b = primer_bin_dir();
        assert_eq!(b.file_name().unwrap(), "bin");
    }

    #[test]
    fn primer_bin_dir_parent_is_primer_dir() {
        assert_eq!(primer_bin_dir().parent().unwrap(), primer_dir());
    }
}
