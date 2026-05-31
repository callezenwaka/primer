mod allowlist;
mod cache;
mod cli;
mod config;
mod engine;
mod lockfile;
mod manifest;
mod output;
mod prompt;
mod report;
mod shim;
mod summary;

use std::io;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use engine::osv;

#[derive(Parser)]
#[command(
    name = "primer",
    about = "Pre-install security interceptor for package managers",
    version,
    help_template = "\
{before-help}{name} {version}
{about}

{usage-heading} {usage}

Commands (Common):
{subcommands}
{after-help}"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ── Common ───────────────────────────────────────────────────────────────
    /// Scan a package for known vulnerabilities
    Scan {
        /// Package name to scan (omit when using --file)
        #[arg(required_unless_present = "file")]
        package: Option<String>,
        /// Scan all packages declared in a manifest file
        #[arg(long, value_name = "PATH", conflicts_with = "package")]
        file: Option<std::path::PathBuf>,
        /// Package ecosystem (inferred from --file when omitted)
        #[arg(long, value_enum)]
        ecosystem: Option<Ecosystem>,
        /// Specific version to check (single-package scan only)
        #[arg(long)]
        version: Option<String>,
        /// Proceed regardless of findings
        #[arg(long)]
        force: bool,
        /// Print cache hit/miss and fetch source
        #[arg(long)]
        verbose: bool,
        /// Generate an AI summary of findings using the local model
        #[arg(long)]
        ai: bool,
        /// Scan only directly declared packages; skip lockfile transitive deps
        #[arg(long)]
        direct_only: bool,
        /// Output format: human (default) or sarif — only valid with --file
        #[arg(long, value_name = "FORMAT", requires = "file")]
        format: Option<String>,
        /// Write output to file instead of stdout — only valid with --format sarif
        #[arg(long, value_name = "FILE", requires = "format")]
        output: Option<std::path::PathBuf>,
    },
    /// Generate shims and update PATH
    Init,
    /// Show system info (PATH order, shims, cache, model) — alias for doctor
    Info,

    // ── Management ───────────────────────────────────────────────────────────
    /// Manage the package allow-list (.primer-ignore)
    Allow {
        #[command(subcommand)]
        command: AllowCommands,
    },
    /// Manage the local vulnerability cache
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// Read and write ~/.primer/config.toml
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Manage AI inference models
    Model {
        #[command(subcommand)]
        command: ModelCommands,
    },
    /// Manage git hook integration
    Hook {
        #[command(subcommand)]
        command: HookCommands,
    },
    /// Watch manifest files and auto-scan on change
    Watch {
        /// Directory to watch (default: current)
        #[arg(long, value_name = "PATH")]
        directory: Option<std::path::PathBuf>,
        /// Scan existing manifests immediately on startup
        #[arg(long)]
        scan: bool,
    },
    /// Start an MCP server over stdio for AI agent integration
    Mcp,
    /// Generate a Software Bill of Materials (CycloneDX or SPDX)
    Sbom {
        /// Manifest or lockfile to generate SBOM from
        #[arg(long, value_name = "PATH")]
        file: std::path::PathBuf,
        /// Write output to file instead of stdout
        #[arg(long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,
        /// Output format: cyclonedx (default) or spdx
        #[arg(long, default_value = "cyclonedx")]
        format: String,
        /// Skip OSV vulnerability enrichment (inventory only)
        #[arg(long)]
        no_scan: bool,
    },
    /// Remove shims and PATH entries
    Uninit {
        /// Also delete cache and model files
        #[arg(long)]
        purge: bool,
    },
    /// Check PATH order, shim health, cache, and model state
    Doctor,
    /// Emit shell completion script
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum AllowCommands {
    /// Add a package to the allow-list
    Add {
        /// Package name
        package: String,
        /// Ecosystem to scope the entry (optional)
        #[arg(long, value_enum)]
        ecosystem: Option<Ecosystem>,
    },
    /// Remove a package from the allow-list
    Remove {
        /// Package name
        package: String,
        /// Ecosystem the entry was scoped to (if any)
        #[arg(long, value_enum)]
        ecosystem: Option<Ecosystem>,
    },
    /// Print all entries in .primer-ignore
    List,
}

#[derive(Subcommand)]
enum CacheCommands {
    /// Remove all cached vulnerability results
    Clear,
    /// Show entry count, total size, and oldest/newest entry
    Stats,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Write a config value (e.g. primer config set ai.backend ollama)
    Set {
        /// Dot-separated key
        key: String,
        /// Value to assign
        value: String,
    },
    /// Read a single config value
    Get {
        /// Dot-separated key
        key: String,
    },
    /// Print all config values
    List,
}

#[derive(Subcommand)]
enum ModelCommands {
    /// Download or import an AI model
    Add {
        /// Use a local GGUF file instead of downloading (skips network)
        #[arg(long, value_name = "PATH")]
        from: Option<std::path::PathBuf>,
        /// Tokenizer to pair with --from
        #[arg(long, value_name = "PATH")]
        tokenizer: Option<std::path::PathBuf>,
        /// HuggingFace repo to download from (use with --file)
        #[arg(long, value_name = "REPO")]
        repo: Option<String>,
        /// Filename within the HF repo
        #[arg(long, value_name = "FILE")]
        file: Option<String>,
    },
    /// List registered models with path and size
    List,
    /// Set the active inference target (path or ollama:<model>)
    Set {
        /// Local GGUF path, or 'ollama:<model>' for Ollama backend
        target: String,
    },
    /// Remove one or more models (interactive if no names given)
    Remove {
        /// Model filename(s) or ollama:<name> targets to remove; omit for interactive select
        names: Vec<String>,
        /// Remove all managed models without prompting
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum HookCommands {
    /// Write .git/hooks/pre-commit to block vulnerable package additions
    Install,
    /// Diff staged manifest changes and scan newly added packages (also called by the hook itself)
    Check,
}

#[derive(Clone, ValueEnum)]
enum Ecosystem {
    #[value(name = "pypi")]
    PyPI,
    #[value(name = "npm")]
    Npm,
    #[value(name = "go")]
    Go,
    #[value(name = "cargo")]
    Cargo,
}

impl Ecosystem {
    fn as_osv_str(&self) -> &'static str {
        match self {
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Npm => "npm",
            Ecosystem::Go => "Go",
            Ecosystem::Cargo => "crates.io",
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Check if we are being invoked as a PM shim (e.g. argv[0] == "pip").
    let argv0 = std::env::args().next().unwrap_or_default();
    if let Some(pm) = shim::PackageManager::from_argv0(&argv0) {
        let args: Vec<String> = std::env::args().skip(1).collect();
        return shim::run(pm, args).await;
    }

    let cli = Cli::parse();

    match cli.command {
        // ── Common ───────────────────────────────────────────────────────────
        Commands::Scan {
            package,
            file,
            ecosystem,
            version,
            force,
            verbose,
            ai,
            direct_only,
            format,
            output,
        } => {
            // --direct-only flag OR global config key both disable transitive scanning
            let direct_only = direct_only || crate::config::load().unwrap_or_default().direct_only;

            if let Some(path) = file {
                // --- file scan (manifest or lockfile) ---
                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                // Treat lockfiles as manifests when direct-only is set
                let is_lockfile = !direct_only && lockfile::LOCKFILE_NAMES.contains(&filename);
                let eco = ecosystem
                    .as_ref()
                    .map(|e| e.as_osv_str())
                    .or_else(|| lockfile::ecosystem_from_lockfile(filename))
                    .or_else(|| manifest::ecosystem_from_filename(filename))
                    .unwrap_or_else(|| {
                        eprintln!(
                            "⚠ Could not infer ecosystem from filename '{}'. Use --ecosystem.",
                            filename
                        );
                        std::process::exit(1);
                    });
                let content = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                    eprintln!("⚠ Could not read {}: {}", path.display(), e);
                    std::process::exit(1);
                });

                // Resolve to a flat (name, version) list from whichever format matched.
                let packages: Vec<(String, Option<String>)> = if is_lockfile {
                    lockfile::parse_lockfile(filename, &content)
                        .into_iter()
                        .map(|p| (p.name, Some(p.version)))
                        .collect()
                } else {
                    manifest::parse_file(filename, &content)
                        .into_iter()
                        .map(|p| (p.name, p.version))
                        .collect()
                };

                if packages.is_empty() {
                    println!("No packages found in {}.", path.display());
                } else {
                    let kind = if is_lockfile { "lockfile" } else { "manifest" };
                    println!(
                        "Scanning {} ({}) — {} packages [{}] …",
                        filename,
                        eco,
                        packages.len(),
                        kind,
                    );
                    let mut findings: Vec<prompt::AuditFinding> = Vec::new();
                    for (name, version) in &packages {
                        match osv::query(name, eco, version.as_deref(), verbose).await {
                            Ok(vulns) if vulns.is_empty() => {}
                            Ok(vulns) => {
                                if ai {
                                    show_ai_summary(&vulns);
                                }
                                findings.push(prompt::AuditFinding {
                                    package: name.clone(),
                                    ecosystem: eco.to_string(),
                                    vulns,
                                });
                            }
                            Err(e) => eprintln!("  ⚠ {} scan skipped: {}", name, e),
                        }
                    }
                    if format.as_deref() == Some("sarif") {
                        let sarif = output::sarif::build(&findings, filename);
                        let json_str = serde_json::to_string_pretty(&sarif).unwrap_or_default();
                        if let Some(out_path) = output {
                            std::fs::write(&out_path, &json_str).unwrap_or_else(|e| {
                                eprintln!("⚠ Could not write {}: {}", out_path.display(), e);
                                std::process::exit(1);
                            });
                            println!("SARIF written to {}", out_path.display());
                        } else {
                            println!("{}", json_str);
                        }
                        if output::sarif::has_blocking(&sarif) {
                            std::process::exit(1);
                        }
                    } else {
                        if let prompt::Decision::Abort = prompt::audit_summary(&findings) {
                            std::process::exit(1);
                        }
                        println!("✓ Scan complete.");
                    }
                }
            } else {
                // --- single-package scan ---
                let package = package.expect("package is required without --file");
                let eco = ecosystem.as_ref().map(|e| e.as_osv_str()).unwrap_or("PyPI");
                println!("Scanning {} ({}) ...", package, eco);

                match osv::query(&package, eco, version.as_deref(), verbose).await {
                    Ok(vulns) if vulns.is_empty() => {
                        println!("✓ {}: found 0 vulnerabilities.", package);
                    }
                    Ok(vulns) => {
                        if ai {
                            show_ai_summary(&vulns);
                        }
                        match prompt::evaluate(&package, eco, &vulns, force) {
                            prompt::Decision::Abort => std::process::exit(1),
                            prompt::Decision::Proceed => {}
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠ Scan skipped: {} (proceeding)", e);
                    }
                }
            }
        }

        Commands::Init => cli::init::run()?,
        Commands::Watch { directory, scan } => cli::watch::run(directory, scan).await?,
        Commands::Info | Commands::Doctor => cli::doctor::run()?,

        // ── Management ───────────────────────────────────────────────────────
        Commands::Allow { command } => match command {
            AllowCommands::Add { package, ecosystem } => {
                let eco = ecosystem.as_ref().map(|e| e.as_osv_str());
                allowlist::add(&package, eco)?;
            }
            AllowCommands::Remove { package, ecosystem } => {
                let eco = ecosystem.as_ref().map(|e| e.as_osv_str());
                allowlist::remove(&package, eco)?;
            }
            AllowCommands::List => allowlist::list()?,
        },

        Commands::Cache { command } => match command {
            CacheCommands::Clear => match cache::clear() {
                Ok(0) => println!("Cache is already empty."),
                Ok(n) => println!(
                    "Cleared {} cached entr{}.",
                    n,
                    if n == 1 { "y" } else { "ies" }
                ),
                Err(e) => eprintln!("Failed to clear cache: {}", e),
            },
            CacheCommands::Stats => cache::stats()?,
        },

        Commands::Config { command } => match command {
            ConfigCommands::Set { key, value } => config::set(&key, &value)?,
            ConfigCommands::Get { key } => match config::get(&key)? {
                Some(v) => println!("  {} = {}", key, v),
                None => println!("  {} = (not set)", key),
            },
            ConfigCommands::List => config::list()?,
        },

        Commands::Model { command } => match command {
            ModelCommands::Add {
                from,
                tokenizer,
                repo,
                file,
            } => {
                cli::model::add(from, tokenizer, repo, file).await?;
            }
            ModelCommands::List => cli::model::list()?,
            ModelCommands::Set { target } => cli::model::set(&target)?,
            ModelCommands::Remove { names, all } => cli::model::remove(names, all)?,
        },

        Commands::Hook { command } => match command {
            HookCommands::Install => cli::hook::install()?,
            HookCommands::Check => cli::hook::check().await?,
        },

        Commands::Mcp => cli::mcp::run().await?,

        Commands::Sbom {
            file,
            output,
            format,
            no_scan,
        } => cli::sbom::run(file, output, &format, no_scan).await?,

        Commands::Uninit { purge } => cli::uninit::run(purge)?,

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "primer", &mut io::stdout());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// AI summary display
// ---------------------------------------------------------------------------

fn show_ai_summary(vulns: &[osv::Vulnerability]) {
    if std::env::var("PRIMER_AI")
        .map(|v| v == "0")
        .unwrap_or(false)
    {
        return;
    }

    #[cfg(not(feature = "ai"))]
    {
        let _ = vulns;
        eprintln!("  ℹ  --ai requires the AI feature: cargo install primer --features ai");
    }

    #[cfg(feature = "ai")]
    {
        if !summary::model_present() {
            eprintln!("  ℹ  No model found. Run: primer model add");
            return;
        }

        eprint!("  Generating summary … ");
        match summary::generate(vulns) {
            Some(s) => {
                eprintln!();
                eprintln!();
                eprintln!("  Summary");
                eprintln!("  ───────");
                eprintln!("  {}", s.text);
                eprintln!();
            }
            None => eprintln!("(unavailable)"),
        }
    }
}
