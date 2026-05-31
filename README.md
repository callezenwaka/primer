# primer

Pre-install security interceptor for package managers. Scans packages against the [OSV vulnerability database](https://osv.dev/) before they hit your system — with an optional local AI summary, git hook integration, and CI mode.

## How it works

primer places lightweight shims ahead of your package managers in `$PATH`. When you run `pip install requests`, the shim intercepts the command, queries OSV, and either passes through silently (clean result) or prompts you before executing.

```
pip install pillow
  → primer shim intercepts
  → queries OSV
  → found 3 vulnerabilities (1 CRITICAL, 2 HIGH)
    pillow 9.0.0 — GHSA-56pw-mpj4-fxjw [CRITICAL]
      Summary: Heap buffer overflow in TIFF image parser
      Fixed in: 9.0.1
  → [prompt] View full details? (y/N)
  → [prompt] Continue install anyway? (y/N)
  → exits 1 on "N"
```

✓ requests: found 0 vulnerabilities — passes through silently (after the first cached query).

## Supported ecosystems

| Ecosystem | Intercepted commands | Manifest / Lockfile |
|-----------|---------------------|---------------------|
| Python    | `pip`, `uv`, `poetry` | `requirements.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock` |
| Node.js   | `npm`, `yarn`, `pnpm` | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Go        | `go get`, `go mod` | `go.mod`, `go.sum` |
| Rust      | `cargo add`, `cargo build`, `cargo fetch`, `cargo check` | `Cargo.toml`, `Cargo.lock` |

## Installation

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/barestripehq/primer/releases/latest/download/primer-installer.sh | sh
```

Then run once to set up shims:

```sh
primer init
```

This creates shims in `~/.primer/bin` and prepends it to your shell config (`.zshenv` for zsh, `.bashrc` for bash, fish function for fish). Restart your shell or `source` the config file.

**From source:**

```sh
cargo install --git https://github.com/barestripehq/primer
primer init
```

## Commands

### Scanning

```sh
# Scan any package manually
primer scan requests --ecosystem pypi
primer scan express --ecosystem npm
primer scan github.com/gin-gonic/gin --ecosystem go
primer scan serde --ecosystem cargo

# Pin a version
primer scan pillow --ecosystem pypi --version 9.0.0

# Skip prompts (proceed regardless)
primer scan pillow --ecosystem pypi --force

# Show cache hit/miss
primer scan requests --ecosystem pypi --verbose

# Include AI-generated summary (requires primer model add)
primer scan pillow --ecosystem pypi --ai

# Scan all packages declared in a manifest file (no install)
primer scan --file requirements.txt
primer scan --file package.json
primer scan --file go.mod
primer scan --file Cargo.toml

# Scan a lockfile directly — resolves exact pinned versions for every transitive dep
primer scan --file package-lock.json
primer scan --file yarn.lock
primer scan --file Cargo.lock

# Skip transitive dependencies (direct packages only)
primer scan --file package.json --direct-only

# Output SARIF 2.1.0 for GitHub Security tab upload
primer scan --file requirements.txt --format sarif
primer scan --file package-lock.json --format sarif --output results.sarif
```

Each finding shows the patched version when OSV provides one:

```
pillow 9.0.0 — GHSA-56pw-mpj4-fxjw [CRITICAL]
  Summary: Heap buffer overflow in TIFF image parser
  Fixed in: 9.0.1
```

### Transitive dependency scanning

By default, primer scans the full dependency tree — not just the package you name, but everything it pulls in.

**Explicit installs** (`npm install express`, `cargo add serde`): primer scans the named package first (pre-install), then after the PM runs it diffs the lockfile and scans any newly added transitive packages. Post-install findings include a remove hint since the package is already on disk.

**Bare restores** (`npm install`, `go mod download`): when `intercept-restore` is enabled and a lockfile exists alongside the manifest, primer loads it to resolve exact versions for both direct and transitive packages before the PM runs. The header shows the split:

```
  primer: scanning package.json — 3 direct + 47 transitive packages
```

**Opt out** — skip transitive scanning when you want low-noise results:

```sh
# Per command
primer scan --file package.json --direct-only

# Globally (writes to ~/.primer/config.toml)
primer config set direct-only true
```

The transitive scan always closes with a status line:

```
  primer: scanning 4 new transitive packages …
  ✓ transitive scan complete — found 0 vulnerabilities.
```

### Auditing existing vulnerabilities

The shim gates new installs. To surface vulnerabilities already in your project, scan the manifest or lockfile directly:

```sh
primer scan --file package-lock.json   # full resolved tree (recommended)
primer scan --file package.json        # declared dependencies only
primer scan --file requirements.txt
primer scan --file Cargo.toml
```

For each vulnerable package, primer shows the CVE details and a ready-to-run fix command:

```
⚠ lodash 4.17.15 (npm) — 6 vulnerabilities

  [HIGH]   GHSA-35jh-r3h4-6jhm — Command Injection
           Fixed in: 4.17.21
           Fix:      npm install lodash@4.17.21
  …
```

Primer prints the fix command but does not modify your manifests — you run it, and the shim gates the new version on the way in.

### Directory watcher

Auto-scan manifest files whenever they change — useful for long-running dev sessions:

```sh
primer watch                        # watch current directory
primer watch --directory /project   # watch a specific path
primer watch --scan                 # also scan immediately on startup
```

Watches: `requirements.txt`, `pyproject.toml`, `package.json`, `go.mod`, `Cargo.toml`. Debounced at 500 ms. Exit with `Ctrl+C`.

### Policy file

`.primer-policy.toml` is committed to the repo and enforced automatically on every developer machine and in CI — no flags required. It is separate from `~/.primer/config.toml` (machine-wide settings).

```toml
[policy]
threshold = "high"          # optional global override for this repo

[[deny]]
package = "event-stream"    # hard block by name regardless of CVE status
reason  = "supply chain compromise"

[[ignore]]
cve     = "CVE-2023-1234"
package = "pillow"          # optional: scope to one package
expires = "2026-12-31"      # YYYY-MM-DD; finding re-activates after this date
reason  = "Mitigated by WAF"

[[override]]
package   = "requests"
threshold = "critical"      # per-package threshold
```

Evaluation order: `[[deny]]` → `[[ignore]]` (expiry checked) → `[[override]]` → `[policy].threshold`.

```sh
primer policy list    # show all rules and expiry status
primer policy check   # validate syntax without scanning
```

### Severity threshold

Control which severity level triggers a prompt or CI block:

```sh
primer config set prompt-threshold medium   # block MEDIUM, HIGH, CRITICAL
primer config set prompt-threshold critical # block CRITICAL only
primer config set prompt-threshold high     # default
```

### SBOM generation

Emit a Software Bill of Materials for any manifest or lockfile:

```sh
primer sbom --file requirements.txt              # CycloneDX JSON to stdout
primer sbom --file package-lock.json             # from lockfile (exact versions)
primer sbom --file Cargo.toml --output sbom.json # write to file
primer sbom --file package.json --format spdx    # SPDX 2.3 JSON
primer sbom --file go.mod --no-scan              # inventory only, no OSV queries
```

### AI agent integration (MCP)

`primer mcp` starts a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, exposing a `scan_package` tool that any MCP-capable agent (Claude Code, Cursor, Cline, …) can call before deciding to install a package.

Add a `.mcp.json` in your project root (or `~/.claude/mcp.json` for Claude Code):

```json
{
  "mcpServers": {
    "primer": {
      "command": "primer",
      "args": ["mcp"]
    }
  }
}
```

The agent can then call:

```
scan_package("pillow", "PyPI", "9.0.0")
→ ⚠ pillow 9.0.0 (PyPI) — found 2 vulnerabilities:
    [HIGH] GHSA-xxxx-yyyy-zzzz — Buffer overflow in TIFF decoder (Fixed in: 9.1.0)
    [MEDIUM] GHSA-aaaa-bbbb-cccc — …
```

The tool returns structured JSON (`vulnerabilities[]`, `summary.blocking`) so the agent can decide whether to proceed. OSV cache applies — repeated lookups are instant.

### Setup and teardown

```sh
primer init           # create shims, update PATH
primer uninit         # remove shims, strip PATH entry
primer uninit --purge # also delete cache and model files
primer doctor         # check PATH order, shim health, cache state, model state
```

### Allow-list

Add a package to `.primer-ignore` in the project root to skip the scan without `--force`:

```sh
primer allow add pillow
primer allow add pillow --ecosystem pypi   # scope to one ecosystem
```

### Cache

```sh
primer cache clear    # remove all cached OSV results
```

Results are cached in `~/.primer/cache/` with a 24-hour TTL. On network failure the most recent cached result is used (stale-on-error fallback).

### AI model

```sh
# Download the default model (~80 MB, no account required)
primer model add

# Import a local GGUF file
primer model add --from /path/to/model.gguf --tokenizer /path/to/tokenizer.json

# Download a specific model from HuggingFace Hub
primer model add --repo <hf-repo> --file <filename>

# List registered models (* = active)
primer model list

# Set the active inference target
primer model set ~/.primer/models/smollm2.gguf   # local candle inference
primer model set ollama:llama3.2                 # route to local Ollama instance

# Remove models
primer model remove                              # interactive select
primer model remove smollm2.gguf ollama:llama3.2 # remove by name (no prompt)
primer model remove --all                        # remove all, clear config
```

Once a model is present, pass `--ai` to any `scan` command to get a plain-English CVE summary before the decision prompt.

Set `PRIMER_AI=0` to disable AI entirely (useful in CI pipelines).

### Git hook

Block commits that add vulnerable packages to manifests:

```sh
# Install the pre-commit hook in the current repo
primer hook install

# Run the check manually without committing
primer hook check
```

Monitored manifests: `requirements.txt`, `pyproject.toml`, `package.json`, `go.mod`, `Cargo.toml`.

### Intercept bare restore commands

By default, bare restore commands (`npm install` with no packages, `go mod download`, etc.) pass straight through. Enable interception to scan the manifest before dependencies are installed:

```sh
primer config set intercept-restore true
```

When enabled, primer scans the relevant manifest for each PM's "install all" form before passing through. If a lockfile is present, primer loads it to include transitive packages at exact pinned versions:

| Command | Manifest scanned | Lockfile (if present) |
|---------|-----------------|----------------------|
| `npm install` / `pnpm install` / `yarn` | `package.json` | `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml` |
| `pip install` (no packages) / `uv sync` | `requirements.txt` → `pyproject.toml` | `uv.lock`, `poetry.lock` |
| `poetry install` | `pyproject.toml` | `poetry.lock`, `uv.lock` |
| `go mod download` | `go.mod` | `go.sum` |
| `cargo build` / `cargo fetch` / `cargo check` | `Cargo.toml` | `Cargo.lock` |

Disabled by default — large projects can have many deps. Cache makes repeat scans instant. Use `--direct-only` (or `primer config set direct-only true`) to skip transitive packages.

## CI / non-interactive mode

When `CI=true` is set (standard on GitHub Actions, CircleCI, etc.) or stdin is not a TTY, primer switches to non-interactive mode automatically:

- No prompts — consolidated findings table printed to stderr
- Blocks on Critical and High findings (exit code `1`)
- Writes all findings to `primer-report.json` in the working directory

Override with `PRIMER_CI_MODE=allow-all` to disable blocking (audit-only pipelines).

### GitHub Actions

Use `barestripehq/primer-action@v1` — it installs primer, scans the manifest, uploads SARIF to the GitHub Security tab, and posts a PR comment in one step:

```yaml
permissions:
  security-events: write   # SARIF upload
  pull-requests: write     # PR comments
  actions: read
  contents: read

steps:
  - uses: actions/checkout@v6
  - uses: barestripehq/primer-action@v1
    with:
      file: package-lock.json
```

See the [Integrations docs](https://primer.barestripe.com/doc/integrations/) for all inputs and examples.

### Other CI systems (CircleCI, GitLab CI, Jenkins)

Install primer via the installer script and call `--format sarif` to emit SARIF 2.1.0:

```yaml
- name: Install primer
  run: curl --proto '=https' --tlsv1.2 -fsSL https://github.com/barestripehq/primer/releases/latest/download/primer-installer.sh | sh
- name: Scan dependencies
  run: primer scan --file package-lock.json --format sarif --output results.sarif
```

## Diagnostics

```sh
primer doctor
```

Reports:
- Whether `~/.primer/bin` is correctly ordered ahead of version managers (`nvm`, `pyenv`, `asdf`, `volta`) in `$PATH`
- Resolved path of each shim and its real binary
- Cache entry count and total size
- `intercept-restore` config status with enable hint
- Active AI model path and file size

## Uninstall

```sh
primer uninit --purge
```

Removes shims, strips the `$PATH` entry from your shell config, and deletes `~/.primer/` (cache, models, config).

## License

MIT
