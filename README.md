# vuln-scanner

A comprehensive, zero-bloat cybersecurity scanner CLI covering supply-chain CVEs, leaked secrets, git history, Python/JS/Go SAST & cross-file taint tracking, CI/CD pipelines, containers/IaC, PII & Cloud IAM compliance, Docker image tarballs, host permissions, open ports, license compliance, and live web/TLS/DAST/DNS audits.

---

## How to Use This on Your Own Projects

### Option 1: Install directly from GitHub (`pip` / `pipx`)
```bash
pip install "git+https://github.com/sharathl2580-cpu/vuln-scanner.git"
```
Then run from inside any project directory:
```bash
# Full security scan (code, dependencies, secrets, IaC, compliance, licenses)
vuln-scanner /path/to/your/project

# Offline CI gate (no internet required, fail build on HIGH or CRITICAL findings)
vuln-scanner /path/to/your/project --no-network --fail-on high

# Only scan files changed in your current PR vs main
vuln-scanner /path/to/your/project --diff main --fail-on high
```

### Option 2: Run with Docker (no Python setup needed)
```bash
docker build -t vuln-scanner .
docker run --rm -v "$(pwd):/workspace" vuln-scanner /workspace --no-network --fail-on high
```

### Option 3: Add as a `pre-commit` Hook in Any Repo
Add this to `.pre-commit-config.yaml` in your project:
```yaml
repos:
  - repo: https://github.com/sharathl2580-cpu/vuln-scanner
    rev: main
    hooks:
      - id: vuln-scanner
```

### Option 4: Add to GitHub Actions (SARIF Upload to GitHub Security Tab)
Copy [.github/workflows/security.yml](.github/workflows/security.yml) into your repository or add a step:
```yaml
- name: Install & Run vuln-scanner
  run: |
    pip install "git+https://github.com/sharathl2580-cpu/vuln-scanner.git"
    vuln-scanner . --format sarif --output results.sarif --fail-on high
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Key Capabilities & Commands

| Capability | Example Command |
| :--- | :--- |
| **Dependencies (OSV Batch + Cache)** | `vuln-scanner . --checks deps` |
| **Auto-Fix Pinned Dependencies** | `vuln-scanner . --fix` |
| **Secrets & Git Commit History** | `vuln-scanner . --checks secrets --git-history` |
| **SAST + Intra/Cross-File Taint** | `vuln-scanner . --checks sast` |
| **CI/CD, Typosquatting & Archives** | `vuln-scanner . --checks supply` |
| **Containers & IaC (Docker/K8s/TF)** | `vuln-scanner . --checks iac` |
| **PII (Luhn/SSN) & Cloud IAM** | `vuln-scanner . --checks compliance` |
| **License Compliance** | `vuln-scanner . --checks licenses` |
| **Host Permissions & Open Ports** | `vuln-scanner . --checks cyber --host 127.0.0.1` |
| **Docker Image Tarball Scan** | `vuln-scanner . --image my-app.tar` |
| **Live Web, TLS, Active DAST & DNS** | `vuln-scanner . --url https://example.com --active-web --domain example.com` |
| **Interactive Local Web Dashboard** | `vuln-scanner . --serve --port 8443` |
| **Export Formats** | `--format text \| json \| sarif \| markdown \| html \| cyclonedx` |
| **Baseline / Ignore Rules** | `--save-baseline base.json` / `--baseline base.json` / `--ignore-rules SAST007` |

---

## Configuration & Suppressions
- **`vuln-scanner.toml`**: Store default `checks`, `format`, `fail_on`, `exclude`, `ignore_rules`, and `[[custom_rules]]` (see [vuln-scanner.toml.example](vuln-scanner.toml.example)).
- **`.vulnignore`**: Suppress files or rule+file pairs (`SAST001:tests/*`).
- **Inline Suppression**: Add `# nosec` or `# nosec RULE_ID` on any line.

## Supported Ecosystems
- **npm**: `package-lock.json`, `yarn.lock`
- **Python (PyPI)**: `requirements.txt`, `poetry.lock`
- **Go**: `go.mod`
- **Rust**: `Cargo.lock`
- **Java (Maven)**: `pom.xml`
- **Ruby**: `Gemfile.lock`
- **PHP**: `composer.lock`
- **OS Packages (Docker tarballs)**: Debian (`dpkg`) & Alpine (`apk`)

## Local Development
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

## License
MIT — see [LICENSE](LICENSE).
