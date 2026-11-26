import json
import re
import zipfile
from pathlib import Path
from typing import Dict, List, Set

from vuln_scanner.parsers import find_lockfiles, parse_lockfile
from vuln_scanner.security_checks import (
    SECRET_PATTERNS,
    _is_ignored_by_vulnignore,
    _is_line_suppressed,
    _is_placeholder,
    iter_scannable_files,
    load_vulnignore,
    redact_secret,
)

POPULAR_PYPI = {
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "flask",
    "django",
    "fastapi",
    "boto3",
    "pyyaml",
    "cryptography",
    "pytest",
    "pillow",
    "beautifulsoup4",
    "sqlalchemy",
    "pydantic",
    "setuptools",
    "scipy",
    "torch",
}

POPULAR_NPM = {
    "lodash",
    "express",
    "react",
    "axios",
    "chalk",
    "moment",
    "webpack",
    "typescript",
    "minimist",
    "dotenv",
    "commander",
    "debug",
    "uuid",
    "eslint",
    "prettier",
}

UNTRUSTED_GHA_CONTEXT_RE = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref)|comment\.body|discussion\.(?:title|body))[^}]*\}\}"
)
SUSPICIOUS_SCRIPT_RE = re.compile(
    r"(?:curl\s+|wget\s+|powershell\b|base64\s+-d|\beval\s*\(|bash\s+-c|sh\s+-c)",
    re.IGNORECASE,
)

SUPPLY_REMEDIATIONS = {
    "CICD001": "Assign untrusted github.event.* values to an intermediate env: variable instead of interpolating directly in run:.",
    "CICD002": "Avoid checking out PR head code in pull_request_target workflows, or isolate build permissions.",
    "CICD003": "Pin third-party GitHub Actions to a full 40-character commit SHA instead of a mutable tag/branch.",
    "CICD004": "Use least-privilege explicit permissions instead of permissions: write-all.",
    "SUP001": "Audit install/postinstall scripts for unexpected network calls or shell execution.",
    "SUP002": "Verify package spelling carefully to ensure this is not a typosquatting package.",
    "ARC001": "Remove secrets/.env files from packaged archives and rotate exposed credentials.",
}

MAX_ARCHIVE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_ARCHIVE_ENTRY_BYTES = 512 * 1024


def _edit_distance_one(a: str, b: str) -> bool:
    """Return True if strings a and b differ by exactly 1 insertion, deletion, substitution, or adjacent swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2:
            i, j = diffs
            return j == i + 1 and a[i] == b[j] and a[j] == b[i]
        return False
    short, long_s = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    skipped = False
    while i < len(short) and j < len(long_s):
        if short[i] == long_s[j]:
            i += 1
            j += 1
        elif not skipped:
            skipped = True
            j += 1
        else:
            return False
    return True


def _scan_cicd_workflows(root_path: Path, ignore_rules: list) -> List[Dict]:
    findings: List[Dict] = []

    def _add(rule_id: str, severity: str, fpath: Path, line_no: int, msg: str, match: str) -> None:
        if _is_ignored_by_vulnignore(fpath, root_path, rule_id, ignore_rules):
            return
        findings.append({
            "category": "supply_chain",
            "rule_id": rule_id,
            "severity": severity,
            "file": str(fpath),
            "line": line_no,
            "message": msg,
            "match": match[:120],
            "remediation": SUPPLY_REMEDIATIONS[rule_id],
        })

    for file_path in iter_scannable_files(root_path, {".yml", ".yaml"}, ignore_rules):
        is_gha = ".github/workflows" in str(file_path).replace("\\", "/")
        is_gitlab = file_path.name == ".gitlab-ci.yml"
        if not (is_gha or is_gitlab):
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = content.splitlines()
        uses_pr_target = "pull_request_target" in content

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if UNTRUSTED_GHA_CONTEXT_RE.search(line) and not _is_line_suppressed(line, "CICD001"):
                _add("CICD001", "CRITICAL", file_path, line_no, "Potential GitHub Actions script injection via untrusted event context", stripped)

            if uses_pr_target and "github.event.pull_request.head" in line and not _is_line_suppressed(line, "CICD002"):
                _add("CICD002", "HIGH", file_path, line_no, "pull_request_target checks out untrusted PR head ref", stripped)

            m_uses = re.match(r"^(?:-\s*)?uses\s*:\s*([^@\s]+)@([^\s#]+)", stripped)
            if m_uses and not _is_line_suppressed(line, "CICD003"):
                action, ref = m_uses.group(1), m_uses.group(2)
                if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                    _add("CICD003", "MEDIUM", file_path, line_no, f"GitHub Action '{action}@{ref}' is not pinned to a commit SHA", stripped)

            if re.match(r"^permissions\s*:\s*write-all\b", stripped) and not _is_line_suppressed(line, "CICD004"):
                _add("CICD004", "HIGH", file_path, line_no, "Over-privileged CI workflow token (permissions: write-all)", stripped)

    return findings


def _scan_install_scripts(root_path: Path, ignore_rules: list) -> List[Dict]:
    findings: List[Dict] = []

    for file_path in iter_scannable_files(root_path, {".json", ".py"}, ignore_rules):
        if file_path.name == "package.json":
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            scripts = data.get("scripts", {})
            if isinstance(scripts, dict):
                for hook in ("preinstall", "install", "postinstall", "prepare"):
                    cmd = scripts.get(hook)
                    if isinstance(cmd, str) and SUSPICIOUS_SCRIPT_RE.search(cmd):
                        if not _is_ignored_by_vulnignore(file_path, root_path, "SUP001", ignore_rules):
                            findings.append({
                                "category": "supply_chain",
                                "rule_id": "SUP001",
                                "severity": "HIGH",
                                "file": str(file_path),
                                "line": 1,
                                "message": f"Suspicious npm '{hook}' lifecycle script executes network/shell command",
                                "match": f"{hook}: {cmd[:100]}",
                                "remediation": SUPPLY_REMEDIATIONS["SUP001"],
                            })

        elif file_path.name == "setup.py":
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "cmdclass" in content and SUSPICIOUS_SCRIPT_RE.search(content):
                if not _is_ignored_by_vulnignore(file_path, root_path, "SUP001", ignore_rules):
                    findings.append({
                        "category": "supply_chain",
                        "rule_id": "SUP001",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": 1,
                        "message": "setup.py defines cmdclass hook with shell/network execution",
                        "match": "setup.py cmdclass",
                        "remediation": SUPPLY_REMEDIATIONS["SUP001"],
                    })

    return findings


def _scan_typosquatting(root_path: Path, ignore_rules: list) -> List[Dict]:
    findings: List[Dict] = []
    seen: Set[str] = set()

    for lockfile in find_lockfiles(root_path):
        if _is_ignored_by_vulnignore(lockfile, root_path, "SUP002", ignore_rules):
            continue
        eco, pkgs = parse_lockfile(lockfile)
        if eco == "PyPI":
            popular = POPULAR_PYPI
        elif eco == "npm":
            popular = POPULAR_NPM
        else:
            continue

        for name, _ in pkgs:
            norm = name.lower().strip()
            if norm in popular or (eco, norm) in seen:
                continue
            for target in popular:
                if len(target) >= 5 and _edit_distance_one(norm, target):
                    seen.add((eco, norm))
                    findings.append({
                        "category": "supply_chain",
                        "rule_id": "SUP002",
                        "severity": "HIGH",
                        "file": str(lockfile),
                        "line": 1,
                        "message": f"Potential typosquatting dependency '{name}' [{eco}] closely resembles '{target}'",
                        "match": f"{name} ~ {target}",
                        "remediation": SUPPLY_REMEDIATIONS["SUP002"],
                    })
                    break

    return findings


def _scan_archives(root_path: Path, ignore_rules: list) -> List[Dict]:
    findings: List[Dict] = []

    for file_path in iter_scannable_files(root_path, {".zip", ".whl", ".jar"}, ignore_rules):
        try:
            if file_path.stat().st_size > MAX_ARCHIVE_BYTES:
                continue
            with zipfile.ZipFile(file_path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > MAX_ARCHIVE_ENTRY_BYTES:
                        continue
                    entry_name = Path(info.filename).name
                    if entry_name == ".env" or entry_name.endswith((".pem", ".key")):
                        if not _is_ignored_by_vulnignore(file_path, root_path, "ARC001", ignore_rules):
                            findings.append({
                                "category": "supply_chain",
                                "rule_id": "ARC001",
                                "severity": "CRITICAL",
                                "file": f"{file_path}!/{info.filename}",
                                "line": 1,
                                "message": f"Sensitive file '{entry_name}' bundled inside archive",
                                "match": info.filename,
                                "remediation": SUPPLY_REMEDIATIONS["ARC001"],
                            })
                        continue

                    if not info.filename.endswith((".py", ".js", ".json", ".txt", ".cfg", ".properties", ".yml")):
                        continue
                    raw = zf.read(info.filename).decode("utf-8", errors="ignore")
                    for rule_id, severity, desc, pattern in SECRET_PATTERNS:
                        m = pattern.search(raw)
                        if not m:
                            continue
                        matched = m.group(1) if m.lastindex else m.group(0)
                        if rule_id == "SEC007" and _is_placeholder(matched):
                            continue
                        if not _is_ignored_by_vulnignore(file_path, root_path, "ARC001", ignore_rules):
                            findings.append({
                                "category": "supply_chain",
                                "rule_id": "ARC001",
                                "severity": severity,
                                "file": f"{file_path}!/{info.filename}",
                                "line": 1,
                                "message": f"Secret bundled in archive: {desc}",
                                "match": redact_secret(matched),
                                "remediation": SUPPLY_REMEDIATIONS["ARC001"],
                            })
                        break
        except Exception:
            continue

    return findings


def scan_supply_chain(root_path: Path) -> List[Dict]:
    """Run CI/CD workflow, lifecycle install-script, typosquatting, and archive checks."""
    ignore_rules = load_vulnignore(root_path)
    findings: List[Dict] = []
    findings.extend(_scan_cicd_workflows(root_path, ignore_rules))
    findings.extend(_scan_install_scripts(root_path, ignore_rules))
    findings.extend(_scan_typosquatting(root_path, ignore_rules))
    findings.extend(_scan_archives(root_path, ignore_rules))
    return findings
