import re
import subprocess
from pathlib import Path
from typing import Dict, List

from vuln_scanner.security_checks import (
    ENTROPY_ASSIGN_RE,
    REMEDIATIONS,
    SECRET_PATTERNS,
    _is_placeholder,
    _shannon_entropy,
    redact_secret,
)

GIT_SECRET_REMEDIATION = (
    "Purge the secret from git history (e.g. git filter-repo / BFG) and rotate the credential immediately."
)


def scan_git_history(root_path: Path, max_commits: int = 50) -> List[Dict]:
    """Scan recent git commit diffs for leaked secrets in added lines."""
    repo_dir = root_path.parent if root_path.is_file() else root_path
    if not (repo_dir / ".git").exists():
        return []

    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_dir), "log", f"-n{max_commits}", "-p", "--no-color"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception:
        return []

    if proc.returncode != 0 or not proc.stdout:
        return []

    findings: List[Dict] = []
    seen = set()
    current_commit = ""
    current_file = "<unknown>"

    for line in proc.stdout.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:8]
            continue
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue

        added = line[1:]
        matched_known = False

        for rule_id, severity, description, pattern in SECRET_PATTERNS:
            match = pattern.search(added)
            if not match:
                continue
            matched_text = match.group(1) if match.lastindex else match.group(0)
            if rule_id == "SEC007" and _is_placeholder(matched_text):
                continue
            matched_known = True
            dedup_key = (rule_id, current_file, matched_text)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append({
                "category": "git_history",
                "rule_id": rule_id,
                "severity": severity,
                "file": f"{current_file}@{current_commit}",
                "line": 1,
                "message": f"[git history {current_commit}] {description}",
                "match": redact_secret(matched_text),
                "remediation": GIT_SECRET_REMEDIATION,
            })

        if not matched_known:
            ent_match = ENTROPY_ASSIGN_RE.search(added)
            if ent_match:
                candidate = ent_match.group(1)
                if not _is_placeholder(candidate) and _shannon_entropy(candidate) >= 4.0:
                    dedup_key = ("SEC008", current_file, candidate)
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        findings.append({
                            "category": "git_history",
                            "rule_id": "SEC008",
                            "severity": "HIGH",
                            "file": f"{current_file}@{current_commit}",
                            "line": 1,
                            "message": f"[git history {current_commit}] High-entropy secret in commit diff",
                            "match": redact_secret(candidate),
                            "remediation": GIT_SECRET_REMEDIATION,
                        })

    return findings
