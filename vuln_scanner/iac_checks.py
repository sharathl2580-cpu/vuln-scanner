import re
from pathlib import Path
from typing import Dict, List

from vuln_scanner.security_checks import (
    _is_ignored_by_vulnignore,
    _is_line_suppressed,
    iter_scannable_files,
    load_vulnignore,
)

IAC_REMEDIATIONS = {
    "IAC001": "Add a non-root USER instruction (e.g. USER appuser) in the Dockerfile.",
    "IAC002": "Pin the base image to a specific version or SHA256 digest instead of :latest.",
    "IAC003": "Use COPY instead of ADD for remote URLs, or curl/wget with checksum verification.",
    "IAC004": "Do not bake secrets into ENV/ARG; pass them at runtime or use build secrets.",
    "IAC005": "Download scripts, verify checksums/signatures, and inspect before executing.",
    "IAC006": "Set privileged: false and drop unnecessary Linux capabilities.",
    "IAC007": "Disable hostNetwork/hostPID and set allowPrivilegeEscalation: false.",
    "IAC008": "Set runAsNonRoot: true and a non-zero runAsUser.",
    "IAC009": "Restrict CIDR blocks to specific trusted IP ranges instead of 0.0.0.0/0.",
    "IAC010": "Set S3 bucket ACL to private and enable Block Public Access.",
    "IAC011": "Enable encryption at rest (encrypted = true).",
}


def _scan_dockerfile(
    file_path: Path,
    root_path: Path,
    ignore_rules: list,
) -> List[Dict]:
    findings: List[Dict] = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    has_non_root_user = False
    from_line = 1

    def _add(rule_id: str, severity: str, line_no: int, message: str, match: str) -> None:
        line_text = lines[line_no - 1] if 1 <= line_no <= len(lines) else ""
        if _is_line_suppressed(line_text, rule_id) or _is_ignored_by_vulnignore(
            file_path, root_path, rule_id, ignore_rules
        ):
            return
        findings.append({
            "category": "iac",
            "rule_id": rule_id,
            "severity": severity,
            "file": str(file_path),
            "line": line_no,
            "message": message,
            "match": match[:120],
            "remediation": IAC_REMEDIATIONS[rule_id],
        })

    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        upper = stripped.upper()

        if upper.startswith("FROM "):
            from_line = line_no
            image = stripped[5:].strip().split()[0]
            if image.lower() != "scratch" and (":" not in image or image.endswith(":latest")):
                _add("IAC002", "MEDIUM", line_no, f"Unpinned or :latest base image '{image}'", stripped)

        elif upper.startswith("USER "):
            user = stripped[5:].strip().split(":")[0]
            if user in {"root", "0"}:
                _add("IAC001", "HIGH", line_no, "Container explicitly runs as root user", stripped)
            else:
                has_non_root_user = True

        elif upper.startswith("ADD ") and ("http://" in stripped.lower() or "https://" in stripped.lower()):
            _add("IAC003", "MEDIUM", line_no, "Dockerfile ADD fetches remote URL without integrity check", stripped)

        elif upper.startswith(("ENV ", "ARG ")):
            if re.search(r"(?i)(?:password|passwd|secret|api_key|apikey|token|private_key)[A-Z0-9_]*\s*=\s*\S+", stripped):
                _add("IAC004", "CRITICAL", line_no, "Potential secret hardcoded in Dockerfile ENV/ARG", stripped.split("=")[0])

        elif upper.startswith("RUN ") and re.search(r"(?:curl|wget)\b.*\|\s*(?:sh|bash)\b", stripped):
            _add("IAC005", "HIGH", line_no, "Piping remote script directly to shell in RUN", stripped)

    if lines and not has_non_root_user and not any(f["rule_id"] == "IAC001" for f in findings):
        _add("IAC001", "HIGH", from_line, "Dockerfile has no non-root USER instruction (defaults to root)", "USER root (default)")

    return findings


def _scan_yaml_iac(file_path: Path, root_path: Path, ignore_rules: list) -> List[Dict]:
    findings: List[Dict] = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    patterns = [
        ("IAC006", "CRITICAL", re.compile(r"^\s*privileged\s*:\s*true\b", re.IGNORECASE), "Privileged container enabled (privileged: true)"),
        ("IAC007", "HIGH", re.compile(r"^\s*(?:hostNetwork|hostPID|allowPrivilegeEscalation)\s*:\s*true\b", re.IGNORECASE), "Unsafe host namespace or privilege escalation enabled"),
        ("IAC008", "MEDIUM", re.compile(r"^\s*runAsUser\s*:\s*0\b", re.IGNORECASE), "Container configured to run as root (runAsUser: 0)"),
    ]

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for rule_id, severity, pat, msg in patterns:
            if pat.search(line):
                if _is_line_suppressed(line, rule_id) or _is_ignored_by_vulnignore(
                    file_path, root_path, rule_id, ignore_rules
                ):
                    continue
                findings.append({
                    "category": "iac",
                    "rule_id": rule_id,
                    "severity": severity,
                    "file": str(file_path),
                    "line": line_no,
                    "message": msg,
                    "match": stripped[:120],
                    "remediation": IAC_REMEDIATIONS[rule_id],
                })
    return findings


def _scan_terraform(file_path: Path, root_path: Path, ignore_rules: list) -> List[Dict]:
    findings: List[Dict] = []
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    patterns = [
        ("IAC009", "HIGH", re.compile(r"""(?:0\.0\.0\.0/0|::/0)"""), "Open CIDR block (0.0.0.0/0 or ::/0) in Terraform network rule"),
        ("IAC010", "HIGH", re.compile(r"""acl\s*=\s*["']public-read(?:-write)?["']"""), "Public S3 bucket ACL configured"),
        ("IAC011", "MEDIUM", re.compile(r"""encrypted\s*=\s*false\b"""), "Storage encryption explicitly disabled (encrypted = false)"),
    ]

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        for rule_id, severity, pat, msg in patterns:
            if pat.search(line):
                if _is_line_suppressed(line, rule_id) or _is_ignored_by_vulnignore(
                    file_path, root_path, rule_id, ignore_rules
                ):
                    continue
                findings.append({
                    "category": "iac",
                    "rule_id": rule_id,
                    "severity": severity,
                    "file": str(file_path),
                    "line": line_no,
                    "message": msg,
                    "match": stripped[:120],
                    "remediation": IAC_REMEDIATIONS[rule_id],
                })
    return findings


def scan_iac(root_path: Path) -> List[Dict]:
    """Scan Dockerfiles, Kubernetes/Compose YAML, and Terraform files for misconfigurations."""
    findings: List[Dict] = []
    ignore_rules = load_vulnignore(root_path)

    for file_path in iter_scannable_files(root_path, None, ignore_rules):
        name = file_path.name
        suffix = file_path.suffix.lower()
        if name == "Dockerfile" or name.startswith("Dockerfile."):
            findings.extend(_scan_dockerfile(file_path, root_path, ignore_rules))
        elif suffix in {".yml", ".yaml"}:
            findings.extend(_scan_yaml_iac(file_path, root_path, ignore_rules))
        elif suffix == ".tf":
            findings.extend(_scan_terraform(file_path, root_path, ignore_rules))

    return findings
