import json
import re
from pathlib import Path
from typing import Dict, List

from vuln_scanner.security_checks import (
    TEXT_EXTENSIONS,
    _is_ignored_by_vulnignore,
    _is_line_suppressed,
    iter_scannable_files,
    load_vulnignore,
    redact_secret,
)

CC_CANDIDATE_RE = re.compile(r"\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7})\b")
SSN_RE = re.compile(r"\b(?!000|666|9\d{2})(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b")
IGNORED_SSNS = {"123-45-6789", "111-11-1111", "999-99-9999"}

COMPLIANCE_REMEDIATIONS = {
    "PII001": "Remove hardcoded payment card numbers from code/logs and tokenize via a PCI-DSS compliant vault.",
    "PII002": "Remove hardcoded SSNs from code/fixtures/logs and mask or encrypt sensitive PII.",
    "IAM001": "Replace Action='*' and Resource='*' with least-privilege scoped actions and resource ARNs.",
    "IAM002": "Scope wildcard service actions and add IAM Conditions (e.g. aws:MultiFactorAuthPresent).",
    "IAM003": "Scope Terraform IAM policy actions and resources instead of using ['*'].",
}


def _luhn_valid(digits: str) -> bool:
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    reverse = digits[::-1]
    for idx, ch in enumerate(reverse):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def scan_pii(root_path: Path) -> List[Dict]:
    """Scan files for unmasked PCI/PII data (Luhn-valid card numbers and SSNs)."""
    findings: List[Dict] = []
    ignore_rules = load_vulnignore(root_path)

    for file_path in iter_scannable_files(root_path, TEXT_EXTENSIONS, ignore_rules):
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for line_no, line in enumerate(lines, start=1):
            if not (_is_line_suppressed(line, "PII001") or _is_ignored_by_vulnignore(file_path, root_path, "PII001", ignore_rules)):
                for m in CC_CANDIDATE_RE.finditer(line):
                    digits = re.sub(r"[-\s]", "", m.group(1))
                    if _luhn_valid(digits):
                        findings.append({
                            "category": "compliance",
                            "rule_id": "PII001",
                            "severity": "HIGH",
                            "file": str(file_path),
                            "line": line_no,
                            "message": "Potential unmasked payment card number (Luhn-valid) detected",
                            "match": redact_secret(digits),
                            "remediation": COMPLIANCE_REMEDIATIONS["PII001"],
                        })
                        break

            if not (_is_line_suppressed(line, "PII002") or _is_ignored_by_vulnignore(file_path, root_path, "PII002", ignore_rules)):
                m_ssn = SSN_RE.search(line)
                if m_ssn and m_ssn.group(0) not in IGNORED_SSNS:
                    findings.append({
                        "category": "compliance",
                        "rule_id": "PII002",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_no,
                        "message": "Potential US Social Security Number (SSN) detected",
                        "match": f"***-**-{m_ssn.group(3)}",
                        "remediation": COMPLIANCE_REMEDIATIONS["PII002"],
                    })

    return findings


def scan_iam_policies(root_path: Path) -> List[Dict]:
    """Audit JSON IAM policies and Terraform IAM blocks for overly permissive privileges."""
    findings: List[Dict] = []
    ignore_rules = load_vulnignore(root_path)

    def _add(rule_id: str, severity: str, fpath: Path, line_no: int, msg: str, match: str) -> None:
        if _is_ignored_by_vulnignore(fpath, root_path, rule_id, ignore_rules):
            return
        findings.append({
            "category": "compliance",
            "rule_id": rule_id,
            "severity": severity,
            "file": str(fpath),
            "line": line_no,
            "message": msg,
            "match": match[:120],
            "remediation": COMPLIANCE_REMEDIATIONS[rule_id],
        })

    for file_path in iter_scannable_files(root_path, {".json", ".tf"}, ignore_rules):
        if file_path.suffix.lower() == ".json":
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            stmts = data.get("Statement") if isinstance(data, dict) else None
            if not isinstance(stmts, list):
                continue
            for stmt in stmts:
                if not isinstance(stmt, dict) or str(stmt.get("Effect", "")).lower() != "allow":
                    continue
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                act_list = actions if isinstance(actions, list) else [actions]
                res_list = resources if isinstance(resources, list) else [resources]
                has_star_res = "*" in res_list
                if "*" in act_list and has_star_res:
                    _add("IAM001", "CRITICAL", file_path, 1, "IAM policy grants full admin privileges (Action: '*', Resource: '*')", "Action:* Resource:*")
                elif has_star_res and any(isinstance(a, str) and a.endswith(":*") for a in act_list) and "Condition" not in stmt:
                    _add("IAM002", "HIGH", file_path, 1, "IAM policy grants wildcard service actions on Resource: '*' without Condition", ", ".join(str(a) for a in act_list))

        elif file_path.suffix.lower() == ".tf":
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if re.search(r'actions\s*=\s*\[\s*"\*"\s*\]', content) and re.search(r'resources\s*=\s*\[\s*"\*"\s*\]', content):
                _add("IAM003", "CRITICAL", file_path, 1, "Terraform IAM policy allows actions=['*'] on resources=['*']", 'actions=["*"] resources=["*"]')

    return findings
