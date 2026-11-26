import html
import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from vuln_scanner.parsers import find_lockfiles, parse_lockfile

SARIF_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

PURL_ECOSYSTEM_MAP = {
    "npm": "npm",
    "PyPI": "pypi",
    "Maven": "maven",
    "RubyGems": "gem",
    "Go": "golang",
    "crates.io": "cargo",
    "Packagist": "composer",
}

SECTIONS = (
    ("secrets", "Secret & Credential Findings"),
    ("git_history", "Git History Secret Leaks"),
    ("sast", "Static Security Analysis (SAST & Taint)"),
    ("iac", "Container & IaC Security Findings"),
    ("supply_chain", "Supply-Chain & CI/CD Security"),
    ("compliance", "PII & Cloud IAM Compliance"),
    ("image", "Container Image Layer Findings"),
    ("cyber", "Host, Permission & Network Security"),
    ("web", "Live Web / HTTP Security Audit"),
    ("dns", "DNS & Email Security Posture"),
    ("licenses", "License Compliance Findings"),
    ("custom", "Custom Policy Rule Findings"),
    ("hygiene", "Dependency Hygiene Findings"),
)


def format_text(report: Dict[str, List[Dict]]) -> str:
    """Format scan findings as a human-readable report with remediation hints."""
    total = sum(len(v) for v in report.values())
    if total == 0:
        return "No security issues or known vulnerabilities found."

    lines: List[str] = []

    if report.get("dependencies"):
        lines.append("=== Dependency Vulnerabilities (OSV) ===")
        for entry in report["dependencies"]:
            lines.append(f"File: {entry['file']}")
            lines.append(
                f"Package: {entry['package']} ({entry['version']}) [{entry['ecosystem']}]"
            )
            for vuln in entry["vulns"]:
                id_ = vuln.get("id", "N/A")
                summary = vuln.get("summary", "")
                severity = vuln.get("resolved_severity") or entry.get("severity", "HIGH")
                fixed = vuln.get("fixed_version")
                fix_hint = f" | Fix: upgrade to {fixed}" if fixed else ""
                lines.append(f"  - [{severity}] {id_}: {summary}{fix_hint}")
            lines.append("-")

    for section, title in SECTIONS:
        items = report.get(section, [])
        if not items:
            continue
        lines.append(f"=== {title} ===")
        for item in items:
            lines.append(
                f"[{item['severity']}] {item['rule_id']} {item['file']}:{item['line']} - "
                f"{item['message']} ({item['match']})"
            )
            if item.get("remediation"):
                lines.append(f"  Remediation: {item['remediation']}")
        lines.append("-")

    lines.append(
        "Summary: "
        f"{len(report.get('dependencies', []))} vulnerable dependencies, "
        f"{len(report.get('secrets', []))} secrets, "
        f"{len(report.get('git_history', []))} git history secrets, "
        f"{len(report.get('sast', []))} SAST issues, "
        f"{len(report.get('iac', []))} IaC issues, "
        f"{len(report.get('supply_chain', []))} supply-chain/CI issues, "
        f"{len(report.get('compliance', []))} PII/IAM issues, "
        f"{len(report.get('image', []))} image issues, "
        f"{len(report.get('cyber', []))} host/network issues, "
        f"{len(report.get('web', []))} web issues, "
        f"{len(report.get('dns', []))} DNS issues, "
        f"{len(report.get('licenses', []))} license issues, "
        f"{len(report.get('custom', []))} custom rule issues, "
        f"{len(report.get('hygiene', []))} hygiene issues"
    )
    return "\n".join(lines)


def format_json(report: Dict[str, List[Dict]]) -> str:
    return json.dumps(report, indent=2)


def format_sarif(report: Dict[str, List[Dict]]) -> str:
    """Format scan findings as SARIF 2.1.0 for GitHub Code Scanning & CI tools."""
    rules_by_id: Dict[str, Dict] = {}
    results: List[Dict] = []

    def _ensure_rule(rule_id: str, short_desc: str, remediation: str = "") -> None:
        if rule_id in rules_by_id:
            return
        rule: Dict = {
            "id": rule_id,
            "shortDescription": {"text": short_desc},
        }
        if remediation:
            rule["help"] = {"text": remediation}
        rules_by_id[rule_id] = rule

    for entry in report.get("dependencies", []):
        for vuln in entry.get("vulns", []):
            vuln_id = vuln.get("id", "OSV-UNKNOWN")
            severity = (vuln.get("resolved_severity") or entry.get("severity", "HIGH")).upper()
            summary = vuln.get("summary") or f"Vulnerability {vuln_id}"
            fixed = vuln.get("fixed_version")
            remediation = (
                f"Upgrade {entry['package']} to version {fixed}."
                if fixed
                else f"Check advisory {vuln_id} for {entry['package']} remediation."
            )
            _ensure_rule(vuln_id, summary, remediation)
            results.append({
                "ruleId": vuln_id,
                "level": SARIF_LEVEL_MAP.get(severity, "warning"),
                "message": {
                    "text": f"{entry['package']} ({entry['version']}) [{entry['ecosystem']}]: {summary}. {remediation}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": entry["file"]},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            })

    for section, _ in SECTIONS:
        for item in report.get(section, []):
            rule_id = item["rule_id"]
            remediation = item.get("remediation", "")
            _ensure_rule(rule_id, item["message"], remediation)
            msg = item["message"]
            if remediation:
                msg = f"{msg}. Remediation: {remediation}"
            results.append({
                "ruleId": rule_id,
                "level": SARIF_LEVEL_MAP.get(item["severity"].upper(), "warning"),
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item["file"]},
                            "region": {"startLine": max(1, int(item.get("line", 1)))},
                        }
                    }
                ],
            })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vuln-scanner",
                        "version": "0.4.0",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def format_markdown(report: Dict[str, List[Dict]]) -> str:
    """Format scan findings as a Markdown summary suitable for PR comments."""
    lines = ["# Security Scan Report", ""]
    lines.append("| Category | Findings |")
    lines.append("| :--- | :---: |")
    lines.append(f"| Vulnerable Dependencies | {len(report.get('dependencies', []))} |")
    for section, title in SECTIONS:
        lines.append(f"| {title} | {len(report.get(section, []))} |")
    lines.append("")

    if report.get("dependencies"):
        lines.append("## Dependency Vulnerabilities")
        for entry in report["dependencies"]:
            for vuln in entry["vulns"]:
                sev = vuln.get("resolved_severity") or entry.get("severity", "HIGH")
                fixed = vuln.get("fixed_version")
                fix = f" (fix: `{fixed}`)" if fixed else ""
                lines.append(
                    f"- **[{sev}]** `{entry['package']}=={entry['version']}` ({entry['ecosystem']}): "
                    f"`{vuln.get('id', 'N/A')}` — {vuln.get('summary', '')}{fix}"
                )
        lines.append("")

    for section, title in SECTIONS:
        items = report.get(section, [])
        if not items:
            continue
        lines.append(f"## {title}")
        for item in items:
            rem = f" — *Fix: {item['remediation']}*" if item.get("remediation") else ""
            lines.append(
                f"- **[{item['severity']}]** `{item['rule_id']}` `{item['file']}:{item['line']}`: "
                f"{item['message']}{rem}"
            )
        lines.append("")

    return "\n".join(lines).rstrip()


def format_html(report: Dict[str, List[Dict]]) -> str:
    """Format scan findings as a self-contained HTML executive audit dashboard."""
    total = sum(len(v) for v in report.values())
    rows: List[str] = []

    for entry in report.get("dependencies", []):
        for vuln in entry["vulns"]:
            sev = html.escape(str(vuln.get("resolved_severity") or entry.get("severity", "HIGH")))
            fixed = vuln.get("fixed_version")
            rem = f"Upgrade to {fixed}" if fixed else "Check OSV advisory"
            rows.append(
                f"<tr><td><span class='badge {sev.lower()}'>{sev}</span></td>"
                f"<td>{html.escape(str(vuln.get('id', 'N/A')))}</td>"
                f"<td>Dependency</td>"
                f"<td>{html.escape(entry['file'])}</td>"
                f"<td>{html.escape(entry['package'])} ({html.escape(entry['version'])}) — {html.escape(vuln.get('summary', ''))}</td>"
                f"<td>{html.escape(rem)}</td></tr>"
            )

    for section, title in SECTIONS:
        for item in report.get(section, []):
            sev = html.escape(item["severity"])
            rows.append(
                f"<tr><td><span class='badge {sev.lower()}'>{sev}</span></td>"
                f"<td>{html.escape(item['rule_id'])}</td>"
                f"<td>{html.escape(title)}</td>"
                f"<td>{html.escape(item['file'])}:{item['line']}</td>"
                f"<td>{html.escape(item['message'])}</td>"
                f"<td>{html.escape(item.get('remediation', ''))}</td></tr>"
            )

    table_body = "\n".join(rows) if rows else "<tr><td colspan='6'>No security issues found.</td></tr>"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>vuln-scanner Security Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #0f172a; color: #e2e8f0; }}
  h1 {{ color: #f8fafc; }}
  .summary {{ margin-bottom: 1.5rem; padding: 1rem; background: #1e293b; border-radius: 8px; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; font-size: 0.9rem; }}
  th {{ background: #0f172a; color: #94a3b8; }}
  .badge {{ padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }}
  .critical {{ background: #991b1b; color: #fecaca; }}
  .high {{ background: #9a3412; color: #fed7aa; }}
  .medium {{ background: #854d0e; color: #fef08a; }}
  .low {{ background: #1e40af; color: #bfdbfe; }}
</style>
</head>
<body>
  <h1>vuln-scanner Security Report</h1>
  <div class="summary">Total findings: <strong>{total}</strong></div>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Location</th><th>Finding</th><th>Remediation</th></tr></thead>
    <tbody>
      {table_body}
    </tbody>
  </table>
</body>
</html>"""


def format_cyclonedx(report: Dict[str, List[Dict]], root_path: Optional[Path] = None) -> str:
    """Export discovered dependencies and vulnerabilities as a CycloneDX 1.5 JSON SBOM."""
    components: List[Dict] = []
    seen = set()

    if root_path is not None:
        for lockfile in find_lockfiles(root_path):
            eco, pkgs = parse_lockfile(lockfile)
            purl_type = PURL_ECOSYSTEM_MAP.get(eco, eco.lower())
            for name, ver in pkgs:
                if not ver or (eco, name, ver) in seen:
                    continue
                seen.add((eco, name, ver))
                purl = f"pkg:{purl_type}/{name}@{ver}"
                components.append({
                    "type": "library",
                    "name": name,
                    "version": ver,
                    "purl": purl,
                    "bom-ref": purl,
                })

    vulns: List[Dict] = []
    for entry in report.get("dependencies", []):
        eco = entry["ecosystem"]
        purl_type = PURL_ECOSYSTEM_MAP.get(eco, eco.lower())
        ref = f"pkg:{purl_type}/{entry['package']}@{entry['version']}"
        for v in entry.get("vulns", []):
            vulns.append({
                "id": v.get("id", "N/A"),
                "description": v.get("summary", ""),
                "ratings": [{"severity": (v.get("resolved_severity") or "HIGH").lower()}],
                "affects": [{"ref": ref}],
            })

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "vuln-scanner", "name": "vuln-scanner", "version": "0.4.0"}],
        },
        "components": components,
        "vulnerabilities": vulns,
    }
    return json.dumps(sbom, indent=2)
