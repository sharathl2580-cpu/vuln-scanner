import argparse
from concurrent.futures import ThreadPoolExecutor
import fnmatch
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from vuln_scanner.autofix import apply_dependency_fixes
from vuln_scanner.compliance_and_iam import scan_iam_policies, scan_pii
from vuln_scanner.config import load_config
from vuln_scanner.cross_file_taint import scan_cross_file_taint
from vuln_scanner.cyber_checks import scan_open_ports, scan_system_and_files
from vuln_scanner.dashboard import serve_dashboard
from vuln_scanner.git_history import scan_git_history
from vuln_scanner.iac_checks import scan_iac
from vuln_scanner.image_checks import scan_docker_image_tar
from vuln_scanner.license_checks import scan_licenses
from vuln_scanner.osv_client import (
    extract_fixed_version,
    extract_severity,
    query_osv_batch,
)
from vuln_scanner.parsers import (
    ECOSYSTEMS,
    find_lockfiles,
    parse_gemfile_lock,
    parse_lockfile,
    parse_maven_pom,
    parse_npm_lock,
    parse_requirements,
)
from vuln_scanner.reporting import (
    format_cyclonedx,
    format_html,
    format_json,
    format_markdown,
    format_sarif,
    format_text,
)
from vuln_scanner.security_checks import (
    scan_custom_rules,
    scan_dependency_hygiene,
    scan_sast,
    scan_secrets,
)
from vuln_scanner.supply_chain_checks import scan_supply_chain
from vuln_scanner.web_checks import scan_domain_posture, scan_url

SEVERITY_ORDER = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def query_osv(package: str, version: str, ecosystem: str) -> Dict:
    """Single-package OSV query helper (kept for backwards compatibility)."""
    payload = {
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }
    try:
        resp = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


def scan_dependencies(root: Path, use_cache: bool = True) -> List[Dict]:
    """Scan lockfiles and query OSV in batches for known vulnerabilities."""
    lockfile_entries: List[Tuple[Path, str, str, str]] = []
    batch_queries: List[Tuple[str, str, str]] = []

    for lockfile in find_lockfiles(root):
        ecosystem, pkgs = parse_lockfile(lockfile)
        for name, ver in pkgs:
            if not ver:
                continue
            lockfile_entries.append((lockfile, ecosystem, name, ver))
            batch_queries.append((name, ver, ecosystem))

    if not batch_queries:
        return []

    osv_results = query_osv_batch(batch_queries, use_cache=use_cache)
    results: List[Dict] = []

    for lockfile, ecosystem, name, ver in lockfile_entries:
        vulns = osv_results.get((name, ver, ecosystem))
        if not vulns:
            continue

        enriched_vulns: List[Dict] = []
        highest_sev = "LOW"
        for vuln in vulns:
            sev = extract_severity(vuln)
            if SEVERITY_ORDER.get(sev, 1) > SEVERITY_ORDER.get(highest_sev, 1):
                highest_sev = sev
            fixed = extract_fixed_version(vuln, name, ecosystem)
            enriched = dict(vuln)
            enriched["resolved_severity"] = sev
            if fixed:
                enriched["fixed_version"] = fixed
            enriched_vulns.append(enriched)

        results.append({
            "category": "dependency",
            "file": str(lockfile),
            "package": name,
            "version": ver,
            "ecosystem": ecosystem,
            "severity": highest_sev,
            "vulns": enriched_vulns,
        })

    return results


def _finding_fingerprint(section: str, item: Dict, root: Path) -> str:
    raw_file = str(item.get("file", ""))
    try:
        rel_file = str(Path(raw_file).resolve().relative_to(root.resolve()))
    except Exception:
        rel_file = raw_file

    if section == "dependencies":
        ids = ",".join(sorted(v.get("id", "") for v in item.get("vulns", [])))
        return f"dep|{rel_file}|{item.get('package')}|{item.get('version')}|{ids}"
    return f"{section}|{item.get('rule_id')}|{rel_file}|{item.get('match')}"


def _git_changed_files(root: Path, base_ref: str) -> Optional[Set[str]]:
    repo_dir = root.parent if root.is_file() else root
    if not (repo_dir / ".git").exists():
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_dir), "diff", "--name-only", f"{base_ref}...HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            return None
        changed = {
            str((repo_dir / p.strip()).resolve())
            for p in proc.stdout.splitlines()
            if p.strip()
        }
        return changed
    except Exception:
        return None


def _filter_report(
    report: Dict[str, List[Dict]],
    root: Path,
    excludes: Optional[List[str]] = None,
    ignore_rules: Optional[List[str]] = None,
    baseline_fps: Optional[Set[str]] = None,
    changed_files: Optional[Set[str]] = None,
) -> Dict[str, List[Dict]]:
    exclude_pats = excludes or []
    ignored_ids = {r.upper() for r in (ignore_rules or [])}
    baseline = baseline_fps or set()

    def _keep_file(file_str: str) -> bool:
        if changed_files is not None:
            try:
                resolved = str(Path(file_str).resolve())
                if resolved not in changed_files:
                    return False
            except Exception:
                return False
        if exclude_pats:
            try:
                rel = str(Path(file_str).relative_to(root))
            except ValueError:
                rel = file_str
            for pat in exclude_pats:
                if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(Path(file_str).name, pat):
                    return False
        return True

    filtered: Dict[str, List[Dict]] = {}
    for section, items in report.items():
        kept: List[Dict] = []
        for item in items:
            if not _keep_file(str(item.get("file", ""))):
                continue
            rule_id = str(item.get("rule_id", "")).upper()
            if rule_id and rule_id in ignored_ids:
                continue
            if baseline and _finding_fingerprint(section, item, root) in baseline:
                continue
            kept.append(item)
        filtered[section] = kept
    return filtered


def scan_path(
    root_path: str,
    checks: Optional[List[str]] = None,
    no_network: bool = False,
    use_cache: bool = True,
    target_url: Optional[str] = None,
    target_host: Optional[str] = None,
    target_domain: Optional[str] = None,
    active_web: bool = False,
    image_tar: Optional[str] = None,
    git_history: bool = False,
    git_max_commits: int = 50,
    custom_rules: Optional[List[Dict[str, Any]]] = None,
    excludes: Optional[List[str]] = None,
    ignore_rules: Optional[List[str]] = None,
    baseline_path: Optional[str] = None,
    diff_base: Optional[str] = None,
) -> Dict[str, List[Dict]]:
    """Run selected security checks concurrently on root_path and return grouped findings."""
    root = Path(root_path)
    selected = set(checks or ["all"])
    run_all = "all" in selected

    report: Dict[str, List[Dict]] = {
        "dependencies": [],
        "secrets": [],
        "git_history": [],
        "sast": [],
        "iac": [],
        "supply_chain": [],
        "compliance": [],
        "image": [],
        "cyber": [],
        "web": [],
        "dns": [],
        "licenses": [],
        "custom": [],
        "hygiene": [],
    }

    futures = {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        if (run_all or "deps" in selected) and not no_network:
            futures["dependencies"] = pool.submit(scan_dependencies, root, use_cache)
        if run_all or "secrets" in selected:
            futures["secrets"] = pool.submit(scan_secrets, root)
        if git_history or "git" in selected:
            futures["git_history"] = pool.submit(scan_git_history, root, git_max_commits)
        if run_all or "sast" in selected:
            futures["sast"] = pool.submit(scan_sast, root)
            futures["cross_taint"] = pool.submit(scan_cross_file_taint, root)
        if run_all or "iac" in selected:
            futures["iac"] = pool.submit(scan_iac, root)
        if run_all or "supply" in selected:
            futures["supply_chain"] = pool.submit(scan_supply_chain, root)
        if run_all or "compliance" in selected:
            futures["pii"] = pool.submit(scan_pii, root)
            futures["iam"] = pool.submit(scan_iam_policies, root)
        if image_tar:
            futures["image"] = pool.submit(scan_docker_image_tar, Path(image_tar), no_network, use_cache)
        if run_all or "cyber" in selected:
            futures["cyber"] = pool.submit(scan_system_and_files, root)
        if run_all or "licenses" in selected:
            futures["licenses"] = pool.submit(scan_licenses, root, no_network, use_cache)
        if run_all or "hygiene" in selected:
            futures["hygiene"] = pool.submit(scan_dependency_hygiene, root)
        if custom_rules:
            futures["custom"] = pool.submit(scan_custom_rules, root, custom_rules)
        if target_host and not no_network:
            futures["ports"] = pool.submit(scan_open_ports, target_host)
        if target_url and not no_network:
            futures["web"] = pool.submit(scan_url, target_url, 10, True, active_web)
        if target_domain and not no_network:
            futures["dns"] = pool.submit(scan_domain_posture, target_domain)

        for key, fut in futures.items():
            if key == "ports":
                report["cyber"].extend(fut.result())
            elif key == "cross_taint":
                report["sast"].extend(fut.result())
            elif key in {"pii", "iam"}:
                report["compliance"].extend(fut.result())
            else:
                report[key] = fut.result()

    baseline_fps: Optional[Set[str]] = None
    if baseline_path and Path(baseline_path).exists():
        try:
            baseline_fps = set(json.loads(Path(baseline_path).read_text(encoding="utf-8")))
        except Exception:
            baseline_fps = None

    changed_files = _git_changed_files(root, diff_base) if diff_base else None

    return _filter_report(
        report,
        root,
        excludes=excludes,
        ignore_rules=ignore_rules,
        baseline_fps=baseline_fps,
        changed_files=changed_files,
    )


def _exceeds_threshold(report: Dict[str, List[Dict]], fail_on: str) -> bool:
    threshold = SEVERITY_ORDER.get(fail_on.upper(), 0)
    if threshold == 0:
        return False

    for finding in report.get("dependencies", []):
        if SEVERITY_ORDER.get(finding.get("severity", "HIGH").upper(), 3) >= threshold:
            return True

    for section in (
        "secrets",
        "git_history",
        "sast",
        "iac",
        "supply_chain",
        "compliance",
        "image",
        "cyber",
        "web",
        "dns",
        "licenses",
        "custom",
        "hygiene",
    ):
        for finding in report.get(section, []):
            sev = finding.get("severity", "LOW").upper()
            if SEVERITY_ORDER.get(sev, 1) >= threshold:
                return True

    return False


def pretty_print(report: Dict[str, List[Dict]]) -> None:
    print(format_text(report))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Comprehensive cybersecurity scanner for dependencies, secrets, SAST, taint, IaC, licenses, host, and web."
    )
    parser.add_argument("path", help="Path to the project directory or file to scan")
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["all", "deps", "secrets", "git", "sast", "iac", "supply", "compliance", "cyber", "licenses", "hygiene"],
        default=None,
        help="Security checks to run (default: all, or from vuln-scanner.toml)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif", "markdown", "html", "cyclonedx"],
        default=None,
        dest="output_format",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Alias for --format json",
    )
    parser.add_argument("--output", help="Write formatted output to a file instead of stdout")
    parser.add_argument("--url", dest="target_url", help="Live URL to audit HTTP headers, CORS, TLS, and recon paths")
    parser.add_argument("--active-web", action="store_true", help="Enable opt-in safe active DAST probes on --url")
    parser.add_argument("--domain", dest="target_domain", help="Domain to audit SPF, DMARC, and subdomain takeover posture")
    parser.add_argument("--host", dest="target_host", help="Host/IP to audit for exposed high-risk network ports")
    parser.add_argument("--image", dest="image_tar", help="Path to a docker-save image .tar file to scan layers & OS packages")
    parser.add_argument("--serve", action="store_true", help="Launch interactive local web dashboard after scanning")
    parser.add_argument("--port", type=int, default=8443, help="Port for --serve web dashboard (default: 8443)")
    parser.add_argument("--git-history", action="store_true", default=None, help="Scan git commit history for leaked secrets")
    parser.add_argument("--git-max-commits", type=int, default=None, help="Max git commits to scan (default: 50)")
    parser.add_argument("--exclude", nargs="+", default=None, help="Glob patterns of files/paths to exclude")
    parser.add_argument("--ignore-rules", nargs="+", default=None, help="Rule IDs to suppress (e.g. SAST007 LIC003)")
    parser.add_argument("--baseline", help="Path to baseline JSON file of accepted findings to ignore")
    parser.add_argument("--save-baseline", help="Save current findings as a baseline JSON file")
    parser.add_argument("--diff", dest="diff_base", help="Only report findings in files changed vs git ref (e.g. main)")
    parser.add_argument("--fix", action="store_true", help="Auto-upgrade vulnerable pinned dependencies to fixed versions")
    parser.add_argument("--quiet", action="store_true", help="Only print output when findings exist")
    parser.add_argument("--no-network", action="store_true", default=None, help="Skip network queries (local checks only)")
    parser.add_argument("--no-cache", action="store_true", default=None, help="Disable local OSV/license response caching")
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default=None,
        help="Exit with code 1 if any finding meets or exceeds this severity",
    )
    args = parser.parse_args(argv)

    root = Path(args.path)
    cfg = load_config(root)
    checks = args.checks if args.checks is not None else cfg.get("checks", ["all"])
    fmt = (
        "json"
        if args.json_output
        else (args.output_format if args.output_format is not None else cfg.get("format", "text"))
    )
    no_network = args.no_network if args.no_network is not None else bool(cfg.get("no_network", False))
    no_cache = args.no_cache if args.no_cache is not None else bool(cfg.get("no_cache", False))
    git_history = args.git_history if args.git_history is not None else bool(cfg.get("git_history", False))
    git_max_commits = (
        args.git_max_commits if args.git_max_commits is not None else int(cfg.get("git_max_commits", 50))
    )
    excludes = args.exclude if args.exclude is not None else cfg.get("exclude", [])
    ignore_rules = args.ignore_rules if args.ignore_rules is not None else cfg.get("ignore_rules", [])
    custom_rules = cfg.get("custom_rules", [])
    fail_on = args.fail_on if args.fail_on is not None else str(cfg.get("fail_on", "none"))

    report = scan_path(
        args.path,
        checks=checks,
        no_network=no_network,
        use_cache=not no_cache,
        target_url=args.target_url,
        target_host=args.target_host,
        target_domain=args.target_domain,
        active_web=args.active_web,
        image_tar=args.image_tar,
        git_history=git_history,
        git_max_commits=git_max_commits,
        custom_rules=custom_rules,
        excludes=excludes,
        ignore_rules=ignore_rules,
        baseline_path=args.baseline,
        diff_base=args.diff_base,
    )

    if args.save_baseline:
        fps = sorted(
            _finding_fingerprint(section, item, root)
            for section, items in report.items()
            for item in items
        )
        Path(args.save_baseline).write_text(json.dumps(fps, indent=2) + "\n", encoding="utf-8")

    if args.fix:
        applied = apply_dependency_fixes(report, root)
        if applied and not args.quiet:
            print("Applied dependency fixes:")
            for line in applied:
                print(f"  - {line}")

    if fmt == "json":
        rendered = format_json(report)
    elif fmt == "sarif":
        rendered = format_sarif(report)
    elif fmt == "markdown":
        rendered = format_markdown(report)
    elif fmt == "html":
        rendered = format_html(report)
    elif fmt == "cyclonedx":
        rendered = format_cyclonedx(report, root)
    else:
        rendered = format_text(report)

    total_findings = sum(len(v) for v in report.values())
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    elif not (args.quiet and total_findings == 0):
        print(rendered)

    if args.serve:
        serve_dashboard(report, root_path=root, port=args.port)

    return 1 if _exceeds_threshold(report, fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
