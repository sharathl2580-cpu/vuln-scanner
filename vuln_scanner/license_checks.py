import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

from vuln_scanner.osv_client import OSVCache
from vuln_scanner.parsers import find_lockfiles, parse_lockfile
from vuln_scanner.security_checks import (
    _is_ignored_by_vulnignore,
    iter_scannable_files,
    load_vulnignore,
)

STRONG_COPYLEFT = {
    "AGPL-3.0",
    "AGPL-3.0-ONLY",
    "AGPL-3.0-OR-LATER",
    "AGPL-1.0",
    "GPL-3.0",
    "GPL-3.0-ONLY",
    "GPL-3.0-OR-LATER",
    "GPL-2.0",
    "GPL-2.0-ONLY",
    "GPL-2.0-OR-LATER",
    "SSPL-1.0",
    "EUPL-1.2",
}

WEAK_COPYLEFT = {
    "LGPL-3.0",
    "LGPL-3.0-ONLY",
    "LGPL-3.0-OR-LATER",
    "LGPL-2.1",
    "LGPL-2.1-ONLY",
    "MPL-2.0",
    "EPL-2.0",
    "EPL-1.0",
    "CDDL-1.0",
}

LICENSE_REMEDIATIONS = {
    "LIC001": "Strong copyleft license may require disclosing source code; replace dependency or get legal approval.",
    "LIC002": "Weak copyleft/reciprocal license detected; ensure attribution and dynamic-linking compliance.",
    "LIC003": "Add a LICENSE file or declare an explicit license identifier in the project manifest.",
}


def classify_license(license_str: str) -> Optional[Tuple[str, str, str]]:
    """Return (rule_id, severity, reason) if license_str carries compliance risk, else None."""
    if not license_str:
        return None
    upper = license_str.strip().upper()
    if upper in {"UNLICENSED", "PROPRIETARY", "UNKNOWN", "NONE"}:
        return ("LIC002", "MEDIUM", f"Ambiguous or restrictive license '{license_str}'")

    tokens = [tok.strip() for tok in re.split(r"[\s,/()]+", upper) if tok.strip()]
    for tok in tokens:
        if tok in STRONG_COPYLEFT or tok.startswith(("GPL", "AGPL", "SSPL")):
            return ("LIC001", "HIGH", f"Strong copyleft license '{license_str}' detected")
        if tok in WEAK_COPYLEFT or tok.startswith(("LGPL", "MPL-", "EPL-", "CDDL")):
            return ("LIC002", "MEDIUM", f"Weak copyleft license '{license_str}' detected")
    return None


def _fetch_package_license(
    package: str,
    version: str,
    ecosystem: str,
    cache: Optional[OSVCache] = None,
) -> Optional[str]:
    """Fetch license string for PyPI or npm packages (cached)."""
    cache_key = f"license:{ecosystem}:{package}:{version}"
    if cache is not None:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached.get("license")

    lic: Optional[str] = None
    try:
        if ecosystem == "PyPI":
            url = f"https://pypi.org/pypi/{package}/{version}/json"
            resp = requests.get(url, timeout=8)
            if resp.status_code == 200:
                info = resp.json().get("info", {})
                lic = info.get("license") or info.get("license_expression")
                if not lic:
                    for cls in info.get("classifiers", []):
                        if cls.startswith("License :: OSI Approved :: "):
                            lic = cls.split("::")[-1].strip()
                            break
        elif ecosystem == "npm":
            url = f"https://registry.npmjs.org/{package}/{version}"
            resp = requests.get(url, timeout=8)
            if resp.status_code == 200:
                raw_lic = resp.json().get("license")
                if isinstance(raw_lic, dict):
                    lic = raw_lic.get("type")
                elif isinstance(raw_lic, str):
                    lic = raw_lic
    except Exception:
        return None

    if cache is not None and lic is not None:
        cache.set(cache_key, {"license": lic})
    return lic


def scan_licenses(
    root_path: Path,
    no_network: bool = False,
    use_cache: bool = True,
) -> List[Dict]:
    """Audit project manifests, composer.lock, and dependencies for license compliance risks."""
    findings: List[Dict] = []
    ignore_rules = load_vulnignore(root_path)
    cache = OSVCache() if use_cache else None

    def _add(rule_id: str, severity: str, file_path: Path, line: int, message: str, match: str) -> None:
        if _is_ignored_by_vulnignore(file_path, root_path, rule_id, ignore_rules):
            return
        findings.append({
            "category": "license",
            "rule_id": rule_id,
            "severity": severity,
            "file": str(file_path),
            "line": line,
            "message": message,
            "match": match[:120],
            "remediation": LICENSE_REMEDIATIONS[rule_id],
        })

    # 1. Check root directory for a LICENSE file if this is a directory
    if root_path.is_dir():
        has_license_file = any(
            (root_path / name).exists()
            for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.txt")
        )
        if not has_license_file and find_lockfiles(root_path):
            _add(
                "LIC003",
                "LOW",
                root_path,
                1,
                "Project directory has dependency manifests but no LICENSE file",
                "LICENSE missing",
            )

    # 2. Check local manifests (package.json, setup.cfg, Cargo.toml, composer.lock)
    for file_path in iter_scannable_files(root_path, {".json", ".cfg", ".toml", ".lock"}, ignore_rules):
        if file_path.name == "package.json":
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            lic = data.get("license")
            if isinstance(lic, dict):
                lic = lic.get("type")
            if not lic:
                _add("LIC003", "LOW", file_path, 1, "package.json is missing a 'license' field", "license missing")
            elif isinstance(lic, str):
                risk = classify_license(lic)
                if risk:
                    rule_id, sev, msg = risk
                    _add(rule_id, sev, file_path, 1, f"Project package.json: {msg}", lic)

        elif file_path.name == "composer.lock":
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            for section in ("packages", "packages-dev"):
                for pkg in data.get(section, []):
                    if not isinstance(pkg, dict):
                        continue
                    pkg_name = pkg.get("name", "unknown")
                    for lic in pkg.get("license", []):
                        risk = classify_license(str(lic))
                        if risk:
                            rule_id, sev, msg = risk
                            _add(rule_id, sev, file_path, 1, f"{pkg_name}: {msg}", f"{pkg_name} ({lic})")

    # 3. Check third-party PyPI / npm dependency licenses via registry metadata (when online)
    if not no_network:
        seen = set()
        for lockfile in find_lockfiles(root_path):
            eco, pkgs = parse_lockfile(lockfile)
            if eco not in {"PyPI", "npm"}:
                continue
            for pkg, ver in pkgs:
                if not ver or (eco, pkg, ver) in seen:
                    continue
                seen.add((eco, pkg, ver))
                lic = _fetch_package_license(pkg, ver, eco, cache=cache)
                if lic:
                    risk = classify_license(lic)
                    if risk:
                        rule_id, sev, msg = risk
                        _add(rule_id, sev, lockfile, 1, f"{pkg}=={ver} [{eco}]: {msg}", f"{pkg} ({lic})")

    return findings
