import io
from pathlib import Path
import tarfile
from typing import Dict, List, Tuple

from vuln_scanner.osv_client import extract_fixed_version, extract_severity, query_osv_batch
from vuln_scanner.security_checks import SECRET_PATTERNS, _is_placeholder, redact_secret

MAX_IMAGE_ENTRY_BYTES = 2 * 1024 * 1024  # 2 MB per layer text entry


def _parse_dpkg_status(text: str) -> List[Tuple[str, str]]:
    pkgs: List[Tuple[str, str]] = []
    name = ""
    version = ""
    for line in text.splitlines():
        if not line.strip():
            if name and version:
                pkgs.append((name, version))
            name = ""
            version = ""
        elif line.startswith("Package:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
    if name and version:
        pkgs.append((name, version))
    return pkgs


def _parse_apk_installed(text: str) -> List[Tuple[str, str]]:
    pkgs: List[Tuple[str, str]] = []
    name = ""
    version = ""
    for line in text.splitlines():
        if not line.strip():
            if name and version:
                pkgs.append((name, version))
            name = ""
            version = ""
        elif line.startswith("P:"):
            name = line[2:].strip()
        elif line.startswith("V:"):
            version = line[2:].strip()
    if name and version:
        pkgs.append((name, version))
    return pkgs


def _scan_tar_stream(
    tf: tarfile.TarFile,
    label: str,
    os_pkgs: List[Tuple[str, str, str]],
    secret_findings: List[Dict],
) -> None:
    for member in tf.getmembers():
        if not member.isfile():
            continue
        norm = member.name.lstrip("./")

        # Recurse into nested Docker layer tarballs
        if norm.endswith(("layer.tar", ".tar")) and member.size <= 50 * 1024 * 1024:
            fobj = tf.extractfile(member)
            if fobj is not None:
                try:
                    data = fobj.read()
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as nested:
                        _scan_tar_stream(nested, f"{label}!/{norm}", os_pkgs, secret_findings)
                except Exception:
                    pass
            continue

        if member.size > MAX_IMAGE_ENTRY_BYTES:
            continue

        fobj = tf.extractfile(member)
        if fobj is None:
            continue

        if norm.endswith("var/lib/dpkg/status"):
            text = fobj.read().decode("utf-8", errors="ignore")
            for pkg, ver in _parse_dpkg_status(text):
                os_pkgs.append((pkg, ver, "Debian"))
        elif norm.endswith("lib/apk/db/installed"):
            text = fobj.read().decode("utf-8", errors="ignore")
            for pkg, ver in _parse_apk_installed(text):
                os_pkgs.append((pkg, ver, "Alpine"))
        elif Path(norm).name == ".env" or norm.endswith((".pem", ".key")):
            secret_findings.append({
                "category": "image",
                "rule_id": "IMG002",
                "severity": "CRITICAL",
                "file": f"{label}!/{norm}",
                "line": 1,
                "message": f"Sensitive file '{Path(norm).name}' baked into container image layer",
                "match": norm,
                "remediation": "Remove sensitive files from image layers and mount secrets at runtime.",
            })
        elif norm.endswith((".py", ".js", ".json", ".yml", ".yaml", ".conf", ".env", ".sh")):
            text = fobj.read().decode("utf-8", errors="ignore")
            for rule_id, severity, desc, pat in SECRET_PATTERNS:
                m = pat.search(text)
                if not m:
                    continue
                matched = m.group(1) if m.lastindex else m.group(0)
                if rule_id == "SEC007" and _is_placeholder(matched):
                    continue
                secret_findings.append({
                    "category": "image",
                    "rule_id": "IMG002",
                    "severity": severity,
                    "file": f"{label}!/{norm}",
                    "line": 1,
                    "message": f"Secret baked into container image layer: {desc}",
                    "match": redact_secret(matched),
                    "remediation": "Rotate exposed credentials and pass secrets via runtime environment or secret mounts.",
                })
                break


def scan_docker_image_tar(
    tar_path: Path,
    no_network: bool = False,
    use_cache: bool = True,
) -> List[Dict]:
    """Inspect a docker-save image tarball for vulnerable OS packages and embedded secrets."""
    if not tar_path.exists():
        return []

    os_pkgs: List[Tuple[str, str, str]] = []
    findings: List[Dict] = []

    try:
        with tarfile.open(tar_path, mode="r:*") as tf:
            _scan_tar_stream(tf, str(tar_path), os_pkgs, findings)
    except Exception:
        return findings

    if os_pkgs and not no_network:
        osv_res = query_osv_batch(os_pkgs, use_cache=use_cache)
        for pkg, ver, eco in dict.fromkeys(os_pkgs):
            vulns = osv_res.get((pkg, ver, eco))
            if not vulns:
                continue
            for v in vulns:
                sev = extract_severity(v)
                fixed = extract_fixed_version(v, pkg, eco)
                fix_hint = f" (fix: {fixed})" if fixed else ""
                findings.append({
                    "category": "image",
                    "rule_id": "IMG001",
                    "severity": sev,
                    "file": str(tar_path),
                    "line": 1,
                    "message": f"Vulnerable OS package {pkg}=={ver} [{eco}]: {v.get('id', 'OSV')}{fix_hint}",
                    "match": f"{pkg} ({ver})",
                    "remediation": f"Upgrade {pkg} in base image or rebuild with updated packages.{fix_hint}",
                })

    return findings
