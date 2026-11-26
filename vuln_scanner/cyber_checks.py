from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import socket
import stat
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from vuln_scanner.security_checks import (
    _is_ignored_by_vulnignore,
    iter_scannable_files,
    load_vulnignore,
)

SENSITIVE_FILENAMES = {
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".npmrc",
    ".pypirc",
    "kubeconfig",
    ".htpasswd",
}

SENSITIVE_EXTENSIONS = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}

RISKY_PORTS: List[Tuple[int, str, str]] = [
    (21, "FTP", "Disable plaintext FTP and use SFTP/SCP."),
    (23, "Telnet", "Disable Telnet immediately and use SSH."),
    (445, "SMB", "Restrict SMB port 445 to internal/VPN networks."),
    (3306, "MySQL", "Bind MySQL to localhost or firewall port 3306."),
    (5432, "PostgreSQL", "Bind PostgreSQL to localhost or firewall port 5432."),
    (6379, "Redis", "Bind Redis to localhost and require AUTH + TLS."),
    (27017, "MongoDB", "Bind MongoDB to localhost and enable authentication."),
]

CYBER_REMEDIATIONS = {
    "SYS001": "Restrict file permissions (e.g. chmod 600 for keys, remove world-writable bit o-w).",
    "SYS002": "Remove sensitive credential/key files from the repository and rotate them.",
    "SYS003": "Add .env, *.pem, and *.key patterns to .gitignore so secrets are never committed.",
    "SYS004": "Firewall or bind exposed database/legacy service ports to localhost.",
}


def scan_system_and_files(root_path: Path) -> List[Dict]:
    """Audit file permissions, exposed key/credential files, and .gitignore hygiene."""
    findings: List[Dict] = []
    ignore_rules = load_vulnignore(root_path)

    gitignore_text = ""
    gitignore_path = (root_path.parent if root_path.is_file() else root_path) / ".gitignore"
    if gitignore_path.exists():
        try:
            gitignore_text = gitignore_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            pass

    for file_path in iter_scannable_files(root_path, None, ignore_rules):
        try:
            mode = file_path.stat().st_mode
        except OSError:
            continue

        name = file_path.name
        suffix = file_path.suffix.lower()

        # SYS001: World-writable files or over-permissive key files
        if mode & stat.S_IWOTH:
            if not _is_ignored_by_vulnignore(file_path, root_path, "SYS001", ignore_rules):
                findings.append({
                    "category": "cyber",
                    "rule_id": "SYS001",
                    "severity": "HIGH",
                    "file": str(file_path),
                    "line": 1,
                    "message": "World-writable file permissions detected (o+w)",
                    "match": oct(stat.S_IMODE(mode)),
                    "remediation": CYBER_REMEDIATIONS["SYS001"],
                })

        is_key_or_cred = name in SENSITIVE_FILENAMES or suffix in SENSITIVE_EXTENSIONS
        if is_key_or_cred:
            if (mode & (stat.S_IRGRP | stat.S_IROTH)) and not _is_ignored_by_vulnignore(
                file_path, root_path, "SYS001", ignore_rules
            ):
                findings.append({
                    "category": "cyber",
                    "rule_id": "SYS001",
                    "severity": "HIGH",
                    "file": str(file_path),
                    "line": 1,
                    "message": f"Sensitive key/credential file '{name}' is readable by group/others",
                    "match": oct(stat.S_IMODE(mode)),
                    "remediation": CYBER_REMEDIATIONS["SYS001"],
                })

            if not _is_ignored_by_vulnignore(file_path, root_path, "SYS002", ignore_rules):
                findings.append({
                    "category": "cyber",
                    "rule_id": "SYS002",
                    "severity": "CRITICAL",
                    "file": str(file_path),
                    "line": 1,
                    "message": f"Sensitive key/credential file '{name}' present in workspace",
                    "match": name,
                    "remediation": CYBER_REMEDIATIONS["SYS002"],
                })

        # SYS003: .env or key file not covered by .gitignore
        if gitignore_path.exists() and (name == ".env" or suffix in {".pem", ".key"}):
            pattern_present = (name in gitignore_text) or (f"*{suffix}" in gitignore_text if suffix else False)
            if not pattern_present and not _is_ignored_by_vulnignore(
                file_path, root_path, "SYS003", ignore_rules
            ):
                findings.append({
                    "category": "cyber",
                    "rule_id": "SYS003",
                    "severity": "MEDIUM",
                    "file": str(file_path),
                    "line": 1,
                    "message": f"Sensitive file '{name}' is not listed in .gitignore",
                    "match": name,
                    "remediation": CYBER_REMEDIATIONS["SYS003"],
                })

    return findings


def _probe_port(host: str, port: int, service: str, advice: str, timeout: float) -> Optional[Dict]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            return {
                "category": "cyber",
                "rule_id": "SYS004",
                "severity": "HIGH",
                "file": f"{host}:{port}",
                "line": 1,
                "message": f"Exposed {service} port {port} is open on {host}",
                "match": f"{host}:{port} ({service})",
                "remediation": advice,
            }
    except OSError:
        pass
    finally:
        sock.close()
    return None


def scan_open_ports(
    host: str,
    ports: Optional[List[Tuple[int, str, str]]] = None,
    timeout: float = 0.5,
) -> List[Dict]:
    """Check for exposed/unfirewalled high-risk network ports on a target host in parallel."""
    findings: List[Dict] = []
    targets = ports if ports is not None else RISKY_PORTS

    with ThreadPoolExecutor(max_workers=min(16, max(1, len(targets)))) as pool:
        futures = [
            pool.submit(_probe_port, host, port, service, advice, timeout)
            for port, service, advice in targets
        ]
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                findings.append(res)

    return findings
