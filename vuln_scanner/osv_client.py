import hashlib
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours
BATCH_SIZE = 1000


class OSVCache:
    """Simple file-based cache for OSV query and vulnerability detail responses."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    ) -> None:
        env_dir = os.environ.get("VULN_SCANNER_CACHE_DIR")
        if cache_dir is not None:
            self.cache_dir = cache_dir
        elif env_dir:
            self.cache_dir = Path(env_dir)
        else:
            self.cache_dir = Path.home() / ".cache" / "vuln-scanner"
        self.ttl_seconds = ttl_seconds

    def _key_path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def get(self, key: str) -> Optional[Dict]:
        path = self._key_path(key)
        if not path.exists():
            return None
        try:
            age = time.time() - path.stat().st_mtime
            if age > self.ttl_seconds:
                return None
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return None

    def set(self, key: str, value: Dict) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            path = self._key_path(key)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(value, fh)
        except Exception:
            pass


def extract_severity(vuln: Dict) -> str:
    """Extract normalized severity (CRITICAL, HIGH, MEDIUM, LOW) from an OSV record."""
    db_sev = vuln.get("database_specific", {}).get("severity")
    if isinstance(db_sev, str) and db_sev.strip():
        normalized = db_sev.strip().upper()
        if normalized == "MODERATE":
            return "MEDIUM"
        if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return normalized

    for entry in vuln.get("severity", []):
        score = entry.get("score")
        if isinstance(score, (int, float)):
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"
        if isinstance(score, str):
            try:
                num = float(score)
                if num >= 9.0:
                    return "CRITICAL"
                if num >= 7.0:
                    return "HIGH"
                if num >= 4.0:
                    return "MEDIUM"
                return "LOW"
            except ValueError:
                # CVSS vector string without precomputed numeric score
                if score.startswith("CVSS:"):
                    if "/S:C/" in score and "/C:H/I:H/A:H" in score:
                        return "CRITICAL"
                    return "HIGH"

    return "HIGH"


def extract_fixed_version(vuln: Dict, package: str, ecosystem: str) -> Optional[str]:
    """Return the first fixed version for the given package/ecosystem, if present."""
    for affected in vuln.get("affected", []):
        pkg_info = affected.get("package", {})
        if pkg_info.get("name") == package and pkg_info.get("ecosystem") == ecosystem:
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return str(event["fixed"])
    # Fallback: check any affected entry if exact name didn't match (e.g. case differences)
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return str(event["fixed"])
    return None


def _fetch_vuln_details(
    vuln_id: str,
    cache: Optional[OSVCache] = None,
) -> Dict:
    cache_key = f"vuln:{vuln_id}"
    if cache is not None:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

    try:
        resp = requests.get(OSV_VULN_URL.format(vuln_id=vuln_id), timeout=10)  # nosec SAST013
        if resp.status_code == 200:
            data = resp.json()
            if cache is not None:
                cache.set(cache_key, data)
            return data
    except Exception:
        pass
    return {"id": vuln_id}


def query_osv_batch(
    packages: List[Tuple[str, str, str]],
    use_cache: bool = True,
    cache: Optional[OSVCache] = None,
) -> Dict[Tuple[str, str, str], List[Dict]]:
    """Query OSV in batches for (package, version, ecosystem) tuples.

    Returns a mapping from (package, version, ecosystem) -> list of full vuln dicts.
    """
    active_cache = cache if cache is not None else (OSVCache() if use_cache else None)
    results: Dict[Tuple[str, str, str], List[Dict]] = {}
    uncached: List[Tuple[str, str, str]] = []

    for pkg_tuple in dict.fromkeys(packages):
        pkg, ver, eco = pkg_tuple
        if not ver:
            continue
        cache_key = f"pkg:{eco}:{pkg}:{ver}"
        if active_cache is not None:
            cached = active_cache.get(cache_key)
            if cached is not None:
                vulns = cached.get("vulns", [])
                if vulns:
                    results[pkg_tuple] = vulns
                continue
        uncached.append(pkg_tuple)

    for i in range(0, len(uncached), BATCH_SIZE):
        chunk = uncached[i : i + BATCH_SIZE]
        queries = [
            {"package": {"name": pkg, "ecosystem": eco}, "version": ver}
            for pkg, ver, eco in chunk
        ]
        try:
            resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=15)  # nosec SAST013
            if resp.status_code != 200:
                continue
            batch_data = resp.json().get("results", [])
        except Exception:
            continue

        for pkg_tuple, item in zip(chunk, batch_data):
            raw_vulns = item.get("vulns", []) if isinstance(item, dict) else []
            full_vulns: List[Dict] = []
            for stub in raw_vulns:
                vuln_id = stub.get("id")
                if not vuln_id:
                    continue
                # If stub already has summary/affected (e.g., in tests), keep it; else fetch
                if "summary" in stub or "affected" in stub:
                    full_vulns.append(stub)
                else:
                    full_vulns.append(_fetch_vuln_details(vuln_id, active_cache))

            if active_cache is not None:
                pkg, ver, eco = pkg_tuple
                active_cache.set(f"pkg:{eco}:{pkg}:{ver}", {"vulns": full_vulns})

            if full_vulns:
                results[pkg_tuple] = full_vulns

    return results
