import json
import re
from pathlib import Path
from typing import Dict, List


def apply_dependency_fixes(report: Dict[str, List[Dict]], root_path: Path) -> List[str]:
    """Automatically bump vulnerable pinned dependencies when OSV provides a fixed_version."""
    applied: List[str] = []
    fixes_by_file: Dict[Path, Dict[str, str]] = {}

    for entry in report.get("dependencies", []):
        file_p = Path(entry["file"])
        pkg = entry["package"]
        fixed_versions = [
            v["fixed_version"] for v in entry.get("vulns", []) if v.get("fixed_version")
        ]
        if fixed_versions:
            # Pick the highest version string available as target fix
            target_ver = sorted(fixed_versions)[-1]
            fixes_by_file.setdefault(file_p, {})[pkg] = target_ver

    for file_p, pkg_fixes in fixes_by_file.items():
        if not file_p.exists():
            continue
        if file_p.name == "requirements.txt":
            lines = file_p.read_text(encoding="utf-8").splitlines()
            new_lines: List[str] = []
            changed = False
            for line in lines:
                updated = line
                for pkg, fix_ver in pkg_fixes.items():
                    pat = re.compile(rf"^(\s*{re.escape(pkg)}\s*==\s*)([^\s#]+)(.*)$")
                    m = pat.match(line)
                    if m:
                        updated = f"{m.group(1)}{fix_ver}{m.group(3)}"
                        applied.append(f"{file_p}: {pkg} -> =={fix_ver}")
                        changed = True
                        break
                new_lines.append(updated)
            if changed:
                file_p.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

        elif file_p.name == "package-lock.json":
            pkg_json = file_p.parent / "package.json"
            if pkg_json.exists():
                try:
                    data = json.loads(pkg_json.read_text(encoding="utf-8"))
                except Exception:
                    continue
                changed = False
                for section in ("dependencies", "devDependencies"):
                    deps = data.get(section, {})
                    if not isinstance(deps, dict):
                        continue
                    for pkg, fix_ver in pkg_fixes.items():
                        if pkg in deps:
                            deps[pkg] = f"^{fix_ver}"
                            applied.append(f"{pkg_json}: {pkg} -> ^{fix_ver}")
                            changed = True
                if changed:
                    pkg_json.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    return applied
