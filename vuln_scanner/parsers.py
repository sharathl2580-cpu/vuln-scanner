import json
import os
import re
from pathlib import Path
from typing import List, Tuple
from xml.etree import ElementTree as ET

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
}

ECOSYSTEMS = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "requirements.txt": "PyPI",
    "poetry.lock": "PyPI",
    "pom.xml": "Maven",
    "Gemfile.lock": "RubyGems",
    "go.mod": "Go",
    "Cargo.lock": "crates.io",
    "composer.lock": "Packagist",
}


def find_lockfiles(root: Path) -> List[Path]:
    """Recursively find supported lock/manifest files under root."""
    lockfiles: List[Path] = []
    if root.is_file():
        return [root] if root.name in ECOSYSTEMS else []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in ECOSYSTEMS:
                lockfiles.append(Path(dirpath) / name)
    return lockfiles


def parse_npm_lock(file_path: Path) -> List[Tuple[str, str]]:
    """Parse package-lock.json (v1, v2, v3) for (package, version) pairs."""
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return []

    deps: List[Tuple[str, str]] = []
    seen = set()

    if isinstance(data.get("dependencies"), dict):
        for name, info in data["dependencies"].items():
            if isinstance(info, dict) and info.get("version"):
                pair = (name, info["version"])
                if pair not in seen:
                    seen.add(pair)
                    deps.append(pair)

    if isinstance(data.get("packages"), dict):
        for pkg_path, info in data["packages"].items():
            if not pkg_path or not isinstance(info, dict):
                continue
            version = info.get("version")
            if not version:
                continue
            name = pkg_path.split("node_modules/")[-1]
            if name and (name, version) not in seen:
                seen.add((name, version))
                deps.append((name, version))

    return deps


def parse_yarn_lock(file_path: Path) -> List[Tuple[str, str]]:
    """Parse yarn.lock (v1 and Berry) for (package, version) pairs."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    deps: List[Tuple[str, str]] = []
    seen = set()
    current_names: List[str] = []

    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1].strip().strip('"')
            current_names = []
            for spec in header.split(","):
                spec = spec.strip().strip('"')
                if not spec:
                    continue
                # Scoped packages start with @: e.g. @babel/core@^7.0.0 -> @babel/core
                if spec.startswith("@"):
                    idx = spec.find("@", 1)
                    name = spec[:idx] if idx != -1 else spec
                else:
                    idx = spec.find("@")
                    name = spec[:idx] if idx != -1 else spec
                if name:
                    current_names.append(name)
        elif current_names and line.strip().startswith("version"):
            match = re.match(r"""^\s*version[:\s]+['"]?([^'"\s]+)['"]?""", line)
            if match:
                ver = match.group(1)
                for name in current_names:
                    if (name, ver) not in seen:
                        seen.add((name, ver))
                        deps.append((name, ver))
                current_names = []

    return deps


def parse_requirements(file_path: Path) -> List[Tuple[str, str]]:
    deps: List[Tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    for line in lines:
        line = line.strip()
        if not line or line.startswith(("#", "-r", "--")):
            continue
        line = line.split("#", 1)[0].strip()
        for op in ("==", ">=", "<=", ">", "<", "~="):
            if op in line:
                pkg, ver = line.split(op, 1)
                deps.append((pkg.strip(), ver.strip()))
                break
        else:
            deps.append((line, ""))
    return deps


def _parse_toml_package_blocks(file_path: Path) -> List[Tuple[str, str]]:
    """Parse [[package]] blocks used by both Cargo.lock and poetry.lock."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    deps: List[Tuple[str, str]] = []
    in_pkg = False
    name = ""
    version = ""

    def _flush() -> None:
        nonlocal name, version
        if name and version:
            deps.append((name, version))
        name = ""
        version = ""

    for line in lines:
        stripped = line.strip()
        if stripped == "[[package]]":
            _flush()
            in_pkg = True
            continue
        if stripped.startswith("[") and stripped != "[[package]]":
            _flush()
            in_pkg = False
            continue
        if in_pkg:
            m_name = re.match(r'^name\s*=\s*"([^"]+)"', stripped)
            if m_name:
                name = m_name.group(1)
            m_ver = re.match(r'^version\s*=\s*"([^"]+)"', stripped)
            if m_ver:
                version = m_ver.group(1)

    _flush()
    return deps


def parse_poetry_lock(file_path: Path) -> List[Tuple[str, str]]:
    return _parse_toml_package_blocks(file_path)


def parse_cargo_lock(file_path: Path) -> List[Tuple[str, str]]:
    return _parse_toml_package_blocks(file_path)


def parse_maven_pom(file_path: Path) -> List[Tuple[str, str]]:
    deps: List[Tuple[str, str]] = []
    try:
        tree = ET.parse(file_path)  # nosec SAST012
        root = tree.getroot()
    except Exception:
        return []

    for dep in root.iterfind(".//{*}dependency"):
        group_id = dep.find("{*}groupId")
        artifact_id = dep.find("{*}artifactId")
        version = dep.find("{*}version")
        if group_id is not None and artifact_id is not None and group_id.text and artifact_id.text:
            name = f"{group_id.text.strip()}:{artifact_id.text.strip()}"
            ver = version.text.strip() if version is not None and version.text else ""
            deps.append((name, ver))
    return deps


def parse_gemfile_lock(file_path: Path) -> List[Tuple[str, str]]:
    deps: List[Tuple[str, str]] = []
    in_specs = False
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    for line in lines:
        if line.strip() == "GEM":
            continue
        if line.startswith("  specs:"):
            in_specs = True
            continue
        if in_specs:
            if line.startswith("    "):
                parts = line.strip().split()
                if len(parts) >= 2:
                    name = parts[0]
                    ver = parts[1].strip("()")
                    deps.append((name, ver))
            else:
                in_specs = False
    return deps


def parse_go_mod(file_path: Path) -> List[Tuple[str, str]]:
    """Parse go.mod require directives for (module, version) pairs."""
    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []

    deps: List[Tuple[str, str]] = []
    in_require = False

    for line in lines:
        stripped = line.split("//", 1)[0].strip()
        if not stripped:
            continue
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require:
            if stripped == ")":
                in_require = False
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                deps.append((parts[0], parts[1]))
        elif stripped.startswith("require "):
            parts = stripped[len("require "):].strip().split()
            if len(parts) >= 2:
                deps.append((parts[0], parts[1]))

    return deps


def parse_composer_lock(file_path: Path) -> List[Tuple[str, str]]:
    """Parse PHP composer.lock for (package, version) pairs."""
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return []

    deps: List[Tuple[str, str]] = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if name and version:
                deps.append((name, str(version).lstrip("v")))
    return deps


def parse_lockfile(file_path: Path) -> Tuple[str, List[Tuple[str, str]]]:
    """Return (ecosystem, [(package, version), ...]) for a supported lockfile."""
    ecosystem = ECOSYSTEMS.get(file_path.name, "unknown")
    parsers = {
        "package-lock.json": parse_npm_lock,
        "yarn.lock": parse_yarn_lock,
        "requirements.txt": parse_requirements,
        "poetry.lock": parse_poetry_lock,
        "pom.xml": parse_maven_pom,
        "Gemfile.lock": parse_gemfile_lock,
        "go.mod": parse_go_mod,
        "Cargo.lock": parse_cargo_lock,
        "composer.lock": parse_composer_lock,
    }
    parser = parsers.get(file_path.name)
    if parser is None:
        return ecosystem, []
    return ecosystem, parser(file_path)
