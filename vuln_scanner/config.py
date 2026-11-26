import ast
from pathlib import Path
from typing import Any, Dict, List


def load_config(root_path: Path) -> Dict[str, Any]:
    """Load optional vuln-scanner.toml configuration from root_path."""
    base = root_path.parent if root_path.is_file() else root_path
    cfg_path = base / "vuln-scanner.toml"
    if not cfg_path.exists():
        return {}

    config: Dict[str, Any] = {}
    custom_rules: List[Dict[str, Any]] = []
    current_rule: Dict[str, Any] = {}
    in_custom_rule = False

    try:
        lines = cfg_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return {}

    def _parse_val(raw_val: str) -> Any:
        val = raw_val.strip()
        if val.lower() == "true":
            return True
        if val.lower() == "false":
            return False
        try:
            return ast.literal_eval(val)
        except Exception:
            return val.strip("'\"")

    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "[[custom_rules]]":
            if current_rule:
                custom_rules.append(current_rule)
                current_rule = {}
            in_custom_rule = True
            continue
        if line.startswith("["):
            if current_rule:
                custom_rules.append(current_rule)
                current_rule = {}
            in_custom_rule = False
            continue
        if "=" not in line:
            continue

        key, val = line.split("=", 1)
        key = key.strip()
        parsed = _parse_val(val)
        if in_custom_rule:
            current_rule[key] = parsed
        else:
            config[key] = parsed

    if current_rule:
        custom_rules.append(current_rule)
    if custom_rules:
        existing = config.get("custom_rules", [])
        if isinstance(existing, list):
            config["custom_rules"] = existing + custom_rules
        else:
            config["custom_rules"] = custom_rules

    return config
