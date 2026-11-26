import ast
from pathlib import Path
from typing import Dict, List, Set, Tuple

from vuln_scanner.security_checks import (
    _get_call_name,
    _is_ignored_by_vulnignore,
    _is_line_suppressed,
    iter_scannable_files,
    load_vulnignore,
)

TAINT_SOURCES = ("request.", "sys.argv", "input", "os.environ")
DANGEROUS_SINKS = {
    "eval",
    "exec",
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "cursor.execute",
    "requests.get",
    "requests.post",
    "send_file",
}


def _expr_has_source(expr: ast.AST, tainted: Set[str]) -> bool:
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Name) and sub.id in tainted:
            return True
        if isinstance(sub, ast.Attribute):
            full = _get_call_name(sub)
            if any(full.startswith(src) for src in TAINT_SOURCES):
                return True
        if isinstance(sub, ast.Call):
            cname = _get_call_name(sub.func)
            if cname == "input" or any(cname.startswith(src) for src in TAINT_SOURCES):
                return True
    return False


def _find_vulnerable_sink_params(tree: ast.Module) -> Dict[str, Set[int]]:
    """Return {func_name: set_of_param_indices} where param flows to a dangerous sink."""
    summaries: Dict[str, Set[int]] = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        param_names = [arg.arg for arg in node.args.args]
        if not param_names:
            continue
        tainted_params: Dict[str, int] = {name: idx for idx, name in enumerate(param_names)}
        var_to_param: Dict[str, int] = dict(tainted_params)

        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Assign):
                for sub in ast.walk(stmt.value):
                    if isinstance(sub, ast.Name) and sub.id in var_to_param:
                        p_idx = var_to_param[sub.id]
                        for tgt in stmt.targets:
                            if isinstance(tgt, ast.Name):
                                var_to_param[tgt.id] = p_idx
            elif isinstance(stmt, ast.Call):
                sink = _get_call_name(stmt.func)
                if sink in DANGEROUS_SINKS:
                    for arg in stmt.args:
                        for sub in ast.walk(arg):
                            if isinstance(sub, ast.Name) and sub.id in var_to_param:
                                summaries.setdefault(node.name, set()).add(var_to_param[sub.id])
    return summaries


def scan_cross_file_taint(root_path: Path) -> List[Dict]:
    """Build a cross-file Python call graph to detect taint flowing into helper sinks across files."""
    if root_path.is_file():
        return []

    ignore_rules = load_vulnignore(root_path)
    parsed_files: List[Tuple[Path, str, ast.Module]] = []

    for py_file in iter_scannable_files(root_path, {".py"}, ignore_rules):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content, filename=str(py_file))
            parsed_files.append((py_file, content, tree))
        except Exception:
            continue

    # Map module stem -> {func_name: {param_indices}}
    module_sinks: Dict[str, Dict[str, Set[int]]] = {}
    for py_file, _, tree in parsed_files:
        summaries = _find_vulnerable_sink_params(tree)
        if summaries:
            module_sinks[py_file.stem] = summaries

    if not module_sinks:
        return []

    findings: List[Dict] = []

    for py_file, content, tree in parsed_files:
        lines = content.splitlines()
        # Collect imported sink helpers in this file: local_name -> (module, orig_func, param_indices)
        imported_sinks: Dict[str, Tuple[str, str, Set[int]]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                mod_stem = node.module.split(".")[-1]
                if mod_stem in module_sinks and mod_stem != py_file.stem:
                    for alias in node.names:
                        if alias.name in module_sinks[mod_stem]:
                            local = alias.asname or alias.name
                            imported_sinks[local] = (mod_stem, alias.name, module_sinks[mod_stem][alias.name])
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    mod_stem = alias.name.split(".")[-1]
                    if mod_stem in module_sinks and mod_stem != py_file.stem:
                        local_mod = alias.asname or mod_stem
                        for fname, pidxs in module_sinks[mod_stem].items():
                            imported_sinks[f"{local_mod}.{fname}"] = (mod_stem, fname, pidxs)

        if not imported_sinks:
            continue

        def _check_scope(stmts: List[ast.stmt]) -> None:
            tainted: Set[str] = set()
            for stmt in stmts:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _check_scope(stmt.body)
                    continue
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Assign):
                        if _expr_has_source(sub.value, tainted):
                            for tgt in sub.targets:
                                if isinstance(tgt, ast.Name):
                                    tainted.add(tgt.id)
                    elif isinstance(sub, ast.Call):
                        callee = _get_call_name(sub.func)
                        if callee in imported_sinks:
                            mod_stem, orig_fn, param_idxs = imported_sinks[callee]
                            for idx in param_idxs:
                                if idx < len(sub.args) and _expr_has_source(sub.args[idx], tainted):
                                    line_text = lines[sub.lineno - 1] if 1 <= sub.lineno <= len(lines) else ""
                                    if _is_line_suppressed(line_text, "TAINT003") or _is_ignored_by_vulnignore(
                                        py_file, root_path, "TAINT003", ignore_rules
                                    ):
                                        continue
                                    findings.append({
                                        "category": "sast",
                                        "rule_id": "TAINT003",
                                        "severity": "CRITICAL",
                                        "file": str(py_file),
                                        "line": sub.lineno,
                                        "message": f"Cross-file taint: user input flows into '{mod_stem}.{orig_fn}()' sink",
                                        "match": line_text.strip()[:120],
                                        "remediation": "Sanitize/validate untrusted input before passing it across modules to a sink.",
                                    })

        _check_scope(tree.body)

    return findings
