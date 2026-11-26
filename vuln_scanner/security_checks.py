import ast
import fnmatch
import json
import math
import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from vuln_scanner.parsers import SKIP_DIRS

CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".rb",
    ".java",
    ".go",
    ".php",
    ".sh",
}

TEXT_EXTENSIONS = CODE_EXTENSIONS | {
    ".env",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".txt",
    ".xml",
    ".properties",
}

MAX_FILE_BYTES = 1024 * 1024  # 1 MB safety cap per file

PLACEHOLDER_VALUES = {
    "changeme",
    "change_me",
    "example",
    "your_api_key",
    "your-api-key",
    "your_password",
    "your-password",
    "placeholder",
    "dummy",
    "test",
    "testing",
    "password",
    "secret",
    "none",
    "null",
    "todo",
}

REMEDIATIONS = {
    "SEC000": "Remove .env from version control, add it to .gitignore, and rotate exposed credentials.",
    "SEC001": "Revoke the AWS access key in IAM and load credentials via IAM roles or environment variables.",
    "SEC002": "Remove the private key from source control, rotate it, and store it in a secrets manager.",
    "SEC003": "Revoke the GitHub token in developer settings and use short-lived OAuth/GitHub App tokens.",
    "SEC004": "Revoke the Slack token and inject it via environment variables at runtime.",
    "SEC005": "Restrict or rotate the Google API key and avoid embedding it in source code.",
    "SEC006": "Revoke the API secret key and load it from an environment variable or vault.",
    "SEC007": "Replace hardcoded secrets with environment variables or a secrets manager.",
    "SEC008": "High-entropy secret/token detected; move it to environment variables or a secrets manager.",
    "SAST001": "Avoid eval()/exec(); use ast.literal_eval(), JSON parsing, or explicit dispatch tables.",
    "SAST002": "Pass an argument list to subprocess.run(..., shell=False) instead of invoking a shell.",
    "SAST003": "Use json or yaml.safe_load() / yaml.load(..., Loader=yaml.SafeLoader) instead of pickle/unsafe yaml.",
    "SAST004": "Enable TLS certificate verification (remove verify=False / rejectUnauthorized: false).",
    "SAST005": "Use SHA-256 or stronger (or bcrypt/argon2 for passwords) instead of MD5/SHA1.",
    "SAST006": "Use parameterized queries / prepared statements instead of string interpolation.",
    "SAST007": "Use https:// instead of plaintext http:// for non-local endpoints.",
    "SAST008": "Sanitize/escape untrusted HTML or use safe text rendering (textContent) to prevent XSS.",
    "SAST009": "Use secrets (Python) or crypto.randomBytes (Node.js) instead of random/Math.random for security values.",
    "SAST010": "Disable debug mode in production and bind to localhost or a specific interface instead of 0.0.0.0.",
    "SAST011": "Use tempfile.mkstemp() or NamedTemporaryFile() instead of insecure tempfile.mktemp().",
    "SAST012": "Use defusedxml instead of xml.etree.ElementTree/lxml to prevent XXE attacks.",
    "SAST013": "Validate and allowlist URLs/domains before making outbound HTTP requests to prevent SSRF.",
    "SAST014": "Sanitize file paths with os.path.basename / secure_filename and verify they stay inside the base directory.",
    "SAST015": "Use AES-GCM or ChaCha20-Poly1305 instead of ECB mode, DES, or RC4.",
    "SAST016": "Use execFile/spawn with an argument array instead of child_process.exec with interpolated strings.",
    "AUTH001": "Verify JWT signatures with a strong secret/public key and explicit allowed algorithms.",
    "AUTH002": "Restrict CORS origins to explicit trusted domains when credentials are enabled.",
    "TAINT001": "Validate/sanitize untrusted user input before passing it to sensitive sinks.",
    "HYG001": "Pin exact dependency versions with == (or manage via a lockfile).",
    "HYG002": "Generate and commit a lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml).",
    "HYG003": "Replace wildcard/'latest' version ranges with pinned or bounded semver ranges.",
}

# (rule_id, severity, description, compiled_regex)
SECRET_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    ("SEC001", "CRITICAL", "AWS Access Key ID detected", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    (
        "SEC002",
        "CRITICAL",
        "Private key block detected",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    ("SEC003", "CRITICAL", "GitHub personal/OAuth token detected", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b")),
    ("SEC004", "HIGH", "Slack token detected", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("SEC005", "HIGH", "Google API key detected", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("SEC006", "HIGH", "Generic API secret key (sk-*) detected", re.compile(r"\b(sk-(?:proj-|live-|test-)?[A-Za-z0-9]{20,})\b")),
    (
        "SEC007",
        "MEDIUM",
        "Hardcoded password or secret assignment detected",
        re.compile(
            r"""(?i)\b(?:password|passwd|pwd|api_key|apikey|secret_key|access_token|auth_token)\b\s*[:=]\s*['"]([^'"\n]{6,})['"]"""
        ),
    ),
]

# Regex SAST patterns for non-Python files
SAST_PATTERNS: List[Tuple[str, str, str, re.Pattern, Optional[set]]] = [
    (
        "SAST001",
        "HIGH",
        "Use of eval() or exec() can lead to arbitrary code execution",
        re.compile(r"\b(?:eval|exec)\s*\("),
        {".js", ".jsx", ".ts", ".tsx", ".rb", ".php"},
    ),
    (
        "SAST004",
        "MEDIUM",
        "TLS/SSL certificate verification disabled",
        re.compile(r"(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)"),
        None,
    ),
    (
        "SAST005",
        "MEDIUM",
        "Weak cryptographic hash function (MD5 or SHA1)",
        re.compile(r"""crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]"""),
        {".js", ".jsx", ".ts", ".tsx"},
    ),
    (
        "SAST006",
        "HIGH",
        "Potential SQL injection via formatted or concatenated query string",
        re.compile(
            r"""(?i)(?:\$\{[^}]+\}|%s|\+\s*\w+)\s*.*?\b(?:SELECT|INSERT|UPDATE|DELETE)\b|\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*?(?:\$\{[^}]+\}|%s|\+\s*\w+)"""
        ),
        {".js", ".jsx", ".ts", ".tsx", ".rb", ".java", ".php"},
    ),
    (
        "SAST007",
        "LOW",
        "Insecure plaintext HTTP URL detected (prefer HTTPS)",
        re.compile(r"http://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|www\.w3\.org\b|schemas\.)[A-Za-z0-9.-]+"),
        CODE_EXTENSIONS - {".py"},
    ),
    (
        "SAST008",
        "HIGH",
        "Potential XSS / unsafe DOM HTML injection",
        re.compile(r"(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)"),
        {".js", ".jsx", ".ts", ".tsx", ".php"},
    ),
    (
        "SAST009",
        "MEDIUM",
        "Insecure PRNG Math.random() used (not cryptographically secure)",
        re.compile(r"\bMath\.random\s*\("),
        {".js", ".jsx", ".ts", ".tsx"},
    ),
    (
        "SAST016",
        "HIGH",
        "Potential command injection via child_process.exec()",
        re.compile(r"\b(?:child_process\.)?exec(?:Sync)?\s*\("),
        {".js", ".jsx", ".ts", ".tsx"},
    ),
    (
        "AUTH002",
        "HIGH",
        "Permissive CORS wildcard combined with credentials",
        re.compile(r"""Access-Control-Allow-Origin['":\s]+\*"""),
        CODE_EXTENSIONS - {".py"},
    ),
]

ENTROPY_ASSIGN_RE = re.compile(
    r"""(?i)\b(?:token|secret|key|auth|bearer|credential|jwt|signing)[A-Za-z0-9_]*\b\s*[:=]\s*['"]([^'"\s]{20,})['"]"""
)

SQL_KEYWORD_RE = re.compile(
    r"\b(?:SELECT\s+.+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b",
    re.IGNORECASE | re.DOTALL,
)
HTTP_URL_RE = re.compile(
    r"http://(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|www\.w3\.org\b|schemas\.)[A-Za-z0-9.-]+"
)
NOSEC_RE = re.compile(r"(?:#|//)\s*nosec(?:\s+([A-Z0-9_,\s]+))?", re.IGNORECASE)


def load_vulnignore(root: Path) -> List[Tuple[Optional[str], str]]:
    """Load .vulnignore entries as (optional_rule_id, glob_pattern) tuples."""
    ignore_file = (root.parent if root.is_file() else root) / ".vulnignore"
    if not ignore_file.exists():
        return []
    entries: List[Tuple[Optional[str], str]] = []
    try:
        for raw in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                maybe_rule, pattern = line.split(":", 1)
                if re.fullmatch(r"[A-Z]{2,6}\d{3}", maybe_rule.strip()):
                    entries.append((maybe_rule.strip(), pattern.strip()))
                    continue
            entries.append((None, line))
    except OSError:
        pass
    return entries


def _is_ignored_by_vulnignore(
    file_path: Path,
    root_path: Path,
    rule_id: Optional[str],
    ignore_rules: List[Tuple[Optional[str], str]],
) -> bool:
    if not ignore_rules:
        return False
    base = root_path.parent if root_path.is_file() else root_path
    try:
        rel = str(file_path.relative_to(base))
    except ValueError:
        rel = str(file_path)

    for ig_rule, pattern in ignore_rules:
        if ig_rule is not None and (rule_id is None or ig_rule != rule_id):
            continue
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(file_path.name, pattern):
            return True
    return False


def _line_nosec_rules(line: str) -> Optional[Set[str]]:
    """Return None if no nosec comment; empty set if all rules suppressed; or set of rule IDs."""
    m = NOSEC_RE.search(line)
    if not m:
        return None
    spec = (m.group(1) or "").strip()
    if not spec:
        return set()  # suppress all rules on this line
    return {tok.strip().upper() for tok in spec.split(",") if tok.strip()}


def _is_line_suppressed(line: str, rule_id: str) -> bool:
    suppressed = _line_nosec_rules(line)
    if suppressed is None:
        return False
    return len(suppressed) == 0 or rule_id.upper() in suppressed


def iter_scannable_files(
    root: Path,
    extensions: Optional[set] = None,
    ignore_rules: Optional[List[Tuple[Optional[str], str]]] = None,
) -> Iterable[Path]:
    """Yield regular files under root, skipping vendor dirs and .vulnignore paths."""
    rules = ignore_rules or []
    if root.is_file():
        if not _is_ignored_by_vulnignore(root, root, None, rules):
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            if _is_ignored_by_vulnignore(path, root, None, rules):
                continue
            if extensions is not None:
                if path.suffix.lower() not in extensions and not filename.startswith(".env"):
                    continue
            try:
                if path.is_file() and path.stat().st_size <= MAX_FILE_BYTES:
                    yield path
            except OSError:
                continue


def redact_secret(value: str) -> str:
    """Mask most of a secret value so findings never echo full credentials."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in PLACEHOLDER_VALUES:
        return True
    if normalized.startswith(("<", "${", "{{", "your_", "your-")):
        return True
    if set(normalized) <= {"*", "x", "."}:
        return True
    return False


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def scan_secrets(root_path: Path) -> List[Dict]:
    """Scan text and .env files for leaked credentials and hardcoded secrets."""
    findings: List[Dict] = []
    ignore_rules = load_vulnignore(root_path)

    for file_path in iter_scannable_files(root_path, TEXT_EXTENSIONS, ignore_rules):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        lines = content.splitlines()

        if file_path.name == ".env" or file_path.name.startswith(".env."):
            if file_path.name not in {".env.example", ".env.sample", ".env.template"}:
                for line_no, line in enumerate(lines, start=1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or "=" not in stripped:
                        continue
                    if _is_line_suppressed(line, "SEC000") or _is_ignored_by_vulnignore(
                        file_path, root_path, "SEC000", ignore_rules
                    ):
                        continue
                    key, val = stripped.split("=", 1)
                    val_clean = val.strip().strip("'\"")
                    if val_clean and not _is_placeholder(val_clean):
                        findings.append({
                            "category": "secret",
                            "rule_id": "SEC000",
                            "severity": "HIGH",
                            "file": str(file_path),
                            "line": line_no,
                            "message": f"Environment file contains non-empty value for {key.strip()}",
                            "match": redact_secret(val_clean),
                            "remediation": REMEDIATIONS["SEC000"],
                        })

        for line_no, line in enumerate(lines, start=1):
            matched_known = False
            for rule_id, severity, description, pattern in SECRET_PATTERNS:
                if _is_line_suppressed(line, rule_id) or _is_ignored_by_vulnignore(
                    file_path, root_path, rule_id, ignore_rules
                ):
                    continue
                match = pattern.search(line)
                if not match:
                    continue
                matched_text = match.group(1) if match.lastindex else match.group(0)
                if rule_id == "SEC007" and _is_placeholder(matched_text):
                    continue
                matched_known = True
                findings.append({
                    "category": "secret",
                    "rule_id": rule_id,
                    "severity": severity,
                    "file": str(file_path),
                    "line": line_no,
                    "message": description,
                    "match": redact_secret(matched_text),
                    "remediation": REMEDIATIONS[rule_id],
                })

            if not matched_known and not (
                _is_line_suppressed(line, "SEC008")
                or _is_ignored_by_vulnignore(file_path, root_path, "SEC008", ignore_rules)
            ):
                ent_match = ENTROPY_ASSIGN_RE.search(line)
                if ent_match:
                    candidate = ent_match.group(1)
                    if not _is_placeholder(candidate) and _shannon_entropy(candidate) >= 4.0:
                        findings.append({
                            "category": "secret",
                            "rule_id": "SEC008",
                            "severity": "HIGH",
                            "file": str(file_path),
                            "line": line_no,
                            "message": "High-entropy secret or token assignment detected",
                            "match": redact_secret(candidate),
                            "remediation": REMEDIATIONS["SEC008"],
                        })

    return findings


def _get_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _is_true_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _scan_python_ast(
    file_path: Path,
    content: str,
    lines: List[str],
    root_path: Path,
    ignore_rules: List[Tuple[Optional[str], str]],
) -> List[Dict]:
    """Run AST-based static security analysis on a Python file."""
    try:
        tree = ast.parse(content, filename=str(file_path))
    except SyntaxError:
        return []

    findings: List[Dict] = []

    def _add(rule_id: str, severity: str, message: str, lineno: int) -> None:
        line_text = lines[lineno - 1] if 1 <= lineno <= len(lines) else ""
        if _is_line_suppressed(line_text, rule_id) or _is_ignored_by_vulnignore(
            file_path, root_path, rule_id, ignore_rules
        ):
            return
        findings.append({
            "category": "sast",
            "rule_id": rule_id,
            "severity": severity,
            "file": str(file_path),
            "line": lineno,
            "message": message,
            "match": line_text.strip()[:120],
            "remediation": REMEDIATIONS[rule_id],
        })

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _get_call_name(node.func)

            if name in {"eval", "exec"}:
                _add("SAST001", "HIGH", "Use of eval() or exec() can lead to arbitrary code execution", node.lineno)

            elif name == "os.system" or (
                name.startswith("subprocess.")
                and any(kw.arg == "shell" and _is_true_const(kw.value) for kw in node.keywords)
            ):
                _add("SAST002", "HIGH", "Shell command execution with shell=True or os.system()", node.lineno)

            elif name in {"pickle.load", "pickle.loads"}:
                _add("SAST003", "HIGH", "Unsafe deserialization via pickle.load()/loads()", node.lineno)

            elif name == "yaml.load":
                loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
                loader_name = _get_call_name(loader_kw.value) if loader_kw else ""
                if "SafeLoader" not in loader_name and "CSafeLoader" not in loader_name:
                    _add("SAST003", "HIGH", "Unsafe yaml.load() without SafeLoader", node.lineno)

            elif name.startswith("requests.") and any(
                kw.arg == "verify" and _is_false_const(kw.value) for kw in node.keywords
            ):
                _add("SAST004", "MEDIUM", "TLS/SSL certificate verification disabled", node.lineno)

            elif name == "ssl._create_unverified_context":
                _add("SAST004", "MEDIUM", "TLS/SSL certificate verification disabled", node.lineno)

            elif name in {"hashlib.md5", "hashlib.sha1"} or (
                name == "hashlib.new"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and str(node.args[0].value).lower() in {"md5", "sha1"}
            ):
                _add("SAST005", "MEDIUM", "Weak cryptographic hash function (MD5 or SHA1)", node.lineno)

            elif name.endswith(".format") and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str):
                    if SQL_KEYWORD_RE.search(node.func.value.value):
                        _add("SAST006", "HIGH", "Potential SQL injection via formatted query string", node.lineno)

            elif name in {"Markup", "flask.Markup", "markupsafe.Markup"}:
                _add("SAST008", "HIGH", "Potential XSS via unescaped HTML Markup()", node.lineno)

            elif name in {"random.random", "random.randint", "random.choice", "random.randrange"}:
                _add("SAST009", "MEDIUM", "Insecure PRNG random.* used (prefer secrets module for security)", node.lineno)

            elif name == "app.run" and any(kw.arg == "debug" and _is_true_const(kw.value) for kw in node.keywords):
                _add("SAST010", "HIGH", "Flask debug=True enabled in app.run()", node.lineno)

            elif name == "tempfile.mktemp":
                _add("SAST011", "HIGH", "Insecure tempfile.mktemp() (race condition)", node.lineno)

            elif name in {"ET.parse", "ET.fromstring", "ElementTree.parse", "ElementTree.fromstring", "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring", "lxml.etree.fromstring", "lxml.etree.parse"}:
                _add("SAST012", "HIGH", "Unsafe XML parser without defusedxml (potential XXE)", node.lineno)

            elif name in {"requests.get", "requests.post", "requests.request", "urllib.request.urlopen"}:
                if node.args and not isinstance(node.args[0], ast.Constant):
                    _add("SAST013", "HIGH", "Potential SSRF: outbound request URL is dynamically constructed", node.lineno)

            elif name in {"send_file", "flask.send_file"}:
                if node.args and not isinstance(node.args[0], ast.Constant):
                    _add("SAST014", "HIGH", "Potential Path Traversal: dynamic path passed to send_file()", node.lineno)

            elif name == "jwt.decode":
                for kw in node.keywords:
                    if kw.arg == "verify" and _is_false_const(kw.value):
                        _add("AUTH001", "CRITICAL", "JWT signature verification disabled (verify=False)", node.lineno)
                    elif kw.arg == "options" and isinstance(kw.value, ast.Dict):
                        for k, v in zip(kw.value.keys, kw.value.values):
                            if isinstance(k, ast.Constant) and k.value == "verify_signature" and _is_false_const(v):
                                _add("AUTH001", "CRITICAL", "JWT signature verification disabled in options", node.lineno)

            elif name == "CORS" and any(
                kw.arg == "supports_credentials" and _is_true_const(kw.value) for kw in node.keywords
            ) and any(
                kw.arg == "origins" and isinstance(kw.value, ast.Constant) and kw.value.value == "*"
                for kw in node.keywords
            ):
                _add("AUTH002", "HIGH", "CORS configured with origins='*' and supports_credentials=True", node.lineno)

        elif isinstance(node, ast.Attribute) and node.attr in {"MODE_ECB", "ARC4"}:
            _add("SAST015", "MEDIUM", f"Weak/deprecated cryptographic mode or cipher ({node.attr})", node.lineno)

        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DEBUG" and _is_true_const(node.value):
                    _add("SAST010", "HIGH", "DEBUG = True enabled in configuration", node.lineno)

        elif isinstance(node, ast.JoinedStr):
            static_text = "".join(
                v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
            if SQL_KEYWORD_RE.search(static_text):
                _add("SAST006", "HIGH", "Potential SQL injection via f-string query", node.lineno)

        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                if SQL_KEYWORD_RE.search(node.left.value):
                    _add("SAST006", "HIGH", "Potential SQL injection via string concatenation/% formatting", node.lineno)

        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # Only flag actual http:// URLs, not regexes containing http://
            if node.value.startswith("http://") and HTTP_URL_RE.match(node.value):
                _add("SAST007", "LOW", "Insecure plaintext HTTP URL detected (prefer HTTPS)", node.lineno)

    # Intra-file taint tracking (source -> sink within functions or module scope)
    taint_sources = ("request.", "sys.argv", "input(", "os.environ")
    taint_sinks = {
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

    def _expr_uses_taint(expr: ast.AST, tainted: Set[str]) -> bool:
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name) and sub.id in tainted:
                return True
            if isinstance(sub, ast.Attribute):
                full = _get_call_name(sub)
                if any(full.startswith(src.rstrip("(")) for src in taint_sources):
                    return True
            if isinstance(sub, ast.Call):
                cname = _get_call_name(sub.func)
                if cname == "input" or any(cname.startswith(src.rstrip("(")) for src in taint_sources):
                    return True
        return False

    def _walk_scope(stmts: List[ast.stmt]) -> None:
        tainted: Set[str] = set()
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                _walk_scope(stmt.body)
                continue
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Assign):
                    if _expr_uses_taint(sub.value, tainted):
                        for tgt in sub.targets:
                            if isinstance(tgt, ast.Name):
                                tainted.add(tgt.id)
                elif isinstance(sub, ast.Call):
                    sink = _get_call_name(sub.func)
                    if sink in taint_sinks and sub.args:
                        if any(_expr_uses_taint(arg, tainted) for arg in sub.args):
                            # Only emit TAINT001 if tainted via an explicit variable propagation
                            if any(
                                isinstance(n, ast.Name) and n.id in tainted
                                for arg in sub.args
                                for n in ast.walk(arg)
                            ):
                                _add(
                                    "TAINT001",
                                    "CRITICAL",
                                    f"Tainted user input flows into sensitive sink '{sink}()'",
                                    sub.lineno,
                                )

    _walk_scope(tree.body)
    return findings


def scan_sast(root_path: Path) -> List[Dict]:
    """Run AST (Python) and pattern-based (other languages) static security checks."""
    findings: List[Dict] = []
    ignore_rules = load_vulnignore(root_path)

    for file_path in iter_scannable_files(root_path, CODE_EXTENSIONS, ignore_rules):
        ext = file_path.suffix.lower()
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        lines = content.splitlines()
        if ext == ".py":
            findings.extend(_scan_python_ast(file_path, content, lines, root_path, ignore_rules))
            continue

        elif ext in {".js", ".jsx", ".ts", ".tsx"}:
            tainted_js: Set[str] = set()
            for line_no, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith(("//", "/*", "*")):
                    continue
                m_assign = re.match(r"^(?:const|let|var)\s+(\w+)\s*=\s*req\.(?:query|body|params|headers)\b", stripped)
                if m_assign:
                    tainted_js.add(m_assign.group(1))
                elif tainted_js and any(
                    re.search(rf"\b(?:eval|exec|innerHTML|outerHTML|document\.write)\b.*\b{re.escape(var)}\b", stripped)
                    for var in tainted_js
                ):
                    if not (_is_line_suppressed(line, "TAINT002") or _is_ignored_by_vulnignore(file_path, root_path, "TAINT002", ignore_rules)):
                        findings.append({
                            "category": "sast",
                            "rule_id": "TAINT002",
                            "severity": "CRITICAL",
                            "file": str(file_path),
                            "line": line_no,
                            "message": "Untrusted request input flows into dangerous JS/TS sink",
                            "match": stripped[:120],
                            "remediation": REMEDIATIONS["TAINT001"],
                        })
        elif ext == ".go":
            for line_no, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith(("//", "/*", "*")):
                    continue
                if re.search(r'\bexec\.Command\s*\(\s*"(?:sh|bash)"', stripped) and not (
                    _is_line_suppressed(line, "SAST002") or _is_ignored_by_vulnignore(file_path, root_path, "SAST002", ignore_rules)
                ):
                    findings.append({
                        "category": "sast",
                        "rule_id": "SAST002",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_no,
                        "message": "Shell command execution via exec.Command(\"sh\"/\"bash\")",
                        "match": stripped[:120],
                        "remediation": REMEDIATIONS["SAST002"],
                    })

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                continue

            for rule_id, severity, description, pattern, allowed_exts in SAST_PATTERNS:
                if allowed_exts is not None and ext not in allowed_exts:
                    continue
                if _is_line_suppressed(line, rule_id) or _is_ignored_by_vulnignore(
                    file_path, root_path, rule_id, ignore_rules
                ):
                    continue
                if pattern.search(line):
                    findings.append({
                        "category": "sast",
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": str(file_path),
                        "line": line_no,
                        "message": description,
                        "match": stripped[:120],
                        "remediation": REMEDIATIONS[rule_id],
                    })

    return findings


def scan_dependency_hygiene(root_path: Path) -> List[Dict]:
    """Check manifests and lockfiles for unpinned versions or missing lockfiles."""
    findings: List[Dict] = []
    ignore_rules = load_vulnignore(root_path)

    for file_path in iter_scannable_files(root_path, {".txt", ".json"}, ignore_rules):
        if file_path.name == "requirements.txt":
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for line_no, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "-r", "--")):
                    continue
                if _is_line_suppressed(line, "HYG001") or _is_ignored_by_vulnignore(
                    file_path, root_path, "HYG001", ignore_rules
                ):
                    continue
                if "==" not in stripped:
                    findings.append({
                        "category": "hygiene",
                        "rule_id": "HYG001",
                        "severity": "LOW",
                        "file": str(file_path),
                        "line": line_no,
                        "message": f"Unpinned Python dependency '{stripped}' (use == for reproducible builds)",
                        "match": stripped,
                        "remediation": REMEDIATIONS["HYG001"],
                    })

        elif file_path.name == "package.json":
            parent = file_path.parent
            has_lock = any(
                (parent / lock).exists()
                for lock in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
            )
            if not has_lock and not _is_ignored_by_vulnignore(
                file_path, root_path, "HYG002", ignore_rules
            ):
                findings.append({
                    "category": "hygiene",
                    "rule_id": "HYG002",
                    "severity": "MEDIUM",
                    "file": str(file_path),
                    "line": 1,
                    "message": "package.json has no adjacent lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml)",
                    "match": file_path.name,
                    "remediation": REMEDIATIONS["HYG002"],
                })

            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
            except Exception:
                continue

            for section in ("dependencies", "devDependencies"):
                deps = data.get(section, {})
                if not isinstance(deps, dict):
                    continue
                for pkg, ver in deps.items():
                    if isinstance(ver, str) and ver.strip() in {"*", "latest", ""}:
                        if not _is_ignored_by_vulnignore(file_path, root_path, "HYG003", ignore_rules):
                            findings.append({
                                "category": "hygiene",
                                "rule_id": "HYG003",
                                "severity": "MEDIUM",
                                "file": str(file_path),
                                "line": 1,
                                "message": f"Wildcard or unpinned npm dependency '{pkg}': '{ver}'",
                                "match": f"{pkg}: {ver}",
                                "remediation": REMEDIATIONS["HYG003"],
                            })

    return findings


def scan_custom_rules(root_path: Path, custom_rules: List[Dict]) -> List[Dict]:
    """Evaluate user-defined regex rules from vuln-scanner.toml."""
    if not custom_rules:
        return []

    compiled_rules = []
    for idx, rule in enumerate(custom_rules, start=1):
        pat_str = rule.get("pattern")
        if not pat_str:
            continue
        try:
            compiled = re.compile(pat_str)
        except re.error:
            continue
        exts = set(rule["extensions"]) if rule.get("extensions") else None
        compiled_rules.append((
            str(rule.get("id", f"CUST{idx:03d}")),
            str(rule.get("severity", "MEDIUM")).upper(),
            str(rule.get("message", f"Custom rule {pat_str} matched")),
            str(rule.get("remediation", "Review custom policy violation.")),
            compiled,
            exts,
        ))

    if not compiled_rules:
        return []

    findings: List[Dict] = []
    ignore_rules = load_vulnignore(root_path)

    for file_path in iter_scannable_files(root_path, TEXT_EXTENSIONS, ignore_rules):
        ext = file_path.suffix.lower()
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for line_no, line in enumerate(lines, start=1):
            for rule_id, severity, message, remediation, pattern, exts in compiled_rules:
                if exts is not None and ext not in exts:
                    continue
                if _is_line_suppressed(line, rule_id) or _is_ignored_by_vulnignore(
                    file_path, root_path, rule_id, ignore_rules
                ):
                    continue
                if pattern.search(line):
                    findings.append({
                        "category": "custom",
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": str(file_path),
                        "line": line_no,
                        "message": message,
                        "match": line.strip()[:120],
                        "remediation": remediation,
                    })

    return findings
