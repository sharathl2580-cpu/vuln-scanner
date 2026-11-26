import json
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple
from unittest.mock import MagicMock, patch

from vuln_scanner.scan import scan_dependencies
from vuln_scanner.security_checks import (
    scan_dependency_hygiene,
    scan_sast,
    scan_secrets,
)


def _metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision * 100, 1),
        "recall": round(recall * 100, 1),
        "f1": round(f1 * 100, 1),
        "fpr": round(fpr * 100, 1),
    }


def evaluate_sast(base: Path) -> Dict[str, float]:
    # (filename, code, expected_rule_ids_set)  -- empty set means safe (True Negative)
    cases: List[Tuple[str, str, set]] = [
        # True Positives (vulnerable)
        ("tp_eval.py", "eval(user_input)\n", {"SAST001"}),
        ("tp_exec.py", "exec(code_str)\n", {"SAST001"}),
        ("tp_shell.py", "import subprocess\nsubprocess.run('id', shell=True)\n", {"SAST002"}),
        ("tp_system.py", "import os\nos.system('rm -rf /tmp/x')\n", {"SAST002"}),
        ("tp_pickle.py", "import pickle\npickle.loads(data)\n", {"SAST003"}),
        ("tp_yaml.py", "import yaml\nyaml.load(stream)\n", {"SAST003"}),
        ("tp_tls.py", "import requests\nrequests.get('https://x.com', verify=False)\n", {"SAST004"}),
        ("tp_md5.py", "import hashlib\nhashlib.md5(b'pw')\n", {"SAST005"}),
        ("tp_sqli_f.py", 'q = f"SELECT * FROM users WHERE name = {name}"\n', {"SAST006"}),
        ("tp_sqli_pct.py", 'q = "DELETE FROM users WHERE id = %s" % uid\n', {"SAST006"}),
        ("tp_http.py", 'URL = "http://api.example.com/v1"\n', {"SAST007"}),
        ("tp_js_eval.js", "const x = eval(input);\n", {"SAST001"}),
        # True Negatives (safe)
        ("tn_literal_eval.py", "import ast\nast.literal_eval('[1, 2]')\n", set()),
        ("tn_subprocess.py", "import subprocess\nsubprocess.run(['ls', '-la'], shell=False)\n", set()),
        ("tn_yaml_safe.py", "import yaml\nyaml.load(stream, Loader=yaml.SafeLoader)\n", set()),
        ("tn_tls_ok.py", "import requests\nrequests.get('https://x.com', verify=True)\n", set()),
        ("tn_sha256.py", "import hashlib\nhashlib.sha256(b'pw')\n", set()),
        ("tn_sqli_param.py", 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))\n', set()),
        ("tn_localhost.py", 'URL = "http://localhost:8080/health"\n', set()),
        ("tn_comment.py", "# eval(user_input)\n# subprocess.run('id', shell=True)\n", set()),
        ("tn_docstring.py", '"""Example: eval(x) and http://example.com"""\n', set()),
        ("tn_nosec.py", "eval('1+1')  # nosec SAST001\n", set()),
    ]

    tp = fp = fn = tn = 0
    sast_dir = base / "sast"
    sast_dir.mkdir(parents=True, exist_ok=True)

    for fname, code, expected in cases:
        fpath = sast_dir / fname
        fpath.write_text(code, encoding="utf-8")
        found = {f["rule_id"] for f in scan_sast(fpath)}
        if expected:
            if expected <= found:
                tp += 1
            else:
                fn += 1
            fp += len(found - expected)
        else:
            if not found:
                tn += 1
            else:
                fp += len(found)

    return _metrics(tp, fp, fn, tn)


def evaluate_secrets(base: Path) -> Dict[str, float]:
    cases: List[Tuple[str, str, set]] = [
        # True Positives
        ("tp_aws.py", 'AWS = "AKIAIOSFODNN7EXAMPLE"\n', {"SEC001"}),
        ("tp_privkey.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n", {"SEC002"}),
        ("tp_gh.py", 'GH = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"\n', {"SEC003"}),
        ("tp_slack.py", 'SL = "xoxb-1234567890-1234567890-abcdef"\n', {"SEC004"}),
        ("tp_google.py", 'GAPI = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGtQe0"\n', {"SEC005"}),
        ("tp_sk.py", 'OPENAI = "sk-proj-1234567890abcdefghijklmnop"\n', {"SEC006"}),
        ("tp_pw.py", 'password = "correct_horse_battery_staple"\n', {"SEC007"}),
        ("tp_dotenv/.env", "DB_PASS=super_secret_db_pass_99\n", {"SEC000"}),
        # True Negatives
        ("tn_placeholder.py", 'password = "changeme"\n', set()),
        ("tn_env_lookup.py", 'password = os.environ.get("DB_PASS")\n', set()),
        ("tn_env_example/.env.example", "DB_PASS=real_looking_secret_12345\n", set()),
        ("tn_short_pw.py", 'password = "abc"\n', set()),
        ("tn_nosec_sec.py", 'password = "real_secret_value_123"  # nosec SEC007\n', set()),
        ("tn_normal.py", "timeout = 30\nretries = 3\n", set()),
    ]

    tp = fp = fn = tn = 0
    sec_dir = base / "secrets"
    sec_dir.mkdir(parents=True, exist_ok=True)

    for fname, code, expected in cases:
        fpath = sec_dir / fname
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(code, encoding="utf-8")
        found = {f["rule_id"] for f in scan_secrets(fpath)}
        if expected:
            if expected <= found:
                tp += 1
            else:
                fn += 1
            fp += len(found - expected)
        else:
            if not found:
                tn += 1
            else:
                fp += len(found)

    return _metrics(tp, fp, fn, tn)


def evaluate_hygiene(base: Path) -> Dict[str, float]:
    hyg_dir = base / "hygiene"
    hyg_dir.mkdir(parents=True, exist_ok=True)

    # TP 1: unpinned requirements.txt
    tp1 = hyg_dir / "tp_req"
    tp1.mkdir()
    (tp1 / "requirements.txt").write_text("requests\n", encoding="utf-8")

    # TP 2 & 3: package.json with no lockfile + wildcard version
    tp2 = hyg_dir / "tp_npm"
    tp2.mkdir()
    (tp2 / "package.json").write_text(json.dumps({"dependencies": {"lodash": "*"}}), encoding="utf-8")

    # TN 1: pinned requirements.txt
    tn1 = hyg_dir / "tn_req"
    tn1.mkdir()
    (tn1 / "requirements.txt").write_text("requests==2.32.5\n", encoding="utf-8")

    # TN 2: package.json with lockfile and pinned range
    tn2 = hyg_dir / "tn_npm"
    tn2.mkdir()
    (tn2 / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.21"}}), encoding="utf-8")
    (tn2 / "package-lock.json").write_text("{}", encoding="utf-8")

    tp = fp = fn = tn = 0
    for target, expected in [
        (tp1, {"HYG001"}),
        (tp2, {"HYG002", "HYG003"}),
        (tn1, set()),
        (tn2, set()),
    ]:
        found = {f["rule_id"] for f in scan_dependency_hygiene(target)}
        if expected:
            tp += len(expected & found)
            fn += len(expected - found)
            fp += len(found - expected)
        else:
            if not found:
                tn += 1
            else:
                fp += len(found)

    return _metrics(tp, fp, fn, tn)


def evaluate_dependencies(base: Path) -> Dict[str, float]:
    dep_dir = base / "deps"
    dep_dir.mkdir(parents=True, exist_ok=True)

    # Create 6 vulnerable ecosystems + 4 clean packages
    (dep_dir / "requirements.txt").write_text("requests==2.19.0\nflask==3.0.0\n", encoding="utf-8")
    (dep_dir / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 2, "dependencies": {"lodash": {"version": "4.17.20"}, "chalk": {"version": "5.3.0"}}}),
        encoding="utf-8",
    )
    (dep_dir / "yarn.lock").write_text('minimist@^1.2.5:\n  version "1.2.5"\n', encoding="utf-8")
    (dep_dir / "go.mod").write_text("module m\nrequire github.com/gin-gonic/gin v1.7.0\n", encoding="utf-8")
    (dep_dir / "Cargo.lock").write_text('[[package]]\nname = "regex"\nversion = "1.5.4"\n', encoding="utf-8")
    (dep_dir / "composer.lock").write_text(
        json.dumps({"packages": [{"name": "symfony/http-kernel", "version": "v5.4.0"}]}),
        encoding="utf-8",
    )

    vulnerable_set = {
        ("requests", "2.19.0", "PyPI"),
        ("lodash", "4.17.20", "npm"),
        ("minimist", "1.2.5", "npm"),
        ("github.com/gin-gonic/gin", "v1.7.0", "Go"),
        ("regex", "1.5.4", "crates.io"),
        ("symfony/http-kernel", "5.4.0", "Packagist"),
    }

    def fake_post(url, json=None, timeout=15):
        resp = MagicMock()
        resp.status_code = 200
        results = []
        for q in json.get("queries", []):
            pkg = q["package"]["name"]
            eco = q["package"]["ecosystem"]
            ver = q["version"]
            if (pkg, ver, eco) in vulnerable_set:
                results.append({"vulns": [{"id": f"OSV-{pkg}", "summary": "Known vuln", "database_specific": {"severity": "HIGH"}}]})
            else:
                results.append({})
        resp.json.return_value = {"results": results}
        return resp

    with patch("vuln_scanner.osv_client.requests.post", side_effect=fake_post):
        findings = scan_dependencies(dep_dir, use_cache=False)

    detected = {(f["package"], f["version"], f["ecosystem"]) for f in findings}
    tp = len(detected & vulnerable_set)
    fn = len(vulnerable_set - detected)
    fp = len(detected - vulnerable_set)
    tn = 2 - fp  # 2 clean packages (flask, chalk)
    return _metrics(tp, fp, fn, max(0, tn))


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        results = {
            "SAST (Python AST + JS)": evaluate_sast(base),
            "Secret Detection": evaluate_secrets(base),
            "Dependency Hygiene": evaluate_hygiene(base),
            "Dependency / OSV Matching": evaluate_dependencies(base),
        }

    total_tp = sum(r["tp"] for r in results.values())
    total_fp = sum(r["fp"] for r in results.values())
    total_fn = sum(r["fn"] for r in results.values())
    total_tn = sum(r["tn"] for r in results.values())
    overall = _metrics(total_tp, total_fp, total_fn, total_tn)
    results["OVERALL"] = overall

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
