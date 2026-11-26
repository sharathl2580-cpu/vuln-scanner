import json
from pathlib import Path

from vuln_scanner.security_checks import (
    redact_secret,
    scan_dependency_hygiene,
    scan_sast,
    scan_secrets,
)


def test_redact_secret_masks_middle():
    redacted = redact_secret("AKIAIOSFODNN7EXAMPLE")
    assert redacted.startswith("AKIA")
    assert redacted.endswith("MPLE")
    assert "*" in redacted
    assert "IOSFODNN7EXA" not in redacted


def test_scan_secrets_detects_keys_and_redacts(tmp_path: Path):
    cfg = tmp_path / "config.py"
    cfg.write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"\n'
        'PASSWORD = "super_secret_password_123"\n',
        encoding="utf-8",
    )
    findings = scan_secrets(tmp_path)
    rule_ids = {f["rule_id"] for f in findings}
    assert "SEC001" in rule_ids
    assert "SEC003" in rule_ids
    assert "SEC007" in rule_ids
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f["match"]
        assert "super_secret_password_123" not in f["match"]
        assert f["remediation"]


def test_scan_secrets_ignores_placeholders_and_env_examples(tmp_path: Path):
    (tmp_path / ".env.example").write_text("API_KEY=real_looking_value_12345\n", encoding="utf-8")
    (tmp_path / "settings.py").write_text('DB_PASSWORD = "changeme"\n', encoding="utf-8")

    findings = scan_secrets(tmp_path)
    assert findings == []


def test_scan_secrets_flags_real_dotenv(tmp_path: Path):
    (tmp_path / ".env").write_text("STRIPE_SECRET=my_live_secret_value_999\n", encoding="utf-8")
    findings = scan_secrets(tmp_path)
    assert any(f["rule_id"] == "SEC000" for f in findings)


def test_scan_sast_ast_detects_vulnerabilities_and_ignores_strings(tmp_path: Path):
    app = tmp_path / "app.py"
    app.write_text(
        "import os, pickle, hashlib, requests, subprocess, yaml\n"
        "eval(user_input)\n"
        "subprocess.run('ls', shell=True)\n"
        "pickle.loads(raw_bytes)\n"
        "requests.get('http://example.com/api', verify=False)\n"
        "h = hashlib.md5(b'data')\n"
        'query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        "safe = yaml.load(data, Loader=yaml.SafeLoader)\n"
        'doc = "eval(not_a_call) and http://not-a-url-const"\n',
        encoding="utf-8",
    )
    findings = scan_sast(tmp_path)
    rule_ids = {f["rule_id"] for f in findings}
    assert {"SAST001", "SAST002", "SAST003", "SAST004", "SAST005", "SAST006", "SAST007"} <= rule_ids
    # SafeLoader usage should not be flagged as SAST003
    sast003_lines = [f["line"] for f in findings if f["rule_id"] == "SAST003"]
    assert sast003_lines == [4]
    # String literal on line 9 should not trigger SAST001 or SAST007
    assert not any(f["line"] == 9 for f in findings)


def test_scan_sast_skips_comments_and_localhost_http(tmp_path: Path):
    app = tmp_path / "app.py"
    app.write_text(
        "# eval(user_input)\n"
        "url = 'http://localhost:8000/health'\n",
        encoding="utf-8",
    )
    assert scan_sast(tmp_path) == []


def test_nosec_inline_and_vulnignore_suppression(tmp_path: Path):
    (tmp_path / ".vulnignore").write_text(
        "# Ignore test fixtures\nSAST001:ignored_by_rule.py\nignored_all/*\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "eval('1+1')  # nosec SAST001\n"
        "exec('x=1')  # nosec\n",
        encoding="utf-8",
    )
    (tmp_path / "ignored_by_rule.py").write_text(
        "eval('1+1')\n"
        "os.system('ls')\n",
        encoding="utf-8",
    )
    ignored_dir = tmp_path / "ignored_all"
    ignored_dir.mkdir()
    (ignored_dir / "bad.py").write_text("eval('1+1')\n", encoding="utf-8")

    findings = scan_sast(tmp_path)
    # Only os.system in ignored_by_rule.py should remain
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SAST002"
    assert findings[0]["file"].endswith("ignored_by_rule.py")


def test_scan_dependency_hygiene(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests\nflask==2.3.2\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"left-pad": "*"}}),
        encoding="utf-8",
    )
    findings = scan_dependency_hygiene(tmp_path)
    rule_ids = {f["rule_id"] for f in findings}
    assert {"HYG001", "HYG002", "HYG003"} <= rule_ids


def test_scan_sast_extended_rules_and_entropy_secret(tmp_path: Path):
    app = tmp_path / "web_app.py"
    app.write_text(
        "import random, tempfile, xml.etree.ElementTree as ET\n"
        "from markupsafe import Markup\n"
        "DEBUG = True\n"
        "tok = random.choice(['a', 'b'])\n"
        "p = tempfile.mktemp()\n"
        "ET.fromstring('<root/>')\n"
        "html = Markup('<b>hi</b>')\n"
        'signing_token = "aB3$kL9mNpQ2rS5tUvW8xYz01234"\n',
        encoding="utf-8",
    )
    sast_rules = {f["rule_id"] for f in scan_sast(app)}
    sec_rules = {f["rule_id"] for f in scan_secrets(app)}
    assert {"SAST008", "SAST009", "SAST010", "SAST011", "SAST012"} <= sast_rules
    assert "SEC008" in sec_rules


def test_scan_ssrf_path_traversal_jwt_cors_and_crypto(tmp_path: Path):
    api = tmp_path / "api.py"
    api.write_text(
        "import requests, jwt\n"
        "from flask import send_file\n"
        "from flask_cors import CORS\n"
        "from Crypto.Cipher import AES\n"
        "def fetch(u):\n"
        "    return requests.get(u)\n"
        "def dl(p):\n"
        "    return send_file(p)\n"
        "def tok(t):\n"
        "    return jwt.decode(t, options={'verify_signature': False})\n"
        "CORS(app, origins='*', supports_credentials=True)\n"
        "mode = AES.MODE_ECB\n",
        encoding="utf-8",
    )
    rules = {f["rule_id"] for f in scan_sast(api)}
    assert {"SAST013", "SAST014", "SAST015", "AUTH001", "AUTH002"} <= rules
