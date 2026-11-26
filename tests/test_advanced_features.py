import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from vuln_scanner.autofix import apply_dependency_fixes
from vuln_scanner.scan import main
from vuln_scanner.security_checks import scan_sast
from vuln_scanner.web_checks import scan_url


def test_exclude_ignore_rules_and_quiet_flags(tmp_path: Path, capsys):
    (tmp_path / "keep.py").write_text("eval('1+1')\n", encoding="utf-8")
    skip_dir = tmp_path / "skip_me"
    skip_dir.mkdir()
    (skip_dir / "bad.py").write_text("exec('2+2')\n", encoding="utf-8")

    # Exclude skip_me/* and ignore SAST001 -> 0 findings, --quiet prints nothing
    rc = main([
        str(tmp_path),
        "--checks",
        "sast",
        "--no-network",
        "--exclude",
        "skip_me/*",
        "--ignore-rules",
        "SAST001",
        "--quiet",
    ])
    assert rc == 0
    assert capsys.readouterr().out == ""


def test_baseline_save_and_filter(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text("eval('1+1')\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"

    assert main([str(tmp_path), "--checks", "sast", "--no-network", "--save-baseline", str(baseline)]) == 0
    capsys.readouterr()
    assert baseline.exists()

    # Re-run with --baseline -> baselined finding is suppressed, so --fail-on high passes (0)
    assert main([
        str(tmp_path),
        "--checks",
        "sast",
        "--no-network",
        "--baseline",
        str(baseline),
        "--fail-on",
        "high",
    ]) == 0


def test_pr_diff_filters_to_changed_files(tmp_path: Path, capsys):
    (tmp_path / ".git").mkdir()
    changed = tmp_path / "changed.py"
    unchanged = tmp_path / "unchanged.py"
    changed.write_text("eval('1+1')\n", encoding="utf-8")
    unchanged.write_text("exec('2+2')\n", encoding="utf-8")

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "changed.py\n"

    with patch("vuln_scanner.scan.subprocess.run", return_value=mock_proc):
        rc = main([str(tmp_path), "--checks", "sast", "--no-network", "--diff", "main", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["sast"]) == 1
    assert data["sast"][0]["file"].endswith("changed.py")


def test_custom_rules_and_js_go_checks(tmp_path: Path, capsys):
    (tmp_path / "vuln-scanner.toml").write_text(
        'checks = ["sast"]\n'
        "no_network = true\n"
        "[[custom_rules]]\n"
        'id = "CUST001"\n'
        'severity = "HIGH"\n'
        'pattern = "internal\\\\.corp"\n'
        'message = "Internal domain leaked"\n'
        'extensions = [".py"]\n',
        encoding="utf-8",
    )
    (tmp_path / "cfg.py").write_text('HOST = "api.internal.corp"\n', encoding="utf-8")
    (tmp_path / "app.js").write_text("const u = req.query.cmd;\neval(u);\n", encoding="utf-8")
    (tmp_path / "main.go").write_text('exec.Command("sh", "-c", cmd)\n', encoding="utf-8")

    sast_rules = {f["rule_id"] for f in scan_sast(tmp_path)}
    assert {"TAINT002", "SAST002"} <= sast_rules

    assert main([str(tmp_path), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["custom"]) == 1
    assert data["custom"][0]["rule_id"] == "CUST001"


def test_autofix_requirements_and_package_json(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.19.0\n", encoding="utf-8")
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}), encoding="utf-8")
    pkg_lock = tmp_path / "package-lock.json"
    pkg_lock.write_text("{}", encoding="utf-8")

    report = {
        "dependencies": [
            {"file": str(req), "package": "requests", "vulns": [{"fixed_version": "2.32.5"}]},
            {"file": str(pkg_lock), "package": "lodash", "vulns": [{"fixed_version": "4.17.21"}]},
        ]
    }
    applied = apply_dependency_fixes(report, tmp_path)
    assert len(applied) == 2
    assert "requests==2.32.5" in req.read_text(encoding="utf-8")
    assert json.loads(pkg_json.read_text(encoding="utf-8"))["dependencies"]["lodash"] == "^4.17.21"


def test_web_recon_exposed_paths_and_methods():
    def fake_get(url, **kwargs):
        r = MagicMock()
        r.url = url
        r.headers = {}
        if url.endswith("/.env"):
            r.status_code = 200
            r.text = "DB_PASS=secret123"
        elif url.endswith("/.well-known/security.txt"):
            r.status_code = 404
            r.text = ""
        elif url.endswith(("/.git/HEAD", "/actuator/env", "/swagger.json")):
            r.status_code = 404
            r.text = ""
        else:
            r.status_code = 200
            r.text = "ok"
        return r

    opt_resp = MagicMock()
    opt_resp.headers = {"Allow": "GET, POST, TRACE, OPTIONS"}

    with patch("vuln_scanner.web_checks.requests.get", side_effect=fake_get), patch(
        "vuln_scanner.web_checks.requests.options", return_value=opt_resp
    ):
        findings = scan_url("https://example.com", recon=True)

    rules = {f["rule_id"] for f in findings}
    assert {"WEB011", "WEB012", "WEB013"} <= rules
