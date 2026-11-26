import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from vuln_scanner.config import load_config
from vuln_scanner.git_history import scan_git_history
from vuln_scanner.license_checks import classify_license, scan_licenses
from vuln_scanner.scan import main
from vuln_scanner.security_checks import scan_sast


def test_python_taint_tracking_detects_source_to_sink(tmp_path: Path):
    app = tmp_path / "tainted.py"
    app.write_text(
        "def handler(request):\n"
        "    user_cmd = request.args.get('cmd')\n"
        "    os.system(user_cmd)\n",
        encoding="utf-8",
    )
    rules = {f["rule_id"] for f in scan_sast(app)}
    assert "TAINT001" in rules


def test_git_history_secret_scanning(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    diff_output = (
        "commit 1234567890abcdef\n"
        "Author: Dev <dev@example.com>\n"
        "+++ b/settings.py\n"
        '+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = diff_output

    with patch("vuln_scanner.git_history.subprocess.run", return_value=mock_proc):
        findings = scan_git_history(tmp_path, max_commits=10)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC001"
    assert findings[0]["file"] == "settings.py@12345678"
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0]["match"]


def test_vuln_scanner_toml_config_overrides_defaults(tmp_path: Path):
    (tmp_path / "vuln-scanner.toml").write_text(
        'checks = ["sast"]\n'
        'format = "markdown"\n'
        "no_network = true\n"
        'fail_on = "high"\n',
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("eval('1+1')\n", encoding="utf-8")

    cfg = load_config(tmp_path)
    assert cfg["checks"] == ["sast"]
    assert cfg["no_network"] is True
    # Config sets fail_on = "high", so main() should return 1 without passing --fail-on
    assert main([str(tmp_path)]) == 1


def test_markdown_html_and_cyclonedx_formats(tmp_path: Path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.32.5\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("eval('1+1')\n", encoding="utf-8")

    assert main([str(tmp_path), "--checks", "sast", "--no-network", "--format", "markdown"]) == 0
    md = capsys.readouterr().out
    assert "# Security Scan Report" in md
    assert "SAST001" in md

    assert main([str(tmp_path), "--checks", "sast", "--no-network", "--format", "html"]) == 0
    html_out = capsys.readouterr().out
    assert "<title>vuln-scanner Security Report</title>" in html_out
    assert "SAST001" in html_out

    assert main([str(tmp_path), "--checks", "deps", "--no-network", "--format", "cyclonedx"]) == 0
    sbom = json.loads(capsys.readouterr().out)
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["components"][0]["purl"] == "pkg:pypi/requests@2.32.5"


def test_license_classification_and_scan(tmp_path: Path):
    assert classify_license("MIT") is None
    assert classify_license("GPL-3.0-only")[0] == "LIC001"
    assert classify_license("MPL-2.0")[0] == "LIC002"

    (tmp_path / "package.json").write_text(json.dumps({"name": "demo"}), encoding="utf-8")
    (tmp_path / "composer.lock").write_text(
        json.dumps({"packages": [{"name": "vendor/pkg", "version": "1.0.0", "license": ["GPL-3.0"]}]}),
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("somepkg==1.0.0\n", encoding="utf-8")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"info": {"license": "AGPL-3.0"}}

    with patch("vuln_scanner.license_checks.requests.get", return_value=mock_resp):
        findings = scan_licenses(tmp_path, no_network=False, use_cache=False)

    rule_ids = {f["rule_id"] for f in findings}
    assert {"LIC001", "LIC003"} <= rule_ids
