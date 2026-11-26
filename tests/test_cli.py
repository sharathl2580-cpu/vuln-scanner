import json
from pathlib import Path

from vuln_scanner.scan import main


def test_cli_json_output_and_no_network(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text("eval('1+1')\n", encoding="utf-8")
    exit_code = main([str(tmp_path), "--checks", "sast", "--no-network", "--json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data["sast"]) == 1
    assert data["sast"][0]["rule_id"] == "SAST001"


def test_cli_sarif_output_to_file(tmp_path: Path):
    (tmp_path / "app.py").write_text("eval('1+1')\n", encoding="utf-8")
    out_file = tmp_path / "report.sarif"
    exit_code = main([
        str(tmp_path),
        "--checks",
        "sast",
        "--no-network",
        "--format",
        "sarif",
        "--output",
        str(out_file),
    ])
    assert exit_code == 0
    sarif = json.loads(out_file.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "vuln-scanner"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SAST001"


def test_cli_fail_on_severity_threshold(tmp_path: Path):
    (tmp_path / "app.py").write_text("eval('1+1')\n", encoding="utf-8")
    assert main([str(tmp_path), "--checks", "sast", "--no-network", "--fail-on", "high"]) == 1
    assert main([str(tmp_path), "--checks", "sast", "--no-network", "--fail-on", "critical"]) == 0
