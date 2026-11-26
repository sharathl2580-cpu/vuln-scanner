from pathlib import Path
import socket
import threading
from unittest.mock import MagicMock, patch

from vuln_scanner.cyber_checks import scan_open_ports, scan_system_and_files
from vuln_scanner.iac_checks import scan_iac
from vuln_scanner.web_checks import scan_url


def test_scan_dockerfile_iac(tmp_path: Path):
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM python:latest\n"
        "ENV API_SECRET=super_secret_build_val\n"
        "ADD https://example.com/script.sh /tmp/script.sh\n"
        "RUN curl -s https://example.com/install.sh | sh\n",
        encoding="utf-8",
    )
    findings = scan_iac(tmp_path)
    rule_ids = {f["rule_id"] for f in findings}
    assert {"IAC001", "IAC002", "IAC003", "IAC004", "IAC005"} <= rule_ids


def test_scan_k8s_and_terraform_iac(tmp_path: Path):
    k8s = tmp_path / "deploy.yaml"
    k8s.write_text(
        "spec:\n"
        "  hostNetwork: true\n"
        "  containers:\n"
        "    - securityContext:\n"
        "        privileged: true\n"
        "        runAsUser: 0\n",
        encoding="utf-8",
    )
    tf = tmp_path / "main.tf"
    tf.write_text(
        'cidr_blocks = ["0.0.0.0/0"]\n'
        'acl = "public-read"\n'
        "encrypted = false\n",
        encoding="utf-8",
    )
    findings = scan_iac(tmp_path)
    rule_ids = {f["rule_id"] for f in findings}
    assert {"IAC006", "IAC007", "IAC008", "IAC009", "IAC010", "IAC011"} <= rule_ids


def test_scan_url_web_headers():
    mock_resp = MagicMock()
    mock_resp.url = "https://example.com/"
    mock_resp.headers = {
        "Server": "nginx/1.18.0",
        "Set-Cookie": "session=abc123; Path=/",
    }

    with patch("vuln_scanner.web_checks.requests.get", return_value=mock_resp):
        findings = scan_url("http://example.com")

    rule_ids = {f["rule_id"] for f in findings}
    assert {"WEB001", "WEB002", "WEB003", "WEB004", "WEB005", "WEB006", "WEB007"} <= rule_ids


def test_scan_system_and_files_and_open_ports(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("*.log\n", encoding="utf-8")
    key_file = tmp_path / "id_rsa"
    key_file.write_text("SECRETKEY", encoding="utf-8")
    key_file.chmod(0o644)

    findings = scan_system_and_files(tmp_path)
    rule_ids = {f["rule_id"] for f in findings}
    assert {"SYS001", "SYS002"} <= rule_ids

    # Test open port detection with mocked socket connect_ex
    mock_sock = MagicMock()
    mock_sock.connect_ex.return_value = 0
    with patch("vuln_scanner.cyber_checks.socket.socket", return_value=mock_sock):
        port_findings = scan_open_ports("127.0.0.1", ports=[(6379, "Redis", "Bind to localhost")], timeout=0.5)
    assert len(port_findings) == 1
    assert port_findings[0]["rule_id"] == "SYS004"
