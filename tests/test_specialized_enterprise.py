import io
import json
from pathlib import Path
import tarfile
from unittest.mock import MagicMock, patch

from vuln_scanner.compliance_and_iam import scan_iam_policies, scan_pii
from vuln_scanner.dashboard import build_dashboard_html, make_dashboard_handler
from vuln_scanner.image_checks import scan_docker_image_tar
from vuln_scanner.web_checks import scan_domain_posture


def test_pii_luhn_credit_card_and_ssn(tmp_path: Path):
    # 4111111111111111 is Luhn-valid; 4111111111111112 is NOT Luhn-valid
    data_file = tmp_path / "app.py"
    data_file.write_text(
        'card_real = "4111-1111-1111-1111"\n'
        'card_fake = "4111-1111-1111-1112"\n'
        'ssn_real = "123-45-6780"\n'
        'ssn_dummy = "123-45-6789"\n',
        encoding="utf-8",
    )
    findings = scan_pii(tmp_path)
    rules = [f["rule_id"] for f in findings]
    assert rules == ["PII001", "PII002"]
    assert "4111111111111111" not in findings[0]["match"]


def test_cloud_iam_least_privilege(tmp_path: Path):
    (tmp_path / "admin_policy.json").write_text(
        json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Effect": "Allow", "Action": ["iam:*"], "Resource": "*"},
            ],
        }),
        encoding="utf-8",
    )
    (tmp_path / "iam.tf").write_text(
        'data "aws_iam_policy_document" "adm" {\n'
        "  statement {\n"
        '    actions = ["*"]\n'
        '    resources = ["*"]\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    rules = {f["rule_id"] for f in scan_iam_policies(tmp_path)}
    assert {"IAM001", "IAM002", "IAM003"} <= rules


def test_subdomain_takeover_detection():
    def fake_get(url, **kwargs):
        r = MagicMock()
        r.status_code = 200
        if "cloudflare-dns.com" in url:
            params = kwargs.get("params", {})
            if params.get("type") == "CNAME" and params.get("name") == "dev.example.com":
                r.json.return_value = {"Answer": [{"type": 5, "data": "abandoned-bucket.s3.amazonaws.com."}]}
            else:
                r.json.return_value = {"Answer": []}
        else:
            r.text = "<Error><Code>NoSuchBucket</Code></Error>"
        return r

    with patch("vuln_scanner.web_checks.requests.get", side_effect=fake_get):
        findings = scan_domain_posture("example.com", check_takeover=True)

    rules = {f["rule_id"] for f in findings}
    assert {"DNS001", "DNS002", "DNS003"} <= rules


def test_docker_image_tar_scanning(tmp_path: Path):
    # Build a nested layer.tar inside an image.tar with dpkg status + .env secret
    layer_buf = io.BytesIO()
    with tarfile.open(fileobj=layer_buf, mode="w") as layer:
        dpkg_bytes = b"Package: openssl\nVersion: 1.1.1f-1ubuntu2\n\n"
        ti1 = tarfile.TarInfo("var/lib/dpkg/status")
        ti1.size = len(dpkg_bytes)
        layer.addfile(ti1, io.BytesIO(dpkg_bytes))

        env_bytes = b"AWS=AKIAIOSFODNN7EXAMPLE\n"
        ti2 = tarfile.TarInfo("app/.env")
        ti2.size = len(env_bytes)
        layer.addfile(ti2, io.BytesIO(env_bytes))

    tar_path = tmp_path / "image.tar"
    with tarfile.open(tar_path, "w") as img:
        layer_bytes = layer_buf.getvalue()
        ti = tarfile.TarInfo("blobs/layer.tar")
        ti.size = len(layer_bytes)
        img.addfile(ti, io.BytesIO(layer_bytes))

    batch_resp = MagicMock()
    batch_resp.status_code = 200
    batch_resp.json.return_value = {
        "results": [{"vulns": [{"id": "CVE-2023-0001", "summary": "OpenSSL bug", "database_specific": {"severity": "HIGH"}}]}]
    }

    with patch("vuln_scanner.osv_client.requests.post", return_value=batch_resp):
        findings = scan_docker_image_tar(tar_path, no_network=False, use_cache=False)

    rules = {f["rule_id"] for f in findings}
    assert {"IMG001", "IMG002"} <= rules


def test_dashboard_html_and_handler(tmp_path: Path):
    report = {
        "dependencies": [],
        "secrets": [],
        "sast": [
            {
                "rule_id": "SAST001",
                "severity": "HIGH",
                "file": "app.py",
                "line": 3,
                "message": "eval() detected",
                "remediation": "Use ast.literal_eval",
            }
        ],
    }
    html_page = build_dashboard_html(report)
    assert "vuln-scanner Security Dashboard" in html_page
    assert "SAST001" in html_page

    handler_cls = make_dashboard_handler(report, tmp_path)
    assert callable(handler_cls)
