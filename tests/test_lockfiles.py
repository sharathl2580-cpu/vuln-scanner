import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from vuln_scanner.osv_client import OSVCache, extract_fixed_version, extract_severity, query_osv_batch
from vuln_scanner.parsers import (
    parse_cargo_lock,
    parse_composer_lock,
    parse_go_mod,
    parse_poetry_lock,
    parse_yarn_lock,
)
from vuln_scanner.scan import (
    find_lockfiles,
    parse_gemfile_lock,
    parse_maven_pom,
    parse_npm_lock,
    parse_requirements,
    query_osv,
    scan_dependencies,
)


def test_find_lockfiles_skips_vendor_dirs(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    ignored = tmp_path / "node_modules" / "pkg"
    ignored.mkdir(parents=True)
    (ignored / "package-lock.json").write_text("{}", encoding="utf-8")

    found = find_lockfiles(tmp_path)
    assert [p.name for p in found] == ["requirements.txt"]


def test_parse_npm_lock_v1_and_v2(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 2,
                "dependencies": {"lodash": {"version": "4.17.20"}},
                "packages": {
                    "": {"name": "app"},
                    "node_modules/minimist": {"version": "1.2.5"},
                },
            }
        ),
        encoding="utf-8",
    )
    deps = parse_npm_lock(lock)
    assert ("lodash", "4.17.20") in deps
    assert ("minimist", "1.2.5") in deps


def test_parse_npm_lock_malformed_json(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text("{not valid json", encoding="utf-8")
    assert parse_npm_lock(lock) == []


def test_parse_yarn_lock(tmp_path: Path):
    yarn = tmp_path / "yarn.lock"
    yarn.write_text(
        '''# yarn lockfile v1

"@babel/core@^7.12.0":
  version "7.12.10"

lodash@^4.17.20, lodash@^4.17.21:
  version "4.17.21"
''',
        encoding="utf-8",
    )
    deps = parse_yarn_lock(yarn)
    assert ("@babel/core", "7.12.10") in deps
    assert ("lodash", "4.17.21") in deps


def test_parse_requirements_handles_operators_and_comments(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "# comment\nrequests==2.32.0\nflask>=2.0.0 # inline\npyyaml\n",
        encoding="utf-8",
    )
    deps = parse_requirements(req)
    assert deps == [("requests", "2.32.0"), ("flask", "2.0.0"), ("pyyaml", "")]


def test_parse_poetry_and_cargo_lock(tmp_path: Path):
    poetry = tmp_path / "poetry.lock"
    poetry.write_text(
        '[[package]]\nname = "urllib3"\nversion = "2.0.7"\n',
        encoding="utf-8",
    )
    cargo = tmp_path / "Cargo.lock"
    cargo.write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.193"\n',
        encoding="utf-8",
    )
    assert parse_poetry_lock(poetry) == [("urllib3", "2.0.7")]
    assert parse_cargo_lock(cargo) == [("serde", "1.0.193")]


def test_parse_go_mod_and_composer_lock(tmp_path: Path):
    gomod = tmp_path / "go.mod"
    gomod.write_text(
        """module example.com/app

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/net v0.17.0 // indirect
)

require github.com/pkg/errors v0.9.1
""",
        encoding="utf-8",
    )
    composer = tmp_path / "composer.lock"
    composer.write_text(
        json.dumps({"packages": [{"name": "symfony/http-foundation", "version": "v6.3.0"}]}),
        encoding="utf-8",
    )
    assert parse_go_mod(gomod) == [
        ("github.com/gin-gonic/gin", "v1.9.1"),
        ("golang.org/x/net", "v0.17.0"),
        ("github.com/pkg/errors", "v0.9.1"),
    ]
    assert parse_composer_lock(composer) == [("symfony/http-foundation", "6.3.0")]


def test_parse_maven_pom_valid_and_malformed(tmp_path: Path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>""",
        encoding="utf-8",
    )
    assert parse_maven_pom(pom) == [("org.apache.logging.log4j:log4j-core", "2.14.1")]

    bad_pom = tmp_path / "bad_pom.xml"
    bad_pom.write_text("<project><unclosed></project>", encoding="utf-8")
    assert parse_maven_pom(bad_pom) == []


def test_parse_gemfile_lock(tmp_path: Path):
    gemfile = tmp_path / "Gemfile.lock"
    gemfile.write_text(
        """GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.3)
    rails (6.1.4)

PLATFORMS
  ruby
""",
        encoding="utf-8",
    )
    assert parse_gemfile_lock(gemfile) == [("rack", "2.2.3"), ("rails", "6.1.4")]


def test_query_osv_handles_network_error():
    with patch("vuln_scanner.scan.requests.post", side_effect=OSError("timeout")):
        assert query_osv("lodash", "4.17.20", "npm") == {}


def test_osv_severity_and_fixed_version_extraction():
    vuln = {
        "id": "GHSA-1234",
        "database_specific": {"severity": "MODERATE"},
        "affected": [
            {
                "package": {"name": "requests", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}],
            }
        ],
    }
    assert extract_severity(vuln) == "MEDIUM"
    assert extract_fixed_version(vuln, "requests", "PyPI") == "2.31.0"


def test_osv_batch_and_disk_cache(tmp_path: Path):
    cache = OSVCache(cache_dir=tmp_path / "cache")
    batch_resp = MagicMock()
    batch_resp.status_code = 200
    batch_resp.json.return_value = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-test-1234",
                        "summary": "Test vuln",
                        "database_specific": {"severity": "CRITICAL"},
                        "affected": [
                            {
                                "package": {"name": "requests", "ecosystem": "PyPI"},
                                "ranges": [{"events": [{"fixed": "2.32.0"}]}],
                            }
                        ],
                    }
                ]
            }
        ]
    }

    with patch("vuln_scanner.osv_client.requests.post", return_value=batch_resp) as mock_post:
        res1 = query_osv_batch([("requests", "2.19.0", "PyPI")], cache=cache)
        res2 = query_osv_batch([("requests", "2.19.0", "PyPI")], cache=cache)
        assert mock_post.call_count == 1  # second call served from disk cache

    assert "GHSA-test-1234" == res1[("requests", "2.19.0", "PyPI")][0]["id"]
    assert res1 == res2


def test_scan_dependencies_with_mocked_osv(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    batch_resp = MagicMock()
    batch_resp.status_code = 200
    batch_resp.json.return_value = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-test-1234",
                        "summary": "Test vuln",
                        "database_specific": {"severity": "CRITICAL"},
                        "affected": [
                            {
                                "package": {"name": "requests", "ecosystem": "PyPI"},
                                "ranges": [{"events": [{"fixed": "2.32.0"}]}],
                            }
                        ],
                    }
                ]
            }
        ]
    }

    with patch("vuln_scanner.osv_client.requests.post", return_value=batch_resp):
        results = scan_dependencies(tmp_path, use_cache=False)

    assert len(results) == 1
    assert results[0]["package"] == "requests"
    assert results[0]["severity"] == "CRITICAL"
    assert results[0]["vulns"][0]["fixed_version"] == "2.32.0"
