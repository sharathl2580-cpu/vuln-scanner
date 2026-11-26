from datetime import datetime, timezone
import socket
import ssl
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

WEB_REMEDIATIONS = {
    "WEB000": "Verify the target URL is reachable and DNS/TLS are properly configured.",
    "WEB001": "Serve the site over HTTPS and redirect all HTTP traffic to HTTPS.",
    "WEB002": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    "WEB003": "Define a Content-Security-Policy header to mitigate XSS and data injection.",
    "WEB004": "Set X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors.",
    "WEB005": "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
    "WEB006": "Remove or obfuscate Server / X-Powered-By version headers.",
    "WEB007": "Set HttpOnly and Secure flags on all session/sensitive cookies.",
    "WEB008": "Renew or fix the TLS certificate and disable TLS versions below 1.2.",
    "WEB009": "Do not reflect arbitrary Origin headers or combine Access-Control-Allow-Origin: * with credentials.",
    "WEB010": "Add Referrer-Policy (e.g. strict-origin-when-cross-origin) and Permissions-Policy headers.",
    "WEB011": "Block public access to sensitive files/endpoints (/.env, /.git, /actuator, /swagger.json).",
    "WEB012": "Publish a /.well-known/security.txt contact policy for vulnerability disclosures.",
    "WEB013": "Disable dangerous HTTP methods (TRACE, PUT) on public web servers.",
    "WEB014": "Renew the TLS certificate before expiration (automate with ACME/Certbot).",
    "WEB015": "Validate redirect targets against an allowlist to prevent Open Redirect vulnerabilities.",
    "WEB016": "Disable GraphQL schema introspection in production environments.",
    "WEB017": "Disable verbose debug error pages and stack traces in production.",
    "WEB018": "HTML-encode or sanitize reflected query parameters before rendering.",
    "DNS001": "Publish an SPF TXT record (e.g. 'v=spf1 ... -all') to prevent email spoofing.",
    "DNS002": "Publish a DMARC TXT record at _dmarc.<domain> (e.g. 'v=DMARC1; p=quarantine;').",
    "DNS003": "Remove dangling CNAME DNS records or claim the target cloud resource immediately.",
}

TAKEOVER_SIGNATURES = {
    ".s3.amazonaws.com": "NoSuchBucket",
    ".github.io": "There isn't a GitHub Pages site here",
    ".herokuapp.com": "No such app",
    ".azurewebsites.net": "404 Web Site not found",
}

COMMON_SUBDOMAINS = ("www", "api", "dev", "staging", "blog", "app")

EXPOSED_PATHS = [
    ("/.env", "=", "Exposed .env file on web root"),
    ("/.git/HEAD", "ref:", "Exposed .git/HEAD repository metadata"),
    ("/actuator/env", "{", "Exposed Spring Boot /actuator/env endpoint"),
    ("/swagger.json", "swagger", "Publicly exposed Swagger/OpenAPI specification"),
]

ERROR_SIGNATURES = (
    "Traceback (most recent call last)",
    "SQL syntax",
    "sqlite3.OperationalError",
    "SyntaxError:",
    "at Object.<anonymous>",
)


def _check_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> List[tuple]:
    """Return list of (rule_id, severity, message) for TLS issues and certificate expiry."""
    issues: List[tuple] = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                proto = ssock.version() or ""
                if proto in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
                    issues.append(("WEB008", "HIGH", f"Deprecated TLS protocol negotiated: {proto}"))
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter") if isinstance(cert, dict) else None
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (exp - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        issues.append(("WEB014", "CRITICAL", f"TLS certificate expired {abs(days_left)} days ago"))
                    elif days_left <= 30:
                        issues.append(("WEB014", "MEDIUM", f"TLS certificate expires in {days_left} days"))
    except ssl.SSLError as exc:
        issues.append(("WEB008", "HIGH", f"TLS certificate/handshake error: {exc}"))
    except OSError:
        pass
    return issues


def scan_domain_posture(domain: str, timeout: int = 6, check_takeover: bool = True) -> List[Dict]:
    """Audit SPF, DMARC, and subdomain takeover DNS posture via DNS-over-HTTPS."""
    findings: List[Dict] = []

    def _query_dns(name: str, qtype: str, rtype_num: int) -> List[str]:
        try:
            r = requests.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": name, "type": qtype},
                headers={"Accept": "application/dns-json"},
                timeout=timeout,
            )
            if r.status_code != 200:
                return []
            return [
                str(ans.get("data", "")).strip('"')
                for ans in r.json().get("Answer", [])
                if ans.get("type") == rtype_num
            ]
        except Exception:
            return []

    root_txt = _query_dns(domain, "TXT", 16)
    if not any("v=spf1" in t.lower() for t in root_txt):
        findings.append({
            "category": "dns",
            "rule_id": "DNS001",
            "severity": "MEDIUM",
            "file": domain,
            "line": 1,
            "message": f"Domain '{domain}' is missing an SPF (v=spf1) TXT record",
            "match": "SPF missing",
            "remediation": WEB_REMEDIATIONS["DNS001"],
        })

    dmarc_txt = _query_dns(f"_dmarc.{domain}", "TXT", 16)
    if not any("v=dmarc1" in t.lower() for t in dmarc_txt):
        findings.append({
            "category": "dns",
            "rule_id": "DNS002",
            "severity": "MEDIUM",
            "file": f"_dmarc.{domain}",
            "line": 1,
            "message": f"Domain '{domain}' is missing a DMARC (v=DMARC1) TXT record",
            "match": "DMARC missing",
            "remediation": WEB_REMEDIATIONS["DNS002"],
        })

    if check_takeover:
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            cnames = _query_dns(fqdn, "CNAME", 5)
            for target in cnames:
                clean_target = target.rstrip(".").lower()
                for suffix, sig in TAKEOVER_SIGNATURES.items():
                    if clean_target.endswith(suffix):
                        try:
                            resp = requests.get(f"https://{fqdn}", timeout=timeout)  # nosec SAST013
                            if sig in (getattr(resp, "text", "") or ""):
                                findings.append({
                                    "category": "dns",
                                    "rule_id": "DNS003",
                                    "severity": "CRITICAL",
                                    "file": fqdn,
                                    "line": 1,
                                    "message": f"Potential subdomain takeover: {fqdn} CNAME -> {clean_target}",
                                    "match": f"CNAME {clean_target} ({sig})",
                                    "remediation": WEB_REMEDIATIONS["DNS003"],
                                })
                        except Exception:
                            pass

    return findings


def scan_url(
    url: str,
    timeout: int = 10,
    recon: bool = True,
    active_web: bool = False,
) -> List[Dict]:
    """Perform HTTP header, CORS, TLS, recon, and optional safe active DAST probes."""
    findings: List[Dict] = []

    def _add(rule_id: str, severity: str, message: str, match: str) -> None:
        findings.append({
            "category": "web",
            "rule_id": rule_id,
            "severity": severity,
            "file": url,
            "line": 1,
            "message": message,
            "match": match,
            "remediation": WEB_REMEDIATIONS[rule_id],
        })

    if url.lower().startswith("http://"):
        _add("WEB001", "HIGH", "Target URL uses unencrypted HTTP instead of HTTPS", url)

    parsed = urlparse(url)
    if parsed.scheme.lower() == "https" and parsed.hostname:
        for rule_id, sev, msg in _check_tls(parsed.hostname, parsed.port or 443):
            _add(rule_id, sev, msg, parsed.hostname)

    try:
        resp = requests.get(  # nosec SAST013
            url,
            headers={"Origin": "https://evil.example"},
            timeout=timeout,
            allow_redirects=True,
        )
    except Exception as exc:
        _add("WEB000", "LOW", f"Could not reach target URL: {exc}", url)
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    final_is_https = resp.url.lower().startswith("https://")

    if final_is_https and "strict-transport-security" not in headers:
        _add("WEB002", "MEDIUM", "Missing Strict-Transport-Security (HSTS) header", "HSTS missing")

    csp = headers.get("content-security-policy", "")
    if not csp:
        _add("WEB003", "MEDIUM", "Missing Content-Security-Policy (CSP) header", "CSP missing")

    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        _add("WEB004", "LOW", "Missing clickjacking protection (X-Frame-Options / frame-ancestors)", "X-Frame-Options missing")

    if headers.get("x-content-type-options", "").lower() != "nosniff":
        _add("WEB005", "LOW", "Missing X-Content-Type-Options: nosniff header", "nosniff missing")

    for hdr in ("server", "x-powered-by"):
        if hdr in headers:
            _add("WEB006", "LOW", f"Server technology disclosed via '{hdr}' header", f"{hdr}: {headers[hdr]}")

    set_cookie = resp.headers.get("Set-Cookie", "")
    if set_cookie:
        lower_cookie = set_cookie.lower()
        if "httponly" not in lower_cookie or (final_is_https and "secure" not in lower_cookie):
            _add("WEB007", "MEDIUM", "Set-Cookie header missing HttpOnly or Secure attribute", set_cookie[:120])

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "https://evil.example" or (acao == "*" and acac == "true"):
        _add("WEB009", "HIGH", "Insecure CORS configuration reflects arbitrary Origin or allows credentials with *", f"ACAO: {acao}")

    if "referrer-policy" not in headers or "permissions-policy" not in headers:
        _add("WEB010", "LOW", "Missing Referrer-Policy or Permissions-Policy header", "Privacy headers missing")

    base_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else url

    if recon:
        for path, signature, msg in EXPOSED_PATHS:
            target = urljoin(base_origin, path)
            try:
                r = requests.get(target, timeout=5, allow_redirects=False)  # nosec SAST013
                if getattr(r, "status_code", 0) == 200 and signature in (getattr(r, "text", "") or ""):
                    _add("WEB011", "CRITICAL", msg, target)
            except Exception:
                pass

        try:
            sec_txt = requests.get(urljoin(base_origin, "/.well-known/security.txt"), timeout=5, allow_redirects=False)  # nosec SAST013
            if getattr(sec_txt, "status_code", 200) >= 400:
                _add("WEB012", "LOW", "Missing /.well-known/security.txt disclosure policy", "/.well-known/security.txt")
        except Exception:
            pass

        try:
            opt = requests.options(url, timeout=5)
            allow = {m.strip().upper() for m in getattr(opt, "headers", {}).get("Allow", "").split(",") if m.strip()}
            risky = allow & {"TRACE", "PUT"}
            if risky:
                _add("WEB013", "MEDIUM", f"Risky HTTP methods enabled: {', '.join(sorted(risky))}", ", ".join(sorted(risky)))
        except Exception:
            pass

    if active_web:
        # WEB015: Safe Open Redirect probe
        sep = "&" if "?" in url else "?"
        try:
            redir = requests.get(f"{url}{sep}next=https://evil.example", timeout=5, allow_redirects=False)  # nosec SAST013
            loc = getattr(redir, "headers", {}).get("Location", "")
            if getattr(redir, "status_code", 0) in {301, 302, 303, 307, 308} and "evil.example" in loc:
                _add("WEB015", "HIGH", "Open Redirect vulnerability detected via 'next' parameter", loc)
        except Exception:
            pass

        # WEB016: GraphQL introspection probe
        try:
            gql = requests.post(  # nosec SAST013
                urljoin(base_origin, "/graphql"),
                json={"query": "{__schema{types{name}}}"},
                timeout=5,
            )
            if getattr(gql, "status_code", 0) == 200 and "__schema" in (getattr(gql, "text", "") or ""):
                _add("WEB016", "MEDIUM", "GraphQL introspection is enabled in production", "/graphql")
        except Exception:
            pass

        # WEB017: Stack-trace / debug error leak probe
        try:
            err_resp = requests.get(f"{url}{sep}id='\"", timeout=5, allow_redirects=True)  # nosec SAST013
            body = getattr(err_resp, "text", "") or ""
            for sig in ERROR_SIGNATURES:
                if sig in body:
                    _add("WEB017", "HIGH", f"Verbose error/stack-trace leaked in response ({sig})", sig)
                    break
        except Exception:
            pass

        # WEB018: Unescaped reflected canary probe
        canary = "vulnscannercanary987<>"
        try:
            ref_resp = requests.get(f"{url}{sep}q={canary}", timeout=5, allow_redirects=True)  # nosec SAST013
            if canary in (getattr(ref_resp, "text", "") or ""):
                _add("WEB018", "MEDIUM", "Reflected unescaped input detected in query response (potential XSS)", "q=canary")
        except Exception:
            pass

    return findings
