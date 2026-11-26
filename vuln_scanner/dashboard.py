from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse
import webbrowser

from vuln_scanner.reporting import (
    format_cyclonedx,
    format_html,
    format_json,
    format_markdown,
    format_sarif,
)


def build_dashboard_html(report: Dict[str, List[Dict]]) -> str:
    """Return an interactive HTML dashboard with live filtering and report downloads."""
    payload = json.dumps(report)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>vuln-scanner Security Dashboard</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #0b1120; color: #e2e8f0; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }}
  .controls {{ display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem; }}
  input, select, button, a.btn {{ padding: 0.5rem 0.85rem; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: #f8fafc; text-decoration: none; font-size: 0.875rem; cursor: pointer; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }}
  .card {{ background: #1e293b; padding: 1rem; border-radius: 8px; border: 1px solid #334155; }}
  .card h3 {{ margin: 0 0 0.25rem; font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; }}
  .card div {{ font-size: 1.5rem; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #334155; font-size: 0.88rem; vertical-align: top; }}
  th {{ background: #0f172a; color: #94a3b8; }}
  .badge {{ padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }}
  .critical {{ background: #991b1b; color: #fecaca; }}
  .high {{ background: #9a3412; color: #fed7aa; }}
  .medium {{ background: #854d0e; color: #fef08a; }}
  .low {{ background: #1e40af; color: #bfdbfe; }}
</style>
</head>
<body>
  <div class="header">
    <h1>vuln-scanner Security Dashboard</h1>
    <div class="controls">
      <a class="btn" href="/api/export?format=sarif" download="results.sarif">Download SARIF</a>
      <a class="btn" href="/api/export?format=cyclonedx" download="sbom.json">Download CycloneDX</a>
      <a class="btn" href="/api/export?format=markdown" download="report.md">Download Markdown</a>
      <a class="btn" href="/api/export?format=json" download="report.json">Download JSON</a>
    </div>
  </div>
  <div class="cards" id="cards"></div>
  <div class="controls">
    <input id="search" type="search" placeholder="Search rule, file, or message..." oninput="render()" />
    <select id="sevFilter" onchange="render()">
      <option value="">All Severities</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="HIGH">HIGH</option>
      <option value="MEDIUM">MEDIUM</option>
      <option value="LOW">LOW</option>
    </select>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Location</th><th>Message</th><th>Remediation</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
<script>
const REPORT = {payload};
const ITEMS = [];
for (const dep of (REPORT.dependencies || [])) {{
  for (const v of (dep.vulns || [])) {{
    ITEMS.push({{
      severity: (v.resolved_severity || dep.severity || "HIGH").toUpperCase(),
      rule: v.id || "OSV",
      category: "dependency",
      location: dep.file,
      message: `${{dep.package}} (${{dep.version}}): ${{v.summary || ""}}`,
      remediation: v.fixed_version ? `Upgrade to ${{v.fixed_version}}` : "Check OSV advisory"
    }});
  }}
}}
for (const [sec, list] of Object.entries(REPORT)) {{
  if (sec === "dependencies") continue;
  for (const it of (list || [])) {{
    ITEMS.push({{
      severity: (it.severity || "LOW").toUpperCase(),
      rule: it.rule_id || "",
      category: sec,
      location: `${{it.file}}:${{it.line || 1}}`,
      message: it.message || "",
      remediation: it.remediation || ""
    }});
  }}
}}
function esc(s) {{ return String(s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c])); }}
function render() {{
  const q = document.getElementById("search").value.toLowerCase();
  const sev = document.getElementById("sevFilter").value;
  const counts = {{CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0}};
  ITEMS.forEach(i => {{ if (counts[i.severity] !== undefined) counts[i.severity]++; }});
  document.getElementById("cards").innerHTML = `<div class="card"><h3>Total</h3><div>${{ITEMS.length}}</div></div>` +
    Object.entries(counts).map(([k, v]) => `<div class="card"><h3>${{k}}</h3><div>${{v}}</div></div>`).join("");
  const filtered = ITEMS.filter(i => (!sev || i.severity === sev) && (!q || `${{i.rule}} ${{i.location}} ${{i.message}}`.toLowerCase().includes(q)));
  document.getElementById("rows").innerHTML = filtered.length
    ? filtered.map(i => `<tr><td><span class="badge ${{i.severity.toLowerCase()}}">${{esc(i.severity)}}</span></td><td>${{esc(i.rule)}}</td><td>${{esc(i.category)}}</td><td>${{esc(i.location)}}</td><td>${{esc(i.message)}}</td><td>${{esc(i.remediation)}}</td></tr>`).join("")
    : `<tr><td colspan="6">No matching findings.</td></tr>`;
}}
render();
</script>
</body>
</html>"""


def make_dashboard_handler(report: Dict[str, List[Dict]], root_path: Optional[Path] = None):
    dashboard_html = build_dashboard_html(report)

    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return  # keep CLI output clean

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/api/report":
                body = format_json(report).encode("utf-8")
                ctype = "application/json; charset=utf-8"
            elif parsed.path == "/api/export":
                fmt = parse_qs(parsed.query).get("format", ["json"])[0]
                if fmt == "sarif":
                    body = format_sarif(report).encode("utf-8")
                    ctype = "application/json; charset=utf-8"
                elif fmt == "cyclonedx":
                    body = format_cyclonedx(report, root_path).encode("utf-8")
                    ctype = "application/json; charset=utf-8"
                elif fmt == "markdown":
                    body = format_markdown(report).encode("utf-8")
                    ctype = "text/markdown; charset=utf-8"
                elif fmt == "html":
                    body = format_html(report).encode("utf-8")
                    ctype = "text/html; charset=utf-8"
                else:
                    body = format_json(report).encode("utf-8")
                    ctype = "application/json; charset=utf-8"
            else:
                body = dashboard_html.encode("utf-8")
                ctype = "text/html; charset=utf-8"

            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return DashboardHandler


def serve_dashboard(
    report: Dict[str, List[Dict]],
    root_path: Optional[Path] = None,
    host: str = "127.0.0.1",
    port: int = 8443,
    open_browser: bool = True,
) -> None:
    """Start a local HTTP server presenting the interactive security dashboard."""
    server = ThreadingHTTPServer((host, port), make_dashboard_handler(report, root_path))
    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}/"
    print(f"Serving vuln-scanner dashboard at {url} (Ctrl+C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
