"""HTML pentest report builder using Jinja2 templates."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

try:
    import jinja2
except ImportError:
    jinja2 = None  # type: ignore[assignment]


_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ engagement.name | e }} — Pentest Report</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;
--accent:#58a6ff;--critical:#f85149;--high:#f0883e;--medium:#d29922;--low:#3fb950;}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}
.container{max-width:1100px;margin:0 auto}
h1{font-size:1.8rem;margin-bottom:.5rem}
h2{font-size:1.3rem;margin:2rem 0 1rem;padding-bottom:.4rem;border-bottom:1px solid var(--border)}
h3{font-size:1.1rem;margin:1.2rem 0 .6rem}
table{width:100%;border-collapse:collapse;margin-bottom:1.5rem}
th,td{text-align:left;padding:.55rem .75rem;border:1px solid var(--border)}
th{background:var(--surface);font-weight:600;cursor:pointer}
th:hover{color:var(--accent)}
tr:nth-child(even){background:rgba(22,27,34,.5)}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:3px;font-size:.75rem;font-weight:700;text-transform:uppercase}
.badge-critical{background:var(--critical);color:#fff}
.badge-high{background:var(--high);color:#fff}
.badge-medium{background:var(--medium);color:#000}
.badge-low{background:var(--low);color:#000}
.stats{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}
.stat-box{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:1rem 1.4rem;min-width:140px}
.stat-box .label{font-size:.8rem;color:var(--muted)}
.stat-box .value{font-size:1.6rem;font-weight:700}
.scope-list{list-style:none;padding:0}
.scope-list li{padding:.3rem 0;font-family:monospace;font-size:.9rem}
.parsed-block{background:var(--surface);border:1px solid var(--border);border-radius:4px;
padding:.75rem;margin:.5rem 0;font-family:monospace;font-size:.82rem;white-space:pre-wrap;
max-height:250px;overflow-y:auto}
.remediation{background:#1a2332;border-left:3px solid var(--accent);padding:.6rem .9rem;margin:.5rem 0;font-size:.9rem}
.meta{color:var(--muted);font-size:.85rem;margin-bottom:1.5rem}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--muted);font-size:.8rem}
</style>
</head>
<body>
<div class="container">

<h1>{{ engagement.name | e }}</h1>
<p class="meta">
  Engagement ID: <code>{{ engagement.id | e }}</code> &mdash;
  Generated: {{ generated_at }}
  {% if engagement.created_at %} &mdash; Started: {{ engagement.created_at }}{% endif %}
</p>

<h2>Executive Summary</h2>
<div class="stats">
  <div class="stat-box"><div class="label">Total Findings</div><div class="value">{{ findings | length }}</div></div>
  <div class="stat-box"><div class="label">CVEs Correlated</div><div class="value">{{ cves | length }}</div></div>
  {% for sev, count in severity_counts.items() %}
  <div class="stat-box"><div class="label">{{ sev }}</div><div class="value" style="color:var(--{{ sev | lower }})">{{ count }}</div></div>
  {% endfor %}
  <div class="stat-box"><div class="label">Tools Used</div><div class="value">{{ tools_used | length }}</div></div>
</div>

{% if scope %}
<h2>Scope</h2>
{% if scope.allowed_cidrs %}
<h3>Allowed CIDRs</h3>
<ul class="scope-list">{% for c in scope.allowed_cidrs %}<li>{{ c | e }}</li>{% endfor %}</ul>
{% endif %}
{% if scope.allowed_domains %}
<h3>Allowed Domains</h3>
<ul class="scope-list">{% for d in scope.allowed_domains %}<li>{{ d | e }}</li>{% endfor %}</ul>
{% endif %}
{% if scope.excluded_targets %}
<h3>Excluded Targets</h3>
<ul class="scope-list">{% for t in scope.excluded_targets %}<li>{{ t | e }}</li>{% endfor %}</ul>
{% endif %}
{% endif %}

{% if cves %}
<h2>CVE Correlation</h2>
<table>
<thead><tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Host</th><th>Port</th><th>Service</th><th>Description</th></tr></thead>
<tbody>
{% for cve in cves | sort(attribute='cvss_score', reverse=true) %}
<tr>
  <td><code>{{ cve.id | e }}</code></td>
  <td>{{ cve.cvss_score if cve.cvss_score is not none else "N/A" }}</td>
  <td>{% set sev = cve.cvss_severity | default("MEDIUM") | upper %}<span class="badge badge-{{ sev | lower }}">{{ sev }}</span></td>
  <td>{{ cve.host | default("") | e }}</td>
  <td>{{ cve.port | default("") }}</td>
  <td>{{ cve.service | default("") | e }}</td>
  <td>{{ cve.description | default("") | e | truncate(120) }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endif %}

<h2>Findings by Tool</h2>
{% for tool_name in tools_used %}
<h3>{{ tool_name | e }}</h3>
<table>
<thead><tr><th>Target</th><th>Status</th><th>Time</th><th>Summary</th></tr></thead>
<tbody>
{% for f in findings if f.tool == tool_name %}
<tr>
  <td><code>{{ f.target | e }}</code></td>
  <td>{% if f.get("success", true) %}OK{% else %}FAIL{% endif %}</td>
  <td>{{ f.created_at | default("") }}</td>
  <td>{{ summarize_parsed(f) | e | truncate(200) }}</td>
</tr>
{% if f.parsed_output %}
<tr><td colspan="4"><div class="parsed-block">{{ summarize_parsed_detail(f) | e }}</div></td></tr>
{% endif %}
{% if f.remediation %}
{% for rec in f.remediation %}
<tr><td colspan="4"><div class="remediation">{{ rec.remediation | default(rec) | e }}</div></td></tr>
{% endfor %}
{% endif %}
{% endfor %}
</tbody>
</table>
{% endfor %}

<h2>Timeline</h2>
<table>
<thead><tr><th>Time</th><th>Tool</th><th>Target</th></tr></thead>
<tbody>
{% for f in findings | sort(attribute='created_at') %}
<tr>
  <td>{{ f.created_at | default("N/A") }}</td>
  <td>{{ f.tool | e }}</td>
  <td><code>{{ f.target | e }}</code></td>
</tr>
{% endfor %}
</tbody>
</table>

<footer>Generated by Project Astro V2 &mdash; {{ generated_at }}</footer>
</div>
</body>
</html>
"""


def _summarize_parsed(finding: dict[str, Any]) -> str:
    parsed = finding.get("parsed_output") or {}
    tool = finding.get("tool", "")

    if tool == "nmap" and parsed:
        hosts = parsed.get("hosts", [])
        port_count = sum(len(h.get("ports", [])) for h in hosts)
        return f"{len(hosts)} host(s), {port_count} port(s) discovered"

    if tool == "wpscan" and parsed:
        plugins = len(parsed.get("plugins", []))
        users = len(parsed.get("users", []))
        return f"WP {parsed.get('version', '?')}, {plugins} plugin(s), {users} user(s)"

    if tool == "sqlmap" and parsed:
        inj = len(parsed.get("injectable_params", []))
        dbs = len(parsed.get("databases", []))
        return f"{inj} injection point(s), {dbs} database(s)"

    if tool == "hydra" and parsed:
        creds = len(parsed.get("credentials", []))
        return f"{creds} credential(s) found"

    return f"{len(parsed)} field(s)" if parsed else "raw output only"


def _summarize_parsed_detail(finding: dict[str, Any]) -> str:
    parsed = finding.get("parsed_output") or {}
    tool = finding.get("tool", "")

    if tool == "nmap" and parsed:
        lines = []
        for host in parsed.get("hosts", []):
            lines.append(f"Host: {host.get('address', '?')}")
            for port in host.get("ports", []):
                state = port.get("state", "?")
                svc = port.get("service", "?")
                ver = port.get("version", "")
                lines.append(f"  {port.get('port', '?')}/{port.get('protocol', 'tcp')} {state} {svc} {ver}")
        return "\n".join(lines)

    import json
    return json.dumps(parsed, indent=2, default=str)[:2000]


def _count_cve_severities(cves: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for cve in cves:
        sev = (cve.get("cvss_severity") or "MEDIUM").upper()
        if sev in counts:
            counts[sev] += 1
    return {k: v for k, v in counts.items() if v > 0}


class HTMLReportBuilder:
    """Generates HTML pentest reports using Jinja2 templates."""

    def generate(
        self,
        engagement: dict[str, Any],
        findings: list[dict[str, Any]],
        cves: Optional[list[dict[str, Any]]] = None,
    ) -> str:
        if jinja2 is None:
            raise RuntimeError(
                "Jinja2 is required for HTML reports. "
                "Install it with: pip install project-astro[reporting]"
            )

        cves = cves or []
        scope = engagement.get("scope_config") or {}
        if isinstance(scope, str):
            import json
            try:
                scope = json.loads(scope)
            except (json.JSONDecodeError, TypeError):
                scope = {}
        scope = scope.get("scope", scope)

        tools_used = sorted({f.get("tool", "unknown") for f in findings})

        env = jinja2.Environment(autoescape=True, undefined=jinja2.StrictUndefined)
        template = env.from_string(_TEMPLATE)

        return template.render(
            engagement=engagement,
            findings=findings,
            cves=cves,
            scope=scope,
            tools_used=tools_used,
            severity_counts=_count_cve_severities(cves),
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            summarize_parsed=_summarize_parsed,
            summarize_parsed_detail=_summarize_parsed_detail,
        )
