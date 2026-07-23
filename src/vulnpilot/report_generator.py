"""HTML report generator for VulnPilot security scan results."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from vulnpilot.cve_utils import extract_cve_ids
from vulnpilot.models import (
    PackageReport,
    ReportOutput,
    Vulnerability,
)


# ── Priority helpers ─────────────────────────────────────────────


PRIORITY_ORDER = {
    "IMMEDIATE": 0,
    "URGENT": 1,
    "HIGH": 2,
    "NORMAL": 3,
}


def _priority_sort_key(vuln: Vulnerability) -> int:
    return PRIORITY_ORDER.get(vuln.priority, 99)


# ── CSS ──────────────────────────────────────────────────────────


REPORT_CSS = """\
/* ── Reset & Fonts ─────────────────────────────────────── */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root{
  --bg:        #0f0f1a;
  --surface:   #181828;
  --surface-2: #1e1e32;
  --border:    #2a2a45;
  --text:      #e4e4f0;
  --text-dim:  #9090b0;
  --accent:    #7c5cfc;
  --accent-2:  #a78bfa;

  --red:       #ef4444;
  --red-bg:    rgba(239,68,68,.12);
  --orange:    #f59e0b;
  --orange-bg: rgba(245,158,11,.12);
  --yellow:    #eab308;
  --yellow-bg: rgba(234,179,8,.10);
  --green:     #22c55e;
  --green-bg:  rgba(34,197,94,.10);
  --cyan:      #06b6d4;
  --pink:      #ec4899;
}

html{font-size:15px}
body{
  font-family:'Inter',system-ui,-apple-system,sans-serif;
  background:var(--bg);color:var(--text);
  line-height:1.6;padding:2rem 1rem;
  min-height:100vh;
}

/* ── Layout ────────────────────────────────────────────── */
.container{max-width:1280px;margin:0 auto}

.header{
  text-align:center;padding:2.5rem 1rem 1.5rem;
  background:linear-gradient(135deg,#1a103a 0%,#0f0f1a 100%);
  border-radius:16px;border:1px solid var(--border);
  margin-bottom:2rem;position:relative;overflow:hidden;
}
.header::before{
  content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse at 50% 0%,rgba(124,92,252,.15),transparent 70%);
  pointer-events:none;
}
.header h1{
  font-size:2rem;font-weight:800;
  background:linear-gradient(135deg,var(--accent-2),var(--cyan));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;
}
.header .subtitle{color:var(--text-dim);margin-top:.25rem;font-size:.95rem}
.header .meta{color:var(--text-dim);margin-top:.75rem;font-size:.8rem;opacity:.7}

/* ── Summary Cards ─────────────────────────────────────── */
.cards{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:1rem;margin-bottom:2rem;
}
.card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:1.25rem 1.5rem;
  transition:transform .15s ease,box-shadow .15s ease;
}
.card:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.3)}
.card .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:var(--text-dim);font-weight:600}
.card .value{font-size:2rem;font-weight:800;margin-top:.25rem}
.card.immediate .value{color:var(--red)}
.card.urgent    .value{color:var(--orange)}
.card.high      .value{color:var(--yellow)}
.card.normal    .value{color:var(--green)}
.card.total     .value{color:var(--accent-2)}
.card.vuln      .value{color:var(--pink)}

/* ── Risk Gauge ────────────────────────────────────────── */
.risk-gauge{
  display:flex;align-items:center;gap:1rem;
  background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:2rem;
}
.risk-gauge .icon{font-size:2rem}
.risk-gauge .level{font-size:1.2rem;font-weight:700}
.risk-gauge .desc{font-size:.85rem;color:var(--text-dim)}
.risk-critical .level{color:var(--red)}
.risk-high     .level{color:var(--orange)}
.risk-moderate .level{color:var(--yellow)}
.risk-low      .level{color:var(--green)}

/* ── Section Headers ───────────────────────────────────── */
.section-title{
  font-size:1.15rem;font-weight:700;margin:2rem 0 1rem;
  padding-bottom:.5rem;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:.5rem;
}

/* ── Table ─────────────────────────────────────────────── */
.table-wrap{
  overflow-x:auto;border-radius:12px;
  border:1px solid var(--border);margin-bottom:2rem;
}
table{width:100%;border-collapse:collapse;font-size:.85rem}
thead{background:var(--surface-2)}
th{
  padding:.75rem 1rem;text-align:left;font-weight:600;
  color:var(--text-dim);text-transform:uppercase;
  letter-spacing:.05em;font-size:.72rem;
  cursor:pointer;user-select:none;white-space:nowrap;
  border-bottom:2px solid var(--border);
}
th:hover{color:var(--accent-2)}
th .sort-arrow{margin-left:4px;opacity:.4;font-size:.65rem}
td{padding:.7rem 1rem;border-bottom:1px solid var(--border);vertical-align:top}
tbody tr{background:var(--surface);transition:background .1s}
tbody tr:nth-child(even){background:var(--surface-2)}
tbody tr:hover{background:rgba(124,92,252,.08)}

/* ── Badges ────────────────────────────────────────────── */
.badge{
  display:inline-block;padding:2px 10px;border-radius:20px;
  font-size:.72rem;font-weight:600;letter-spacing:.03em;
  text-transform:uppercase;white-space:nowrap;
}
.badge-immediate{background:var(--red-bg);   color:var(--red)}
.badge-urgent   {background:var(--orange-bg);color:var(--orange)}
.badge-high     {background:var(--yellow-bg);color:var(--yellow)}
.badge-normal   {background:rgba(34,197,94,.10);color:var(--green)}
.badge-severity-critical{background:var(--red-bg);color:var(--red)}
.badge-severity-high    {background:var(--orange-bg);color:var(--orange)}
.badge-severity-moderate{background:var(--yellow-bg);color:var(--yellow)}
.badge-severity-low     {background:rgba(34,197,94,.10);color:var(--green)}
.badge-kev{background:rgba(239,68,68,.15);color:var(--red);border:1px solid var(--red)}
.badge-reachable{background:rgba(239,68,68,.10);color:var(--red)}
.badge-test-only{background:rgba(234,179,8,.10);color:var(--yellow)}
.badge-not-used {background:rgba(34,197,94,.08);color:var(--green)}
.badge-unknown  {background:rgba(144,144,176,.10);color:var(--text-dim)}

/* ── Links ─────────────────────────────────────────────── */
a{color:var(--accent-2);text-decoration:none;transition:color .1s}
a:hover{color:var(--cyan);text-decoration:underline}

/* ── Clean list ────────────────────────────────────────── */
.clean-list{list-style:none;padding:0;margin:0}
.clean-list li{padding:.35rem 0;font-size:.8rem}
.clean-list li::before{content:'→ ';color:var(--accent);font-weight:600}

/* ── Package Detail Cards ──────────────────────────────── */
.pkg-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:1.5rem;margin-bottom:1rem;
  transition:border-color .15s;
}
.pkg-card:hover{border-color:var(--accent)}
.pkg-card h3{font-size:1rem;font-weight:700;margin-bottom:.5rem;display:flex;align-items:center;gap:.5rem}
.pkg-card .pkg-meta{font-size:.8rem;color:var(--text-dim);margin-bottom:.75rem}

/* ── Footer ────────────────────────────────────────────── */
.footer{
  text-align:center;padding:2rem 1rem;margin-top:3rem;
  border-top:1px solid var(--border);
  color:var(--text-dim);font-size:.78rem;
}
.footer .brand{
  font-weight:700;
  background:linear-gradient(135deg,var(--accent-2),var(--cyan));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;
}

/* ── No-Vuln Banner ────────────────────────────────────── */
.no-vulns{
  text-align:center;padding:3rem 1rem;
  background:var(--surface);border:1px solid var(--border);
  border-radius:12px;margin:2rem 0;
}
.no-vulns .icon{font-size:3rem;margin-bottom:.5rem}
.no-vulns h2{color:var(--green);font-size:1.3rem;margin-bottom:.25rem}
.no-vulns p{color:var(--text-dim);font-size:.9rem}

/* ── Responsive ────────────────────────────────────────── */
@media(max-width:640px){
  html{font-size:13px}
  .cards{grid-template-columns:repeat(2,1fr)}
  .header h1{font-size:1.5rem}
}
"""


# ── Sorting JS ───────────────────────────────────────────


SORT_JS = """\
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('th[data-sort]').forEach(function(th){
    th.addEventListener('click',function(){
      var table=th.closest('table'),
          tbody=table.querySelector('tbody'),
          rows=Array.from(tbody.querySelectorAll('tr')),
          col=Array.from(th.parentNode.children).indexOf(th),
          asc=th.dataset.dir!=='asc';
      th.parentNode.querySelectorAll('th').forEach(function(h){h.dataset.dir=''});
      th.dataset.dir=asc?'asc':'desc';
      rows.sort(function(a,b){
        var va=a.children[col].getAttribute('data-value')||a.children[col].textContent.trim(),
            vb=b.children[col].getAttribute('data-value')||b.children[col].textContent.trim();
        var na=parseFloat(va),nb=parseFloat(vb);
        if(!isNaN(na)&&!isNaN(nb))return asc?na-nb:nb-na;
        return asc?va.localeCompare(vb):vb.localeCompare(va);
      });
      rows.forEach(function(r){tbody.appendChild(r)});
    });
  });
});
"""


# ── HTML builders ────────────────────────────────────────


def _severity_badge(severity: str | None) -> str:
    if not severity:
        return '<span class="badge badge-unknown">N/A</span>'
    sev = severity.upper()
    css_map = {
        "CRITICAL": "badge-severity-critical",
        "HIGH": "badge-severity-high",
        "MODERATE": "badge-severity-moderate",
        "MEDIUM": "badge-severity-moderate",
        "LOW": "badge-severity-low",
    }
    cls = css_map.get(sev, "badge-unknown")
    return f'<span class="badge {cls}">{_html_escape(severity)}</span>'


def _priority_badge(priority: str) -> str:
    cls_map = {
        "IMMEDIATE": "badge-immediate",
        "URGENT": "badge-urgent",
        "HIGH": "badge-high",
        "NORMAL": "badge-normal",
    }
    cls = cls_map.get(priority, "badge-unknown")
    return f'<span class="badge {cls}">{_html_escape(priority)}</span>'


def _reachability_badge(pkg: PackageReport) -> str:
    r = pkg.reachability
    if r is None:
        return '<span class="badge badge-unknown">Not analyzed</span>'
    if r.production_usage_found:
        return '<span class="badge badge-reachable">Production</span>'
    if r.test_only:
        return '<span class="badge badge-test-only">Test only</span>'
    if not r.usage_found:
        return '<span class="badge badge-not-used">Not used</span>'
    return '<span class="badge badge-unknown">Unknown</span>'


def _kev_badge(vuln: Vulnerability) -> str:
    if vuln.exploit_intelligence.known_exploited:
        return '<span class="badge badge-kev">⚠ KEV</span>'
    return '<span class="badge badge-unknown">No</span>'


def _epss_display(vuln: Vulnerability) -> str:
    prob = vuln.exploit_intelligence.epss_probability
    if prob is None:
        return "—"
    pct = prob * 100
    return f"{pct:.1f}%"


def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _fix_versions_display(vuln: Vulnerability) -> str:
    if not vuln.fixed_versions:
        return '<span style="color:var(--text-dim)">No fix available</span>'
    return ", ".join(
        f"<code>{_html_escape(v)}</code>"
        for v in vuln.fixed_versions[:3]
    )


def _vuln_id_link(vuln: Vulnerability) -> str:
    if vuln.references:
        url = vuln.references[0]
        return f'<a href="{_html_escape(url)}" target="_blank" rel="noopener">{_html_escape(vuln.id)}</a>'
    return _html_escape(vuln.id)


def _cve_display(vuln: Vulnerability) -> str:
    cve_ids = extract_cve_ids(vuln)
    if not cve_ids:
        return "—"
    return ", ".join(cve_ids[:2])


def _overall_risk(
    immediate: int, urgent: int, high: int,
) -> tuple[str, str, str, str]:
    """Return (css_class, icon, level, description)."""
    if immediate > 0:
        return (
            "risk-critical",
            "🔴",
            "CRITICAL",
            "Actively exploited vulnerabilities require immediate remediation.",
        )
    if urgent > 0:
        return (
            "risk-high",
            "🟠",
            "HIGH",
            "High-probability exploits detected in reachable code.",
        )
    if high > 0:
        return (
            "risk-moderate",
            "🟡",
            "MODERATE",
            "Critical-severity vulnerabilities present in production dependencies.",
        )
    return (
        "risk-low",
        "🟢",
        "LOW",
        "No high-priority vulnerabilities detected.",
    )


def _scope_display(pkg: PackageReport) -> str:
    scope = pkg.dependency_scope
    if scope == "production":
        return "Production"
    if scope == "development":
        return "Development"
    return "Unknown"


def _action_text(vuln: Vulnerability) -> str:
    if vuln.exploit_intelligence.known_exploited:
        return "Patch immediately — actively exploited"
    if vuln.priority == "URGENT":
        return "Upgrade this sprint"
    if vuln.priority == "HIGH":
        return "Plan for next release"
    if vuln.fixed_versions:
        return f"Upgrade to {vuln.fixed_versions[0]}"
    return "Monitor for updates"


# ── Main generator ───────────────────────────────────────


def generate_html_report(
    packages: list[PackageReport],
    project_name: str = "Project",
    ecosystem: str = "PyPI",
) -> str:
    """Generate a self-contained HTML security report.

    Args:
        packages: List of PackageReport items with check and
            reachability results already populated.
        project_name: Human-readable project name for the header.
        ecosystem: Ecosystem label for the header.

    Returns:
        A complete HTML document as a string.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Compute stats ────────────────────────────────────
    total_packages = len(packages)
    vulnerable_packages = sum(
        1 for p in packages if p.check_result.vulnerable
    )
    all_vulns: list[tuple[PackageReport, Vulnerability]] = []
    for pkg in packages:
        for vuln in pkg.check_result.vulnerabilities:
            all_vulns.append((pkg, vuln))

    all_vulns.sort(key=lambda pv: _priority_sort_key(pv[1]))

    total_vulns = len(all_vulns)
    immediate = sum(1 for _, v in all_vulns if v.priority == "IMMEDIATE")
    urgent = sum(1 for _, v in all_vulns if v.priority == "URGENT")
    high = sum(1 for _, v in all_vulns if v.priority == "HIGH")
    normal = sum(1 for _, v in all_vulns if v.priority == "NORMAL")

    risk_cls, risk_icon, risk_level, risk_desc = _overall_risk(
        immediate, urgent, high,
    )

    # ── Build HTML pieces ────────────────────────────────
    cards_html = f"""\
<div class="cards">
  <div class="card total">
    <div class="label">Total Packages</div>
    <div class="value">{total_packages}</div>
  </div>
  <div class="card vuln">
    <div class="label">Vulnerable</div>
    <div class="value">{vulnerable_packages}</div>
  </div>
  <div class="card immediate">
    <div class="label">Immediate</div>
    <div class="value">{immediate}</div>
  </div>
  <div class="card urgent">
    <div class="label">Urgent</div>
    <div class="value">{urgent}</div>
  </div>
  <div class="card high">
    <div class="label">High</div>
    <div class="value">{high}</div>
  </div>
  <div class="card normal">
    <div class="label">Normal</div>
    <div class="value">{normal}</div>
  </div>
</div>"""

    gauge_html = f"""\
<div class="risk-gauge {risk_cls}">
  <div class="icon">{risk_icon}</div>
  <div>
    <div class="level">Overall Risk: {risk_level}</div>
    <div class="desc">{risk_desc}</div>
  </div>
</div>"""

    # ── Vulnerability table ──────────────────────────────
    if total_vulns == 0:
        table_html = """\
<div class="no-vulns">
  <div class="icon">🛡️</div>
  <h2>All Clear</h2>
  <p>No known vulnerabilities were found in the scanned packages.</p>
</div>"""
    else:
        rows: list[str] = []
        for pkg, vuln in all_vulns:
            cr = pkg.check_result
            priority_val = PRIORITY_ORDER.get(vuln.priority, 99)
            rows.append(f"""\
    <tr>
      <td>{_html_escape(cr.package_name)}</td>
      <td><code>{_html_escape(cr.version)}</code></td>
      <td>{_vuln_id_link(vuln)}</td>
      <td>{_cve_display(vuln)}</td>
      <td>{_severity_badge(vuln.severity)}</td>
      <td data-value="{priority_val}">{_priority_badge(vuln.priority)}</td>
      <td data-value="{vuln.exploit_intelligence.epss_probability or 0}">{_epss_display(vuln)}</td>
      <td>{_kev_badge(vuln)}</td>
      <td>{_reachability_badge(pkg)}</td>
      <td>{_scope_display(pkg)}</td>
      <td>{_fix_versions_display(vuln)}</td>
      <td style="font-size:.78rem;color:var(--text-dim)">{_html_escape(_action_text(vuln))}</td>
    </tr>""")

        table_html = f"""\
<div class="section-title">📋 Vulnerability Details</div>
<div class="table-wrap">
<table>
  <thead>
    <tr>
      <th data-sort>Package <span class="sort-arrow">▲▼</span></th>
      <th data-sort>Version <span class="sort-arrow">▲▼</span></th>
      <th data-sort>Vuln ID <span class="sort-arrow">▲▼</span></th>
      <th>CVE</th>
      <th data-sort>Severity <span class="sort-arrow">▲▼</span></th>
      <th data-sort>Priority <span class="sort-arrow">▲▼</span></th>
      <th data-sort>EPSS <span class="sort-arrow">▲▼</span></th>
      <th>CISA KEV</th>
      <th>Reachability</th>
      <th>Scope</th>
      <th>Fix Versions</th>
      <th>Recommended Action</th>
    </tr>
  </thead>
  <tbody>
{"".join(rows)}
  </tbody>
</table>
</div>"""

    # ── Package detail cards ─────────────────────────────
    detail_cards: list[str] = []
    for pkg in packages:
        cr = pkg.check_result
        if not cr.vulnerable:
            continue
        vuln_badges = " ".join(
            _priority_badge(v.priority)
            for v in sorted(
                cr.vulnerabilities,
                key=_priority_sort_key,
            )
        )
        reach = _reachability_badge(pkg)
        scope = _scope_display(pkg)
        detail_cards.append(f"""\
<div class="pkg-card">
  <h3>{_html_escape(cr.package_name)} <code>{_html_escape(cr.version)}</code></h3>
  <div class="pkg-meta">{cr.ecosystem} · {scope} · {reach} · {cr.vulnerability_count} vuln(s)</div>
  <div>{vuln_badges}</div>
</div>""")

    details_html = ""
    if detail_cards:
        details_html = (
            '<div class="section-title">📦 Vulnerable Packages</div>\n'
            + "\n".join(detail_cards)
        )

    # ── Assemble full HTML ───────────────────────────────
    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VulnPilot Report — {_html_escape(project_name)}</title>
  <style>{REPORT_CSS}</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>🛡️ VulnPilot Security Report</h1>
    <div class="subtitle">{_html_escape(project_name)} · {_html_escape(ecosystem)}</div>
    <div class="meta">Generated {now}</div>
  </div>

  {cards_html}
  {gauge_html}
  {table_html}
  {details_html}

  <div class="footer">
    Powered by <span class="brand">VulnPilot</span> · Data from OSV, EPSS &amp; CISA KEV · {now}
  </div>

</div>
<script>{SORT_JS}</script>
</body>
</html>"""

    return html


def save_report(
    html: str,
    output_dir: str,
    filename: str | None = None,
) -> str:
    """Write the HTML report to disk and return the absolute path.

    Args:
        html: The full HTML report string.
        output_dir: Directory to write the report into
            (created if it doesn't exist).
        filename: Optional filename. Defaults to
            ``vulnpilot-report-{timestamp}.html``.

    Returns:
        The absolute path of the saved file.
    """
    if filename is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"vulnpilot-report-{ts}.html"

    dir_path = Path(output_dir)
    dir_path.mkdir(parents=True, exist_ok=True)

    file_path = dir_path / filename
    file_path.write_text(html, encoding="utf-8")

    return str(file_path.resolve())


def build_report(
    packages: list[PackageReport],
    project_name: str = "Project",
    ecosystem: str = "PyPI",
    output_dir: str = ".vulnpilot",
) -> ReportOutput:
    """High-level entry point: generate + save + return stats.

    This is the function called by the MCP tool handler.
    """
    html = generate_html_report(
        packages=packages,
        project_name=project_name,
        ecosystem=ecosystem,
    )

    report_path = save_report(html, output_dir)

    all_vulns = [
        v
        for p in packages
        for v in p.check_result.vulnerabilities
    ]

    return ReportOutput(
        report_html=html,
        report_path=report_path,
        total_packages=len(packages),
        vulnerable_packages=sum(
            1 for p in packages if p.check_result.vulnerable
        ),
        total_vulnerabilities=len(all_vulns),
        immediate_count=sum(
            1 for v in all_vulns if v.priority == "IMMEDIATE"
        ),
        urgent_count=sum(
            1 for v in all_vulns if v.priority == "URGENT"
        ),
        high_count=sum(
            1 for v in all_vulns if v.priority == "HIGH"
        ),
        normal_count=sum(
            1 for v in all_vulns if v.priority == "NORMAL"
        ),
    )
