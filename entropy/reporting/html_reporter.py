""""Self-contained HTML report generator."""
from __future__ import annotations

import html as _html
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from entropy.core.models import EntropyReport, Finding, Severity


def _e(text) -> str:
    """HTML-escape a value; safe for insertion into HTML attributes and text."""
    return _html.escape(str(text or ""), quote=True)


_SEV_COLOR = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH:     "#ea580c",
    Severity.MEDIUM:   "#ca8a04",
    Severity.LOW:      "#16a34a",
    Severity.INFO:     "#2563eb",
}

_SEV_BG = {
    Severity.CRITICAL: "#fef2f2",
    Severity.HIGH:     "#fff7ed",
    Severity.MEDIUM:   "#fefce8",
    Severity.LOW:      "#f0fdf4",
    Severity.INFO:     "#eff6ff",
}


class HTMLReporter:

    def render(self, report: EntropyReport) -> str:
        summary  = report.summary()
        findings = report.findings
        duration = ""
        if report.finished_at:
            secs     = (report.finished_at - report.started_at).total_seconds()
            duration = f"{secs:.1f}s"

        findings_html = "\n".join(self._finding_card(f, i) for i, f in enumerate(findings))
        chart_data    = json.dumps([summary.get(s.value, 0) for s in Severity])
        stats_json    = json.dumps(report.stats or {})

        findings_js = json.dumps([{"id": f.id, "type": f.type.value, "severity": f.severity.value, "title": f.title, "endpoint": f.endpoint, "persona": f.persona} for f in findings])

        return f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🌪️ Entropy Report — {report.target}</title>
<style>
:root {{
  --bg: #f8fafc; --surface: #fff; --border: #e2e8f0;
  --text: #1e293b; --muted: #64748b;
  --shadow: 0 1px 3px rgba(0,0,0,.1);
}}
[data-theme=dark] {{
  --bg:#0f172a;--surface:#1e293b;--border:#334155;--text:#f1f5f9;--muted:#94a3b8;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.6}}
header{{background:linear-gradient(135deg,#1e293b,#0f172a);color:#fff;padding:2rem}}
header h1{{font-size:1.75rem;display:flex;align-items:center;gap:.5rem}}
header .meta{{margin-top:.75rem;display:flex;gap:2rem;flex-wrap:wrap;font-size:.875rem;opacity:.8}}
.container{{max-width:1200px;margin:0 auto;padding:1.5rem}}
.dashboard{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}}
.stat-card{{background:var(--surface);border:1px solid var(--border);border-radius:.75rem;padding:1.25rem;text-align:center;box-shadow:var(--shadow)}}
.stat-card .count{{font-size:2.5rem;font-weight:700;line-height:1}}
.stat-card .label{{font-size:.8rem;color:var(--muted);margin-top:.25rem;text-transform:uppercase;letter-spacing:.05em}}
.filters{{background:var(--surface);border:1px solid var(--border);border-radius:.75rem;padding:1rem;margin-bottom:1.5rem;display:flex;gap:1rem;flex-wrap:wrap;align-items:center}}
.filters input{{flex:1;min-width:200px;padding:.5rem .75rem;border:1px solid var(--border);border-radius:.5rem;background:var(--bg);color:var(--text);font-size:.875rem}}
.filters select{{padding:.5rem .75rem;border:1px solid var(--border);border-radius:.5rem;background:var(--bg);color:var(--text);font-size:.875rem}}
.badge{{display:inline-block;padding:.2rem .6rem;border-radius:9999px;font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em}}
.finding-card{{background:var(--surface);border:1px solid var(--border);border-radius:.75rem;margin-bottom:1rem;overflow:hidden;box-shadow:var(--shadow);transition:box-shadow .2s}}
.finding-card:hover{{box-shadow:0 4px 12px rgba(0,0,0,.15)}}
.finding-header{{padding:1rem 1.25rem;cursor:pointer;display:flex;align-items:flex-start;gap:1rem}}
.finding-header .sev-bar{{width:4px;border-radius:2px;align-self:stretch;flex-shrink:0}}
.finding-header .info{{flex:1}}
.finding-header h3{{font-size:1rem;font-weight:600}}
.finding-header .meta{{font-size:.8rem;color:var(--muted);margin-top:.25rem;display:flex;gap:1rem;flex-wrap:wrap}}
.finding-header .chevron{{transition:transform .2s;color:var(--muted)}}
.finding-header.open .chevron{{transform:rotate(180deg)}}
.finding-body{{display:none;padding:1.25rem;border-top:1px solid var(--border)}}
.finding-body.open{{display:block}}
.section-label{{font-size:.75rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.5rem;margin-top:1rem}}
.section-label:first-child{{margin-top:0}}
.remediation{{background:#f0fdf4;border-left:3px solid #16a34a;padding:.75rem 1rem;border-radius:0 .5rem .5rem 0;font-size:.9rem}}
[data-theme=dark] .remediation{{background:#14532d22}}
.step{{background:var(--bg);border:1px solid var(--border);border-radius:.5rem;padding:.75rem 1rem;margin-bottom:.5rem}}
.step-num{{display:inline-block;background:#3b82f6;color:#fff;border-radius:50%;width:1.5rem;height:1.5rem;text-align:center;font-size:.75rem;line-height:1.5rem;margin-right:.5rem;flex-shrink:0}}
pre{{background:#0f172a;color:#e2e8f0;padding:1rem;border-radius:.5rem;overflow-x:auto;font-size:.8rem;margin-top:.5rem}}
.no-findings{{text-align:center;padding:3rem;color:var(--muted)}}
.no-findings .icon{{font-size:3rem;margin-bottom:1rem}}
.theme-toggle{{position:fixed;bottom:1.5rem;right:1.5rem;background:var(--surface);border:1px solid var(--border);border-radius:50%;width:3rem;height:3rem;cursor:pointer;font-size:1.25rem;display:flex;align-items:center;justify-content:center;box-shadow:var(--shadow)}}
.chart-container{{background:var(--surface);border:1px solid var(--border);border-radius:.75rem;padding:1.5rem;margin-bottom:2rem;display:flex;align-items:center;gap:2rem;flex-wrap:wrap}}
canvas#chart{{max-width:200px;max-height:200px}}
.chart-legend{{display:flex;flex-direction:column;gap:.5rem}}
.legend-item{{display:flex;align-items:center;gap:.75rem;font-size:.875rem}}
.legend-dot{{width:12px;height:12px;border-radius:50%}}
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>🌪️ Entropy Security Report</h1>
    <div class="meta">
      <span>🎯 Target: <strong>{report.target}</strong></span>
      <span>📋 ID: {report.id[:8]}</span>
      <span>📅 {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</span>
      {"<span>⏱️ " + duration + "</span>" if duration else ""}
      <span>🔖 Status: <strong>{report.status.value.upper()}</strong></span>
    </div>
  </div>
</header>

<div class="container">

  <!-- Dashboard -->
  <div class="dashboard">
    {"".join(self._stat_card(s, summary.get(s.value, 0)) for s in Severity)}
    <div class="stat-card">
      <div class="count" style="color:#6366f1">{len(findings)}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="stat-card">
      <div class="count" style="color:#0ea5e9">{(report.stats or {}).get('requests_sent', '–')}</div>
      <div class="label">Requests Sent</div>
    </div>
  </div>

  <!-- Chart -->
  <div class="chart-container">
    <canvas id="chart" width="200" height="200"></canvas>
    <div class="chart-legend">
      {"".join(f'<div class="legend-item"><div class="legend-dot" style="background:{_SEV_COLOR[s]}"></div><span>{s.value.capitalize()}: <strong>{summary.get(s.value, 0)}</strong></span></div>' for s in Severity)}
    </div>
  </div>

  <!-- Filters -->
  <div class="filters">
    <input type="text" id="searchInput" placeholder="🔍 Search findings…" oninput="filterFindings()">
    <select id="sevFilter" onchange="filterFindings()">
      <option value="">All Severities</option>
      {"".join(f'<option value="{s.value}">{s.value.capitalize()}</option>' for s in Severity)}
    </select>
    <select id="typeFilter" onchange="filterFindings()">
      <option value="">All Types</option>
      {"".join(f'<option value="{t}">{t.replace("_"," ").title()}</option>' for t in sorted(set(f.type.value for f in findings)))}
    </select>
  </div>

  <!-- Findings -->
  <div id="findingsList">
    {findings_html if findings_html else '<div class="no-findings"><div class="icon">✅</div><h2>No findings detected</h2><p>The target API demonstrated strong resilience against all tested attack scenarios.</p></div>'}
  </div>

</div>

<button class="theme-toggle" onclick="toggleTheme()" title="Toggle dark mode">🌙</button>

<script>
const FINDINGS = {findings_js};
const CHART_DATA = {chart_data};
const COLORS = ["#dc2626","#ea580c","#ca8a04","#16a34a","#2563eb"];
const LABELS = ["Critical","High","Medium","Low","Info"];

// Draw donut chart
(function() {{
  const canvas = document.getElementById('chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const total = CHART_DATA.reduce((a,b)=>a+b, 0);
  if (!total) {{ ctx.font='14px sans-serif'; ctx.fillStyle='#64748b'; ctx.fillText('No data',60,100); return; }}
  let angle = -Math.PI/2;
  CHART_DATA.forEach((v,i)=>{{
    if(!v) return;
    const slice = (v/total)*2*Math.PI;
    ctx.beginPath(); ctx.moveTo(100,100);
    ctx.arc(100,100,90,angle,angle+slice);
    ctx.closePath(); ctx.fillStyle=COLORS[i]; ctx.fill();
    angle+=slice;
  }});
  // Hole
  ctx.beginPath(); ctx.arc(100,100,55,0,2*Math.PI);
  ctx.fillStyle=getComputedStyle(document.documentElement).getPropertyValue('--surface')||'#fff';
  ctx.fill();
  // Center text
  ctx.fillStyle='#1e293b'; ctx.font='bold 28px sans-serif';
  ctx.textAlign='center'; ctx.textBaseline='middle';
  ctx.fillText(total,100,95);
  ctx.font='12px sans-serif'; ctx.fillStyle='#64748b';
  ctx.fillText('total',100,118);
}})();

function toggleCard(id){{
  const body=document.getElementById('body-'+id);
  const hdr=document.getElementById('hdr-'+id);
  body.classList.toggle('open');
  hdr.classList.toggle('open');
}}

function filterFindings(){{
  const q=document.getElementById('searchInput').value.toLowerCase();
  const sev=document.getElementById('sevFilter').value;
  const type=document.getElementById('typeFilter').value;
  document.querySelectorAll('.finding-card').forEach(card=>{{
    const f=FINDINGS.find(x=>card.dataset.id===x.id);
    if(!f)return;
    const show=(!q||(f.title+f.endpoint+f.persona+f.type).toLowerCase().includes(q))
      &&(!sev||f.severity===sev)&&(!type||f.type===type);
    card.style.display=show?'':'none';
  }});
}}

function toggleTheme(){{
  const html=document.documentElement;
  html.dataset.theme=html.dataset.theme==='dark'?'light':'dark';
  localStorage.setItem('entropy-theme',html.dataset.theme);
}}
(function(){{
  const saved=localStorage.getItem('entropy-theme');
  if(saved)document.documentElement.dataset.theme=saved;
}})();
</script>
</body>
</html>"""

    def _stat_card(self, severity: Severity, count: int) -> str:
        color = _SEV_COLOR[severity]
        return f"""<div class="stat-card">
  <div class="count" style="color:{color}">{count}</div>
  <div class="label">{severity.value.capitalize()}</div>
</div>"""

    def _finding_card(self, finding: Finding, idx: int) -> str:
        sev_color = _SEV_COLOR[finding.severity]
        sev_bg    = _SEV_BG[finding.severity]
        steps_html = self._steps_html(finding)
        remediation = f'<div class="section-label">Remediation</div><div class="remediation">{_e(finding.remediation)}</div>' if finding.remediation else ""

        return f"""<div class="finding-card" data-id="{_e(finding.id)}">
  <div class="finding-header" id="hdr-{idx}" onclick="toggleCard({idx})">
    <div class="sev-bar" style="background:{sev_color}"></div>
    <div class="info">
      <h3>{_e(finding.title)}</h3>
      <div class="meta">
        <span><span class="badge" style="background:{sev_bg};color:{sev_color}">{_e(finding.severity.value.upper())}</span></span>
        <span>📌 {_e(finding.type.value.replace('_',' ').title())}</span>
        <span>🔗 <code>{_e(finding.endpoint or '—')}</code></span>
        {"<span>👤 " + _e(finding.persona) + "</span>" if finding.persona else ""}
      </div>
    </div>
    <span class="chevron">▼</span>
  </div>
  <div class="finding-body" id="body-{idx}">
    <div class="section-label">Description</div>
    <p>{_e(finding.description)}</p>
    {remediation}
    {steps_html}
    <div class="section-label">Finding ID</div>
    <code style="font-size:.75rem;color:var(--muted)">{_e(finding.id)}</code>
  </div>
</div>"""

    def _steps_html(self, finding: Finding) -> str:
        if not finding.steps:
            return ""
        items = []
        for step in finding.steps:
            req_html  = ""
            resp_html = ""
            if step.request:
                req  = step.request
                body = json.dumps(req.body, indent=2) if req.body else "null"
                req_html = f"<pre>{_e(req.method)} {_e(req.url)}\n\n{_e(body[:800])}</pre>"
            if step.response:
                resp  = step.response
                rbody = json.dumps(resp.body, indent=2)[:600] if resp.body else str(resp.body)
                resp_html = f"<p style='margin:.5rem 0;font-size:.85rem'>Response: <strong>{_e(resp.status_code)}</strong> ({resp.latency_ms:.0f}ms)</p><pre>{_e(rbody)}</pre>"
            items.append(f"""<div class="step">
  <span class="step-num">{step.step_number}</span> {_e(step.description)}
  {req_html}{resp_html}
</div>""")
        return '<div class="section-label">Reproduction Steps</div>' + "".join(items)

    def save(self, report: EntropyReport, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(report), encoding="utf-8")
        return path
