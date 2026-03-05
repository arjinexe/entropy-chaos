"""Browser-based live dashboard — SSE-powered, no external dependencies."""
from __future__ import annotations

import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Event bus (thread-safe)
# ---------------------------------------------------------------------------

class EventBus:
    """Simple pub/sub bus for streaming scan progress to SSE clients."""

    def __init__(self):
        self._queues: List[queue.Queue] = []
        self._lock   = threading.Lock()
        self._events: List[Dict] = []        # replay buffer (last 500)

    def publish(self, event_type: str, data: Any) -> None:
        event = {"type": event_type, "data": data, "ts": time.time()}
        with self._lock:
            self._events = self._events[-499:]
            self._events.append(event)
            for q in list(self._queues):
                try:
                    q.put_nowait(event)
                except queue.Full:
                    pass

    def subscribe(self) -> queue.Queue:
        q = queue.Queue(maxsize=200)
        with self._lock:
            self._queues.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._queues:
                self._queues.remove(q)

    def replay(self) -> List[Dict]:
        with self._lock:
            return list(self._events)


# ---------------------------------------------------------------------------
# Global bus (singleton)
# ---------------------------------------------------------------------------

_bus: Optional[EventBus] = None


def get_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


def emit(event_type: str, data: Any) -> None:
    get_bus().publish(event_type, data)


# ---------------------------------------------------------------------------
# HTML template (single-file, no external deps)
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Entropy — Live Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e;
    --red: #f85149; --orange: #d29922; --yellow: #e3b341;
    --green: #3fb950; --blue: #58a6ff; --purple: #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 18px; font-weight: 700; }
  header h1 span { color: var(--purple); }
  .badge { background: #21262d; border: 1px solid var(--border); border-radius: 12px; padding: 2px 10px; font-size: 12px; color: var(--muted); }
  #status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); display: inline-block; }
  #status-dot.running { background: var(--green); box-shadow: 0 0 6px var(--green); animation: pulse 1.5s infinite; }
  @keyframes pulse { 0%,100%{opacity:1}50%{opacity:.4} }
  main { padding: 24px; max-width: 1200px; margin: 0 auto; }
  .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card .label { font-size: 11px; text-transform: uppercase; color: var(--muted); letter-spacing: .08em; margin-bottom: 8px; }
  .card .value { font-size: 28px; font-weight: 700; }
  .card.critical .value { color: var(--red); }
  .card.high     .value { color: var(--orange); }
  .card.medium   .value { color: var(--yellow); }
  .card.low      .value { color: var(--green); }
  .section-title { font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; margin-bottom: 12px; }
  .findings { display: flex; flex-direction: column; gap: 8px; margin-bottom: 24px; }
  .finding { background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--muted); border-radius: 6px; padding: 12px 16px; cursor: pointer; transition: border-color .15s; }
  .finding:hover { border-color: var(--blue); }
  .finding.critical { border-left-color: var(--red); }
  .finding.high     { border-left-color: var(--orange); }
  .finding.medium   { border-left-color: var(--yellow); }
  .finding.low      { border-left-color: var(--green); }
  .finding-header { display: flex; justify-content: space-between; align-items: center; }
  .finding-title  { font-weight: 600; font-size: 14px; }
  .finding-meta   { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .sev-badge { font-size: 11px; text-transform: uppercase; font-weight: 700; padding: 2px 8px; border-radius: 4px; }
  .sev-badge.critical { background: rgba(248,81,73,.15); color: var(--red); }
  .sev-badge.high     { background: rgba(210,153,34,.15); color: var(--orange); }
  .sev-badge.medium   { background: rgba(227,179,65,.15); color: var(--yellow); }
  .sev-badge.low      { background: rgba(63,185,80,.15);  color: var(--green); }
  .log { background: #010409; border: 1px solid var(--border); border-radius: 6px; padding: 12px 16px; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 12px; height: 220px; overflow-y: auto; color: var(--muted); }
  .log .line { line-height: 1.6; }
  .log .ok   { color: var(--green); }
  .log .err  { color: var(--red); }
  .log .info { color: var(--blue); }
  .filters { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-btn { background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 4px 12px; font-size: 12px; cursor: pointer; color: var(--muted); }
  .filter-btn.active { border-color: var(--blue); color: var(--blue); }
  #progress-bar-wrap { background: #21262d; border-radius: 4px; height: 6px; margin-bottom: 20px; overflow: hidden; }
  #progress-bar { height: 100%; background: var(--purple); border-radius: 4px; width: 0%; transition: width .5s; }
  .two-col { display: grid; grid-template-columns: 1fr 320px; gap: 16px; }
  @media(max-width:900px){ .grid{grid-template-columns:repeat(2,1fr)} .two-col{grid-template-columns:1fr} }
</style>
</head>
<body>
<header>
  <span id="status-dot"></span>
  <h1>🌪️ <span>Entropy</span> Dashboard</h1>
  <span class="badge" id="target-badge">idle</span>
  <span class="badge" id="run-badge">—</span>
</header>
<main>
  <div id="progress-bar-wrap"><div id="progress-bar"></div></div>
  <div class="grid">
    <div class="card critical"><div class="label">Critical</div><div class="value" id="cnt-critical">0</div></div>
    <div class="card high">   <div class="label">High</div>    <div class="value" id="cnt-high">0</div></div>
    <div class="card medium"> <div class="label">Medium</div>  <div class="value" id="cnt-medium">0</div></div>
    <div class="card low">    <div class="label">Low</div>     <div class="value" id="cnt-low">0</div></div>
  </div>

  <div class="two-col">
    <div>
      <div class="section-title">Findings</div>
      <div class="filters">
        <button class="filter-btn active" onclick="setFilter('all')">All</button>
        <button class="filter-btn" onclick="setFilter('critical')">Critical</button>
        <button class="filter-btn" onclick="setFilter('high')">High</button>
        <button class="filter-btn" onclick="setFilter('medium')">Medium</button>
        <button class="filter-btn" onclick="setFilter('low')">Low</button>
      </div>
      <div class="findings" id="findings-list"><p style="color:var(--muted);font-size:13px">Waiting for scan to start…</p></div>
    </div>
    <div>
      <div class="section-title">Live Log</div>
      <div class="log" id="log"></div>
    </div>
  </div>
</main>

<script>
const state = { findings: [], filter: 'all', running: false, progress: 0 };

function setFilter(f) {
  state.filter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.textContent.toLowerCase() === f));
  renderFindings();
}

function renderFindings() {
  const list = document.getElementById('findings-list');
  const items = state.filter === 'all' ? state.findings
    : state.findings.filter(f => f.severity === state.filter);
  if (!items.length) { list.innerHTML = '<p style="color:var(--muted);font-size:13px">No findings match filter.</p>'; return; }
  list.innerHTML = items.map(f => `
    <div class="finding ${f.severity}">
      <div class="finding-header">
        <span class="finding-title">${f.title}</span>
        <span class="sev-badge ${f.severity}">${f.severity}</span>
      </div>
      <div class="finding-meta">${f.endpoint} · ${f.type}</div>
      ${f.description ? `<div class="finding-meta" style="margin-top:6px;color:var(--text)">${f.description.slice(0,120)}${f.description.length>120?'…':''}</div>` : ''}
    </div>`).join('');
}

function updateCounters() {
  ['critical','high','medium','low'].forEach(s => {
    document.getElementById('cnt-'+s).textContent =
      state.findings.filter(f => f.severity === s).length;
  });
}

function addLog(msg, cls='') {
  const log = document.getElementById('log');
  const line = document.createElement('div');
  line.className = 'line ' + cls;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function handleEvent(ev) {
  const {type, data} = ev;
  if (type === 'scan_start') {
    state.findings = []; state.running = true; state.progress = 5;
    document.getElementById('target-badge').textContent = data.target || '?';
    document.getElementById('run-badge').textContent = 'Run ' + (data.run_id||'').slice(0,8);
    document.getElementById('status-dot').className = 'running';
    document.getElementById('progress-bar').style.width = '5%';
    addLog('Scan started: ' + (data.target||''), 'info');
    renderFindings();
  } else if (type === 'finding') {
    state.findings.unshift(data);
    updateCounters();
    renderFindings();
    addLog(`[${data.severity?.toUpperCase()}] ${data.title}`, data.severity==='critical'||data.severity==='high' ? 'err' : '');
  } else if (type === 'progress') {
    state.progress = Math.min(95, (data.pct||0));
    document.getElementById('progress-bar').style.width = state.progress + '%';
    addLog(data.msg || '', 'ok');
  } else if (type === 'scan_complete') {
    state.running = false; state.progress = 100;
    document.getElementById('status-dot').className = '';
    document.getElementById('progress-bar').style.width = '100%';
    addLog(`Scan complete — ${state.findings.length} finding(s)`, 'ok');
  } else if (type === 'log') {
    addLog(data.msg || '', data.cls || '');
  }
}

// Server-Sent Events
const es = new EventSource('/events');
es.onmessage = e => { try { handleEvent(JSON.parse(e.data)); } catch {} };
es.onerror   = () => addLog('Connection lost — retrying…', 'err');

// Replay on connect
fetch('/events/replay').then(r=>r.json()).then(evs => evs.forEach(handleEvent)).catch(()=>{});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class DashboardHandler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass  # suppress access logs

    def do_GET(self):
        if self.path == "/" or self.path == "/dashboard":
            self._respond(200, "text/html", DASHBOARD_HTML.encode())

        elif self.path == "/events":
            self._stream_sse()

        elif self.path == "/events/replay":
            replay = get_bus().replay()
            self._respond(200, "application/json", json.dumps(replay).encode())

        elif self.path == "/api/findings":
            # Return current findings as JSON (for non-SSE clients)
            data = json.dumps(get_bus().replay()).encode()
            self._respond(200, "application/json", data)

        else:
            self._respond(404, "text/plain", b"Not found")

    def _respond(self, code: int, ct: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _stream_sse(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = get_bus().subscribe()
        try:
            while True:
                try:
                    event = q.get(timeout=25)
                    data  = f"data: {json.dumps(event)}\n\n"
                    self.wfile.write(data.encode())
                    self.wfile.flush()
                except queue.Empty:
                    # heartbeat
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            get_bus().unsubscribe(q)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class DashboardServer:
    """
    Lightweight embedded web server for the Entropy dashboard.
    Runs in a daemon thread so it doesn't block the scan.
    """

    def __init__(self, port: int = 8080, host: str = "127.0.0.1"):
        self.host   = host
        self.port   = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start_background(self) -> str:
        """Start server in a background thread. Returns URL."""
        self._server = HTTPServer((self.host, self.port), DashboardHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        url = f"http://{self.host}:{self.port}"
        print(f"\n  🌐 Dashboard: {url}\n")
        return url

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
