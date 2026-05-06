"""
Neural eBPF Surgery Console — Streamlit Dashboard

Layout:
  Left column : controls (trigger leaks, status)
  Right column: real-time CPU graph (Plotly)
  Bottom      : agent monologue stream + incident history
"""
import json
import os
import subprocess
import sys
import time
from datetime import datetime

import httpx
import plotly.graph_objects as go
import redis
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

DAEMON_URL = os.getenv("DAEMON_URL", "http://localhost:8080")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

st.set_page_config(
    page_title="Neural eBPF — Surgery Console",
    page_icon="🧠",
    layout="wide",
)

# ── Styling ────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  .main { background-color: #0d1117; }
  .block-container { padding-top: 1rem; }
  .metric-card {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; padding: 12px 16px; margin-bottom: 8px;
  }
  .phase-badge {
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-size: 0.75rem; font-weight: 600; letter-spacing: 0.05em;
  }
  .phase-ANALYZING  { background:#1f4e79; color:#79c0ff; }
  .phase-EXECUTING  { background:#3d2b00; color:#ffa500; }
  .phase-VERIFYING  { background:#2d1f4e; color:#c9b1ff; }
  .phase-RESOLVED   { background:#0d3321; color:#56d364; }
  .phase-IDLE       { background:#21262d; color:#8b949e; }
  .monologue-entry  { font-family: monospace; font-size: 0.85rem;
                      border-left: 3px solid #30363d; padding-left: 8px;
                      margin-bottom: 6px; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ────────────────────────────────────────────────────────────────────
@st.cache_resource
def get_redis():
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
        r.ping()
        return r
    except Exception:
        return None


def daemon_healthy() -> bool:
    try:
        resp = httpx.get(f"{DAEMON_URL}/health", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def get_processes() -> list[dict]:
    try:
        resp = httpx.get(f"{DAEMON_URL}/processes", timeout=2)
        return resp.json() if resp.status_code == 200 else []
    except Exception:
        return []


def trigger_leak(kind: str, duration: int = 30):
    """Launch the appropriate leak script in the background."""
    script = os.path.join(os.path.dirname(__file__), "..", "scripts", f"{kind}_leak.py")
    script = os.path.abspath(script)
    subprocess.Popen(
        [sys.executable, script, "--duration", str(duration)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    st.session_state["leak_started"] = kind
    st.session_state["leak_time"] = time.time()


def get_monologue(r, n=20) -> list[dict]:
    if not r:
        return []
    try:
        raw = r.lrange("monologue", 0, n - 1)
        return [json.loads(x) for x in raw]
    except Exception:
        return []


def get_incidents(r, n=5) -> list[dict]:
    if not r:
        return []
    try:
        ids = r.lrange("incidents", 0, n - 1)
        result = []
        for id_ in ids:
            raw = r.hget(id_, "data")
            if raw:
                result.append(json.loads(raw))
        return result
    except Exception:
        return []


def get_metrics(r, pid: int, n: int = 60) -> list[dict]:
    if not r:
        return []
    try:
        key = f"metrics:{pid}"
        raw = r.lrange(key, 0, n - 1)
        return [json.loads(x) for x in reversed(raw)]
    except Exception:
        return []


PHASE_COLORS = {
    "ANALYZING": "#79c0ff",
    "EXECUTING": "#ffa500",
    "VERIFYING": "#c9b1ff",
    "RESOLVED": "#56d364",
    "IDLE": "#8b949e",
}


# ── Title ──────────────────────────────────────────────────────────────────────
st.markdown("## 🧠 Neural eBPF — Surgery Console")
st.markdown("*Self-healing kernel agent · Real-time eBPF telemetry*")

r = get_redis()
healthy = daemon_healthy()

# ── Status row ────────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
c1.metric("Daemon", "🟢 Online" if healthy else "🔴 Offline")
c2.metric("Redis", "🟢 Connected" if r else "🔴 Offline")
procs = get_processes()
c3.metric("Monitored PIDs", len(procs))
top_cpu = max((p["cpu_percent"] for p in procs), default=0)
c4.metric("Peak CPU%", f"{top_cpu:.1f}%")

st.divider()

# ── Main layout: controls | graph ─────────────────────────────────────────────
left, right = st.columns([1, 2])

with left:
    st.subheader("⚡ Incident Triggers")
    col_a, col_b = st.columns(2)
    duration = st.slider("Leak duration (sec)", 10, 120, 30)

    with col_a:
        if st.button("🔥 CPU Leak", use_container_width=True, type="primary"):
            trigger_leak("cpu", duration)
            st.success("CPU leak started!")

    with col_b:
        if st.button("📂 FD Leak", use_container_width=True):
            trigger_leak("fd", duration)
            st.success("FD leak started!")

    if st.session_state.get("leak_started"):
        elapsed = int(time.time() - st.session_state.get("leak_time", time.time()))
        st.info(f"🔴 Active: {st.session_state['leak_started']}_leak  ({elapsed}s)")

    st.subheader("📊 Live Processes")
    if procs:
        for p in sorted(procs, key=lambda x: x["cpu_percent"], reverse=True)[:8]:
            cpu = p["cpu_percent"]
            color = "#ff4b4b" if cpu > 80 else "#ffa500" if cpu > 50 else "#56d364"
            st.markdown(
                f'<div class="metric-card">'
                f'<b style="color:{color}">{p["name"]}</b> '
                f'<span style="color:#8b949e">PID {p["pid"]}</span><br>'
                f'CPU: <b style="color:{color}">{cpu:.1f}%</b>  '
                f'Mem: {p["mem_mb"]:.1f}MB  FDs: {p.get("fd_count", 0)}'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.caption("No processes tracked yet — daemon may be starting.")

with right:
    st.subheader("📈 CPU Activity Graph")
    # Show top-5 processes by CPU in a time-series chart
    fig = go.Figure()
    fig.update_layout(
        paper_bgcolor="#0d1117",
        plot_bgcolor="#161b22",
        font_color="#c9d1d9",
        xaxis=dict(gridcolor="#21262d", title="Time"),
        yaxis=dict(gridcolor="#21262d", title="CPU %", range=[0, 105]),
        legend=dict(bgcolor="#161b22", bordercolor="#30363d"),
        margin=dict(l=40, r=20, t=20, b=40),
        height=320,
    )

    # Overlay vertical line at leak start if recent
    leak_time = st.session_state.get("leak_time")

    shown_any = False
    if r:
        for p in sorted(procs, key=lambda x: x["cpu_percent"], reverse=True)[:5]:
            metrics = get_metrics(r, p["pid"])
            if metrics:
                xs = [datetime.fromtimestamp(m["ts"]).strftime("%H:%M:%S") for m in metrics]
                ys = [m["cpu"] for m in metrics]
                color = "#ff4b4b" if p["cpu_percent"] > 80 else "#79c0ff"
                fig.add_trace(go.Scatter(
                    x=xs, y=ys, mode="lines",
                    name=f"{p['name']} ({p['pid']})",
                    line=dict(color=color, width=2),
                ))
                shown_any = True

    if not shown_any:
        fig.add_annotation(
            text="Waiting for metrics... (start a leak or wait for daemon)",
            xref="paper", yref="paper", x=0.5, y=0.5,
            showarrow=False, font=dict(color="#8b949e", size=14),
        )

    st.plotly_chart(fig, use_container_width=True)

st.divider()

# ── Agent Monologue ────────────────────────────────────────────────────────────
mono_col, incident_col = st.columns([2, 1])

with mono_col:
    st.subheader("🤖 Agent Internal Monologue")
    monologue = get_monologue(r, 25)
    if monologue:
        for entry in monologue:
            phase = entry.get("phase", "IDLE")
            ts = datetime.fromtimestamp(entry.get("timestamp", time.time())).strftime("%H:%M:%S")
            color = PHASE_COLORS.get(phase, "#8b949e")
            st.markdown(
                f'<div class="monologue-entry">'
                f'<span style="color:#8b949e">[{ts}]</span> '
                f'<span class="phase-badge phase-{phase}" style="color:{color}">{phase}</span> '
                f'{entry.get("content", "")}'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.caption("No agent activity yet. Trigger a leak to see the agent respond.")

with incident_col:
    st.subheader("📋 Incident History")
    incidents = get_incidents(r, 10)
    if incidents:
        for inc in incidents:
            ev = inc.get("event", {})
            proc = ev.get("process", {})
            ts = datetime.fromtimestamp(inc.get("timestamp", time.time())).strftime("%m/%d %H:%M")
            st.markdown(
                f'<div class="metric-card">'
                f'<b style="color:#56d364">✓ Resolved</b> <span style="color:#8b949e">{ts}</span><br>'
                f'PID <b>{ev.get("pid")}</b> · {proc.get("name", "?")}<br>'
                f'Type: {ev.get("type", "?")} · Attempts: {inc.get("attempts", "?")}'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.caption("No resolved incidents yet.")

# ── Auto-refresh ───────────────────────────────────────────────────────────────
st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')} · Auto-refreshes every 2s")
time.sleep(2)
st.rerun()
