import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const MAX_POINTS = 72;
const CPU_THRESHOLD = 50;
const FD_THRESHOLD = 200;
const POLL_INTERVAL_MS = 1000;

function isSuspectProcess(proc) {
  const name = String(proc.name || "").toLowerCase();
  return name.includes("leak") || proc.cpu_percent >= CPU_THRESHOLD || (proc.fd_count || 0) >= FD_THRESHOLD;
}

function smooth(previous, next, weight = 0.35) {
  if (previous === undefined) return next;
  return previous * (1 - weight) + next * weight;
}

function timeLabel(ts = Date.now()) {
  return new Intl.DateTimeFormat("en", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(ts);
}

function useDashboardData() {
  const [state, setState] = useState({
    status: { daemon: false, redis: false },
    processes: [],
    monologue: [],
    incidents: [],
    error: "",
  });

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const [status, processes, monologue, incidents] = await Promise.all([
          fetch("/api/status").then((r) => r.json()),
          fetch("/api/processes").then((r) => r.json()),
          fetch("/api/monologue?n=30").then((r) => r.json()),
          fetch("/api/incidents?n=10").then((r) => r.json()),
        ]);
        if (!cancelled) setState({ status, processes, monologue, incidents, error: "" });
      } catch (error) {
        if (!cancelled) setState((current) => ({ ...current, error: error.message }));
      }
    }

    load();
    const id = setInterval(load, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return state;
}

function buildSample(processes, previousPoint) {
  const standard = processes.filter((proc) => !isSuspectProcess(proc));
  const suspects = processes.filter(isSuspectProcess);
  const baselineRaw = standard
    .sort((a, b) => b.cpu_percent - a.cpu_percent)
    .slice(0, 12)
    .reduce((sum, proc) => sum + proc.cpu_percent, 0);
  const suspectRaw = Math.max(0, ...suspects.map((proc) => proc.cpu_percent));

  return {
    label: timeLabel(),
    baseline: Number(smooth(previousPoint?.baseline, Math.min(100, baselineRaw)).toFixed(1)),
    suspect: Number(smooth(previousPoint?.suspect, Math.min(100, suspectRaw), 0.5).toFixed(1)),
  };
}

function CpuGraph({ processes }) {
  const [points, setPoints] = useState([]);

  useEffect(() => {
    setPoints((current) => {
      const point = buildSample(processes, current[current.length - 1]);
      return [...current, point].slice(-MAX_POINTS);
    });
  }, [processes]);

  const path = useMemo(() => {
    const width = 760;
    const height = 240;
    const pad = 22;
    const x = (index) => pad + (index * (width - pad * 2)) / Math.max(1, points.length - 1);
    const y = (value) => height - pad - (Math.min(100, value) / 100) * (height - pad * 2);
    const line = (key) => points.map((point, index) => `${index === 0 ? "M" : "L"} ${x(index)} ${y(point[key])}`).join(" ");
    return { width, height, baseline: line("baseline"), suspect: line("suspect") };
  }, [points]);

  const latest = points[points.length - 1] || { baseline: 0, suspect: 0 };

  return (
    <section className="panel graph-panel">
      <div className="section-heading">
        <div>
          <p className="eyebrow">CPU activity</p>
          <h2>Muted baseline, isolated leaks</h2>
        </div>
        <div className="legend">
          <span><i className="legend-base" />standard {latest.baseline.toFixed(1)}%</span>
          <span><i className="legend-leak" />leak {latest.suspect.toFixed(1)}%</span>
        </div>
      </div>
      <div className="chart-wrap">
        <svg viewBox={`0 0 ${path.width} ${path.height}`} role="img" aria-label="CPU activity graph">
          {[0, 25, 50, 75, 100].map((tick) => (
            <g key={tick}>
              <line x1="22" x2="738" y1={218 - tick * 1.96} y2={218 - tick * 1.96} className="grid-line" />
              <text x="0" y={222 - tick * 1.96}>{tick}</text>
            </g>
          ))}
          <path d={path.baseline} className="line line-base" />
          <path d={path.suspect} className="line line-leak" />
        </svg>
        {points.length === 0 && <div className="empty-chart">Waiting for daemon samples</div>}
      </div>
    </section>
  );
}

function ProcessList({ processes }) {
  const suspects = processes.filter(isSuspectProcess).sort((a, b) => b.cpu_percent - a.cpu_percent);
  const standard = processes.filter((proc) => !isSuspectProcess(proc)).sort((a, b) => b.cpu_percent - a.cpu_percent);
  const visible = [...suspects.slice(0, 4), ...standard.slice(0, 8)];

  return (
    <section className="panel">
      <div className="section-heading compact">
        <div>
          <p className="eyebrow">Process field</p>
          <h2>Tracked PIDs</h2>
        </div>
        <span className="count">{processes.length}</span>
      </div>
      <div className="process-list">
        {visible.length === 0 && <p className="muted">No process data yet.</p>}
        {visible.map((proc) => (
          <article className={isSuspectProcess(proc) ? "process suspect" : "process"} key={proc.pid}>
            <div>
              <strong>{proc.name}</strong>
              <span>PID {proc.pid}</span>
            </div>
            <dl>
              <div><dt>CPU</dt><dd>{proc.cpu_percent.toFixed(1)}%</dd></div>
              <div><dt>MEM</dt><dd>{Number(proc.mem_mb || 0).toFixed(1)}</dd></div>
              <div><dt>FD</dt><dd>{proc.fd_count || 0}</dd></div>
            </dl>
          </article>
        ))}
      </div>
    </section>
  );
}

function Controls({ status, processes }) {
  const [duration, setDuration] = useState(30);
  const [activeLeak, setActiveLeak] = useState(null);
  const [now, setNow] = useState(Date.now());
  const peakCpu = Math.max(0, ...processes.map((proc) => proc.cpu_percent));
  const suspects = processes.filter(isSuspectProcess).length;
  const elapsed = activeLeak ? Math.floor((now - activeLeak.startedAt) / 1000) : 0;
  const remaining = activeLeak ? Math.max(0, activeLeak.duration - elapsed) : 0;

  const servicesReady = status.daemon && status.redis;
  const offlineReason = !status.daemon && !status.redis
    ? "daemon + agent offline"
    : !status.daemon
    ? "daemon offline"
    : "agent / redis offline";

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (activeLeak && remaining === 0) {
      setActiveLeak(null);
    }
  }, [activeLeak, remaining]);

  async function trigger(kind) {
    if (!servicesReady) return;
    await fetch("/api/trigger", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kind, duration }),
    });
    setActiveLeak({ kind, duration, startedAt: Date.now() });
    setNow(Date.now());
  }

  return (
    <section className="panel control-panel">
      <div className="status-grid">
        <Metric label="daemon" value={status.daemon ? "online" : "offline"} live={status.daemon} />
        <Metric label="redis" value={status.redis ? "online" : "offline"} live={status.redis} />
        <Metric label="suspects" value={suspects} />
        <Metric label="peak cpu" value={`${peakCpu.toFixed(1)}%`} />
      </div>
      <label className="range-label" htmlFor="duration">Leak duration <span>{duration}s</span></label>
      <input
        id="duration"
        type="range"
        min="10"
        max="120"
        step="5"
        value={duration}
        disabled={!servicesReady}
        onChange={(event) => setDuration(Number(event.target.value))}
      />
      <div className="button-row">
        <button disabled={!servicesReady} onClick={() => trigger("cpu")}>CPU leak</button>
        <button disabled={!servicesReady} onClick={() => trigger("fd")}>FD leak</button>
      </div>
      {!servicesReady && (
        <p className="offline-notice">{offlineReason} — leak triggers disabled</p>
      )}
      {activeLeak && (
        <div className="leak-clock">
          <span>{activeLeak.kind.toUpperCase()} leak active</span>
          <strong>{elapsed}s elapsed</strong>
          <small>{remaining}s remaining</small>
        </div>
      )}
    </section>
  );
}

function Metric({ label, value, live }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      {live !== undefined && <i className={live ? "dot live" : "dot"} />}
    </div>
  );
}

function Monologue({ entries }) {
  return (
    <section className="panel log-panel">
      <div className="section-heading compact">
        <div>
          <p className="eyebrow">Agent transcript</p>
          <h2>Monologue stream</h2>
        </div>
      </div>
      <div className="log-list">
        {entries.length === 0 && <p className="muted">Trigger a leak to populate the transcript.</p>}
        {entries.map((entry, index) => (
          <article className="log-line" key={`${entry.timestamp}-${index}`}>
            <span>{timeLabel((entry.timestamp || Date.now() / 1000) * 1000)}</span>
            <b>{entry.phase || "IDLE"}</b>
            <p>{entry.content || ""}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

function Incidents({ incidents }) {
  return (
    <section className="panel incidents-panel">
      <div className="section-heading compact">
        <div>
          <p className="eyebrow">Resolved</p>
          <h2>Incident history</h2>
        </div>
      </div>
      <div className="incident-list">
        {incidents.length === 0 && <p className="muted">No resolved incidents yet.</p>}
        {incidents.map((incident, index) => {
          const event = incident.event || {};
          const process = event.process || {};
          return (
            <article className="incident" key={`${incident.timestamp}-${index}`}>
              <strong>{process.name || "unknown"}</strong>
              <span>PID {event.pid || "n/a"} · {event.type || "event"}</span>
              <small>{incident.attempts || 0} attempts</small>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function App() {
  const { status, processes, monologue, incidents, error } = useDashboardData();

  return (
    <main>
      <header className="hero">
        <div>
          <p className="eyebrow">Neural eBPF</p>
          <h1>Surgery Console</h1>
          <p className="lede">Kernel eBPF telemetry, mitigation state, and leak isolation via a kernel agent.</p>
        </div>
        <div className="hero-terminal">
          <span>watch --cpu --fd --agent</span>
          <b>{status.daemon ? "daemon:linked" : "daemon:waiting"}</b>
        </div>
      </header>

      {error && <div className="error">Dashboard API error: {error}</div>}

      <div className="layout">
        <aside>
          <Controls status={status} processes={processes} />
          <ProcessList processes={processes} />
        </aside>
        <div className="main-column">
          <CpuGraph processes={processes} />
          <div className="lower-grid">
            <Monologue entries={monologue} />
            <Incidents incidents={incidents} />
          </div>
        </div>
      </div>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
