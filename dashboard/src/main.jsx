import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const MAX_POINTS = 72;
const CPU_THRESHOLD = 50;
const FD_THRESHOLD = 200;
const POLL_INTERVAL_MS = 1000;
const WEB_SCROLL_QUERY = "(min-width: 1051px)";
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

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

function systemCpuPercent(processCpuPercent, cores) {
  const normalizedCores = Number(cores);
  if (!Number.isFinite(normalizedCores) || normalizedCores <= 0) return null;
  return Math.min(100, Math.max(0, processCpuPercent / normalizedCores));
}

const PULSE_MS = 1800;

function usePulseSync() {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => (t + 1) % 100), PULSE_MS);
    return () => clearInterval(id);
  }, []);
  return tick;
}

function useDashboardData() {
  const [state, setState] = useState({
    status: { daemon: false, redis: false, cpu_cores: null },
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

function useWebViewLocomotiveScroll(refreshKey) {
  const scrollRef = useRef(null);

  useEffect(() => {
    if (typeof window === "undefined") return undefined;

    const webView = window.matchMedia(WEB_SCROLL_QUERY);
    const reducedMotion = window.matchMedia(REDUCED_MOTION_QUERY);
    let cancelled = false;

    async function mountScroll() {
      if (!webView.matches || reducedMotion.matches || scrollRef.current) return;

      const [{ default: LocomotiveScroll }] = await Promise.all([
        import("locomotive-scroll"),
        import("locomotive-scroll/dist/locomotive-scroll.css"),
      ]);

      if (cancelled || !webView.matches || reducedMotion.matches) return;

      document.documentElement.classList.add("web-smooth-scroll");
      scrollRef.current = new LocomotiveScroll({
        autoStart: true,
        lenisOptions: {
          lerp: 0.08,
          wheelMultiplier: 0.86,
          smoothWheel: true,
        },
      });
      requestAnimationFrame(() => scrollRef.current?.resize());
    }

    function unmountScroll() {
      document.documentElement.classList.remove("web-smooth-scroll");
      scrollRef.current?.destroy();
      scrollRef.current = null;
    }

    function syncMode() {
      if (webView.matches && !reducedMotion.matches) {
        mountScroll();
      } else {
        unmountScroll();
      }
    }

    syncMode();
    webView.addEventListener("change", syncMode);
    reducedMotion.addEventListener("change", syncMode);

    return () => {
      cancelled = true;
      webView.removeEventListener("change", syncMode);
      reducedMotion.removeEventListener("change", syncMode);
      unmountScroll();
    };
  }, []);

  useEffect(() => {
    requestAnimationFrame(() => scrollRef.current?.resize());
  }, [refreshKey]);
}

function buildSample(processes, previousPoint, cpuCores) {
  const standard = processes.filter((proc) => !isSuspectProcess(proc));
  const suspects = processes.filter(isSuspectProcess);
  const baselineRaw = standard.reduce((sum, proc) => sum + proc.cpu_percent, 0);
  const suspectRaw = suspects.reduce((sum, proc) => sum + proc.cpu_percent, 0);
  const baseline = systemCpuPercent(baselineRaw, cpuCores);
  const suspect = systemCpuPercent(suspectRaw, cpuCores);
  if (baseline === null || suspect === null) return null;

  return {
    label: timeLabel(),
    baseline: Number(smooth(previousPoint?.baseline, baseline).toFixed(1)),
    suspect: Number(smooth(previousPoint?.suspect, suspect, 0.5).toFixed(1)),
  };
}

function CpuGraph({ processes, cpuCores }) {
  const [points, setPoints] = useState([]);

  useEffect(() => {
    setPoints((current) => {
      const point = buildSample(processes, current[current.length - 1], cpuCores);
      if (!point) return current;
      return [...current, point].slice(-MAX_POINTS);
    });
  }, [processes, cpuCores]);

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
          <h2>System capacity, isolated leaks</h2>
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
        {points.length === 0 && <div className="empty-chart">Waiting for daemon CPU capacity</div>}
      </div>
    </section>
  );
}

function ProcessList({ processes, incidents }) {
  const RESOLVED_TTL_MS = 5 * 60 * 1000;
  const now = Date.now();
  const resolvedPids = useMemo(() => {
    const s = new Set();
    for (const inc of incidents || []) {
      const pid = inc.event?.pid;
      const ts = inc.timestamp ? inc.timestamp * 1000 : 0;
      if (pid && now - ts < RESOLVED_TTL_MS) s.add(pid);
    }
    return s;
  }, [incidents, now]);

  const suspects = processes
    .filter((proc) => isSuspectProcess(proc) && !resolvedPids.has(proc.pid))
    .sort((a, b) => b.cpu_percent - a.cpu_percent);
  const mitigated = processes
    .filter((proc) => isSuspectProcess(proc) && resolvedPids.has(proc.pid))
    .sort((a, b) => b.cpu_percent - a.cpu_percent);
  const standard = processes
    .filter((proc) => !isSuspectProcess(proc))
    .sort((a, b) => b.cpu_percent - a.cpu_percent);
  const visible = [...suspects.slice(0, 4), ...mitigated.slice(0, 2), ...standard.slice(0, 8)];

  return (
    <section className="panel">
      <div className="section-heading compact">
        <div>
          <p className="eyebrow">Process field</p>
          <h2>Tracked PIDs</h2>
        </div>
        <span className="count">{processes.length}</span>
      </div>
      <div className="process-list" onWheel={(e) => e.stopPropagation()}>
        {visible.length === 0 && <p className="muted">No process data yet.</p>}
        {visible.map((proc) => {
          const isActiveSpect = isSuspectProcess(proc) && !resolvedPids.has(proc.pid);
          const isMitigated = isSuspectProcess(proc) && resolvedPids.has(proc.pid);
          const cls = isActiveSpect ? "process suspect" : isMitigated ? "process mitigated" : "process";
          return (
            <article className={cls} key={proc.pid}>
              <div>
                <strong>{proc.name}</strong>
                <span>PID {proc.pid}{isMitigated ? " · mitigated" : ""}</span>
              </div>
              <dl>
                <div><dt>PROC CPU</dt><dd>{proc.cpu_percent.toFixed(1)}%</dd></div>
                <div><dt>MEM</dt><dd>{Number(proc.mem_mb || 0).toFixed(1)}</dd></div>
                <div><dt>FD</dt><dd>{proc.fd_count || 0}</dd></div>
              </dl>
            </article>
          );
        })}
      </div>
    </section>
  );
}

function agentStatus(monologue) {
  if (!monologue.length) return { label: "idle", live: false };
  const latest = monologue[0];
  const age = Date.now() / 1000 - (latest.timestamp || 0);
  const phase = (latest.phase || "").toUpperCase();
  if (phase === "FAILED") return { label: "failed", live: false };
  if (age > 45) return { label: "idle", live: false };
  if (phase === "RESOLVED") return { label: "resolved", live: true };
  if (["ANALYZING", "EXECUTING", "VERIFYING"].includes(phase)) return { label: "active", live: true };
  return { label: "idle", live: false };
}

function Controls({ status, processes, incidents, monologue, pulseTick }) {
  const [duration, setDuration] = useState(45);
  const [activeLeak, setActiveLeak] = useState(null);
  const [now, setNow] = useState(Date.now());
  const totalCpuRaw = processes.reduce((sum, proc) => sum + proc.cpu_percent, 0);
  const systemCpu = systemCpuPercent(totalCpuRaw, status.cpu_cores);
  const suspects = processes.filter(isSuspectProcess).length;
  const agent = agentStatus(monologue);
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

  // Stop the timer early if the agent already resolved an incident for this leak
  useEffect(() => {
    if (!activeLeak || elapsed < 3) return;
    const resolved = incidents.some(
      (inc) => inc.timestamp != null && inc.timestamp * 1000 >= activeLeak.startedAt
    );
    if (resolved) setActiveLeak(null);
  }, [incidents, activeLeak, elapsed]);

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
        <Metric label="daemon" value={status.daemon ? (status.daemon_mode || "online") : "offline"} live={status.daemon} pulseTick={pulseTick} />
        <Metric label="redis" value={status.redis ? (monologue.length === 0 ? "empty" : "online") : "offline"} live={status.redis} pulseTick={pulseTick} />
        <Metric label="agent" value={agent.label} live={agent.live} pulseTick={pulseTick} />
        <Metric label="cpu cores" value={status.cpu_cores ?? "--"} />
        <Metric label="system cpu" value={systemCpu === null ? "--" : `${systemCpu.toFixed(1)}%`} />
        <Metric label="suspects" value={suspects} />
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
        <button className="btn-full btn-ghost" disabled={!status.redis} onClick={async () => {
          await fetch("/api/clear", { method: "POST" });
        }}>Clear logs</button>
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

function Metric({ label, value, live, pulseTick }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong key={value}>{value}</strong>
      {live !== undefined && (
        <i key={live ? pulseTick : "off"} className={live ? "dot live" : "dot"} />
      )}
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
      <div className="log-list" onWheel={(e) => e.stopPropagation()}>
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
      <div className="incident-list" onWheel={(e) => e.stopPropagation()}>
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
  const pulseTick = usePulseSync();
  useWebViewLocomotiveScroll(`${processes.length}:${monologue.length}:${incidents.length}:${error}`);

  return (
    <main data-scroll-section>
      <header className="hero" data-scroll>
        <div>
          <p className="eyebrow">Neural eBPF</p>
          <h1>Surgery Console</h1>
          <p className="lede">Kernel eBPF telemetry, mitigation state, and leak isolation via a kernel agent.</p>
        </div>
        <div className="hero-terminal" data-scroll data-scroll-speed="-0.08">
          <span>watch --cpu --fd --agent</span>
          <b>{status.daemon ? "daemon:linked" : "daemon:waiting"}</b>
        </div>
      </header>

      {error && <div className="error">Dashboard API error: {error}</div>}

      <div className="layout" data-scroll>
        <aside>
          <Controls status={status} processes={processes} incidents={incidents} monologue={monologue} pulseTick={pulseTick} />
          <ProcessList processes={processes} incidents={incidents} />
        </aside>
        <div className="main-column">
          <CpuGraph processes={processes} cpuCores={status.cpu_cores} />
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
