import express from "express";
import Redis from "ioredis";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = Number(process.env.PORT || 8501);
const daemonUrl = process.env.DAEMON_URL || "http://localhost:8080";
const redisHost = process.env.REDIS_HOST || "localhost";
const redisPort = Number(process.env.REDIS_PORT || 6379);
const scriptsDir = process.env.SCRIPTS_DIR || path.resolve(__dirname, "..", "scripts");
const pythonBin = process.env.PYTHON_BIN || "python3";

const redis = new Redis({ host: redisHost, port: redisPort, lazyConnect: true, maxRetriesPerRequest: 1 });
redis.on("error", () => {
  // Offline Redis is reflected by /api/status; avoid noisy connection logs during local UI work.
});

app.use(express.json());

async function redisPing() {
  try {
    if (redis.status === "wait") await redis.connect();
    return (await redis.ping()) === "PONG";
  } catch {
    return false;
  }
}

async function daemonFetch(pathname, options = {}) {
  const response = await fetch(`${daemonUrl}${pathname}`, { signal: AbortSignal.timeout(3000), ...options });
  if (!response.ok) throw new Error(`daemon returned ${response.status}`);
  return response.json();
}

async function readJsonList(key, count) {
  if (!(await redisPing())) return [];
  const raw = await redis.lrange(key, 0, count - 1);
  return raw.map((item) => JSON.parse(item));
}

function activityTime(entry) {
  return Number(entry?.timestamp || 0);
}

function kernelEventToLog(entry) {
  const event = entry.event || {};
  const process = event.process || {};
  return {
    timestamp: activityTime(entry),
    phase: "KERNEL",
    pid: event.pid,
    process: process.name || "unknown",
    content: event.message || `${event.type || "event"} for PID ${event.pid || "n/a"}`,
  };
}

function mitigationToLog(entry) {
  const result = entry.result || {};
  const action = entry.action || result.action || "mitigation";
  const status = result.success === false ? "failed" : "completed";
  return {
    timestamp: activityTime(entry),
    phase: "MITIGATING",
    pid: entry.pid,
    process: "daemon",
    content: `${action} ${status} for PID ${entry.pid || "n/a"}: ${result.message || "no result message"}`,
  };
}

function fallbackIncidentFromMitigation(mitigation, kernelEvents) {
  const result = mitigation.result || {};
  if (!mitigation.pid || result.success === false) return null;
  const eventEntry = kernelEvents
    .filter((entry) => entry.event?.pid === mitigation.pid)
    .sort((a, b) => Math.abs(activityTime(a) - activityTime(mitigation)) - Math.abs(activityTime(b) - activityTime(mitigation)))[0];
  if (!eventEntry?.event) return null;
  return {
    event: eventEntry.event,
    resolution: "mitigated",
    attempts: 1,
    process_class: eventEntry.event.process_class || "unknown",
    anomaly_type: eventEntry.event.anomaly_type || "unknown",
    timestamp: activityTime(mitigation),
  };
}

app.get("/api/status", async (_req, res) => {
  const [redisOk, health] = await Promise.all([
    redisPing(),
    daemonFetch("/health").catch(() => null),
  ]);
  let agentOnline = false;
  if (redisOk) {
    try {
      agentOnline = Boolean(await redis.get("agent:heartbeat"));
    } catch { /* ignore */ }
  }
  res.json({
    daemon: Boolean(health),
    daemon_mode: health?.mode || null,
    redis: redisOk,
    agent: agentOnline,
    cpu_cores: Number(health?.cpu_cores) || null,
  });
});

app.get("/api/processes", async (_req, res) => {
  try {
    res.json(await daemonFetch("/processes"));
  } catch (error) {
    res.json([]);
  }
});

app.get("/api/monologue", async (req, res) => {
  const count = Number(req.query.n || 30);
  if (!(await redisPing())) return res.json([]);
  const [monologue, kernelEvents, mitigations] = await Promise.all([
    readJsonList("monologue", count),
    readJsonList("kernel_events", count),
    readJsonList("mitigations", count),
  ]);
  const activity = [
    ...monologue,
    ...kernelEvents.map(kernelEventToLog),
    ...mitigations.map(mitigationToLog),
  ]
    .filter((entry) => activityTime(entry) > 0)
    .sort((a, b) => activityTime(b) - activityTime(a))
    .slice(0, count);
  res.json(activity);
});

app.get("/api/incidents", async (req, res) => {
  const count = Number(req.query.n || 10);
  if (!(await redisPing())) return res.json([]);
  const ids = await redis.lrange("incidents", 0, count - 1);
  const incidents = [];
  for (const id of ids) {
    const raw = await redis.hget(id, "data");
    if (raw) incidents.push(JSON.parse(raw));
  }
  const savedPids = new Set(incidents.map((incident) => incident.event?.pid).filter(Boolean));
  const [kernelEvents, mitigations] = await Promise.all([
    readJsonList("kernel_events", count * 3),
    readJsonList("mitigations", count * 3),
  ]);
  for (const mitigation of mitigations) {
    if (savedPids.has(mitigation.pid)) continue;
    const incident = fallbackIncidentFromMitigation(mitigation, kernelEvents);
    if (!incident) continue;
    savedPids.add(mitigation.pid);
    incidents.push(incident);
  }
  incidents.sort((a, b) => activityTime(b) - activityTime(a));
  res.json(incidents.slice(0, count));
});

app.post("/api/clear", async (_req, res) => {
  if (!(await redisPing())) return res.status(503).json({ error: "redis offline" });
  const patterns = ["monologue", "incidents", "kernel_events", "mitigations"];
  for (const key of patterns) await redis.del(key);
  // Delete all incident:* and metrics:* keys
  for (const pattern of ["incident:*", "metrics:*"]) {
    let cursor = "0";
    do {
      const [next, keys] = await redis.scan(cursor, "MATCH", pattern, "COUNT", 200);
      cursor = next;
      if (keys.length) await redis.del(...keys);
    } while (cursor !== "0");
  }
  res.json({ ok: true });
});

app.get("/api/metrics/:pid", async (req, res) => {
  const count = Number(req.query.n || 90);
  const metrics = await readJsonList(`metrics:${req.params.pid}`, count);
  res.json(metrics.reverse());
});

app.post("/api/trigger", async (req, res) => {
  const kind = req.body?.kind === "fd" ? "fd" : "cpu";
  const duration = Math.max(10, Math.min(120, Number(req.body?.duration || 30)));
  const script = path.join(scriptsDir, `${kind}_leak.py`);
  const child = spawn(pythonBin, [script, "--duration", String(duration)], {
    detached: true,
    stdio: "ignore",
  });
  child.unref();

  // Arm the daemon watchdog to match the slider duration exactly
  try {
    await daemonFetch("/watchdog", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ timeout: duration }),
    });
  } catch {
    // Best-effort — trigger still proceeds if daemon watchdog update fails
  }

  res.json({ ok: true, kind, duration });
});

if (process.env.NODE_ENV === "development") {
  const { createServer } = await import("vite");
  const vite = await createServer({ server: { middlewareMode: true }, appType: "spa" });
  app.use(vite.middlewares);
} else {
  app.use(express.static(path.join(__dirname, "dist")));
  app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "dist", "index.html")));
}

app.listen(port, () => {
  console.log(`dashboard listening on http://localhost:${port}`);
});
