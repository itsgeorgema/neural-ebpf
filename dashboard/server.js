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

app.get("/api/status", async (_req, res) => {
  const [redisOk, health] = await Promise.all([
    redisPing(),
    daemonFetch("/health").catch(() => null),
  ]);
  res.json({
    daemon: Boolean(health),
    redis: redisOk,
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
  res.json(await readJsonList("monologue", count));
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
  res.json(incidents);
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
