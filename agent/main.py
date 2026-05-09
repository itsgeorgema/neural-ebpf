"""
Main entrypoint for the Neural eBPF agent.
Connects to the Go daemon's SSE event stream and handles each alert.
"""
import json
import logging
import os
import sys
import threading
import time

import httpx
from dotenv import load_dotenv

from agent import handle_event
from redis_store import IncidentStore

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

DAEMON_URL = os.getenv("DAEMON_URL", "http://localhost:8080")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))


def wait_for_daemon(timeout: int = 30):
    log.info("Waiting for daemon at %s ...", DAEMON_URL)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = httpx.get(f"{DAEMON_URL}/health", timeout=2)
            if resp.status_code == 200:
                log.info("Daemon is healthy.")
                return
        except Exception:
            pass
        time.sleep(1)
    log.error("Daemon not reachable after %ds. Exiting.", timeout)
    sys.exit(1)


def metrics_poller(store: IncidentStore):
    """Background thread: poll daemon every 2s for metrics and push to Redis."""
    while True:
        try:
            resp = httpx.get(f"{DAEMON_URL}/processes", timeout=3)
            if resp.status_code == 200:
                for proc in resp.json():
                    store.push_metric(proc["pid"], proc["cpu_percent"], proc["mem_mb"])
        except Exception:
            pass
        time.sleep(2)


def heartbeat_poller(store: IncidentStore):
    """Background thread: write agent liveness every second for dashboard status."""
    while True:
        try:
            store.heartbeat()
        except Exception:
            pass
        time.sleep(1)


def main():
    if not os.getenv("OPENAI_API_KEY"):
        log.error("OPENAI_API_KEY not set. Create a .env file with OPENAI_API_KEY=sk-...")
        sys.exit(1)

    wait_for_daemon()

    store = IncidentStore(host=REDIS_HOST, port=REDIS_PORT)
    if not store.ping():
        log.warning("Redis not reachable at %s:%d — monologue and incidents won't persist.", REDIS_HOST, REDIS_PORT)

    # Start background threads for metrics and low-latency dashboard liveness.
    threading.Thread(target=heartbeat_poller, args=(store,), daemon=True).start()
    threading.Thread(target=metrics_poller, args=(store,), daemon=True).start()

    log.info("Connecting to SSE stream at %s/events ...", DAEMON_URL)
    active_pids: set[int] = set()

    while True:
        try:
            with httpx.stream("GET", f"{DAEMON_URL}/events", timeout=None) as resp:
                event_type = ""
                data_buf = ""
                for line in resp.iter_lines():
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                    elif line.startswith("data:"):
                        data_buf = line[5:].strip()
                    elif line == "":
                        if event_type != "kernel_event" or not data_buf:
                            event_type = ""
                            data_buf = ""
                            continue
                        try:
                            data = json.loads(data_buf)
                        except json.JSONDecodeError:
                            event_type = ""
                            data_buf = ""
                            continue
                        event_type = ""
                        data_buf = ""

                        pid = data.get("pid", 0)
                        ev_type = data.get("type", "")

                        # Record every kernel event to Redis for telemetry
                        store.log_kernel_event(data)

                        if ev_type == "resolved":
                            active_pids.discard(pid)
                            log.info("PID %d resolved — removing from active set", pid)
                            continue

                        # Deduplicate: only handle each PID once at a time
                        if pid in active_pids:
                            log.debug("PID %d already being handled, skipping duplicate event", pid)
                            continue

                        active_pids.add(pid)
                        log.info("New %s event for PID %d — spawning agent", ev_type, pid)

                        # Run agent in a background thread so we don't block the SSE stream
                        def run_agent(ev=data, p=pid):
                            try:
                                handle_event(ev, store)
                            except Exception as exc:
                                log.exception("Agent error for PID %d: %s", p, exc)
                            finally:
                                active_pids.discard(p)

                        threading.Thread(target=run_agent, daemon=True).start()

        except KeyboardInterrupt:
            log.info("Shutting down agent.")
            sys.exit(0)
        except Exception as exc:
            log.error("SSE connection error: %s — reconnecting in 5s", exc)
            time.sleep(5)


if __name__ == "__main__":
    main()
