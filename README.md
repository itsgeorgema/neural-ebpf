# Neural eBPF — Self-Healing Kernel Agent

A "Low-Level SRE" system that detects runaway processes at the kernel level and autonomously applies mitigations using a LangGraph AI agent.

```
┌─────────────────────────────────────────────────────────┐
│                    Surgery Console (React :8501)         │
│   [CPU Leak]  [FD Leak]  │  Smoothed CPU graph          │
│   Live processes         │  Agent monologue             │
└────────────────────┬───────────┴──────────────────────┘
                     │ HTTP/SSE
          ┌──────────▼──────────┐
          │  Go Daemon (:8080)  │
          │  eBPF (Linux) OR    │
          │  ps-poll (macOS)    │
          └──┬──────────────┬───┘
    kernel   │              │ REST /mitigate
    events   │    ┌─────────▼──────────┐
             │    │  LangGraph Agent   │
             │    │  (Python)          │
             │    │  IDLE→ANALYZING    │
             │    │  →PLANNING         │
             │    │  →EXECUTING        │
             │    │  →VERIFYING        │
             │    │  →RESOLVED         │
             │    └─────────┬──────────┘
             │              │
             │    ┌─────────▼──────────┐
             └───►│  Redis             │
                  │  - monologue log   │
                  │  - incident store  │
                  │  - metrics cache   │
                  └────────────────────┘
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Kernel Interface | Go + [cilium/ebpf](https://github.com/cilium/ebpf) (Linux eBPF tracepoints) |
| Mock Mode | Go ps-polling — works on macOS, no root needed |
| AI Orchestration | [LangGraph](https://github.com/langchain-ai/langgraph) + GPT-5.4 (OpenAI) |
| Data Store | Redis (metrics, monologue, incident history) |
| Dashboard | React + Vite + Node API |
| Container | Docker Compose |

## Quick Start (macOS / Mock Mode)

### 1. Prerequisites

```bash
brew install go redis
# Start Redis
brew services start redis
```

### 2. Go Daemon

```bash
cd daemon
go mod tidy
go run ./cmd/daemon --mock --cpu-threshold=80
# Daemon API now available at http://localhost:8080
```

### 3. Python Agent

```bash
cd agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Create .env
cp ../.env.example .env
# Edit .env and set OPENAI_API_KEY=sk-...

python main.py
```

### 4. Dashboard

```bash
cd dashboard
npm install
npm run dev
# Open http://localhost:8501
```

### 5. Trigger a Demo

Open the dashboard, click **CPU Leak**, then watch:
1. The CPU graph separates standard process load from leak/suspect load
2. The agent monologue appear (`ANALYZING → EXECUTING → VERIFYING → RESOLVED`)
3. CPU return to baseline

Or from CLI:
```bash
make test-cpu-leak
```

## Linux (Real eBPF Mode)

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool cpulimit

# Generate vmlinux.h from your running kernel
make bpf-compile
```

### Run

```bash
# Daemon must run as root for eBPF
sudo go run ./daemon/cmd/daemon --cpu-threshold=80 --fd-threshold=200
```

## Docker Compose (Full Stack, Linux)

```bash
cp .env.example .env
# Set OPENAI_API_KEY in .env

docker compose up --build
# Dashboard: http://localhost:8501
# Daemon API: http://localhost:8080
```

## Architecture Deep Dive

### Go Daemon

The daemon has two monitoring modes:

**Mock mode** (`--mock`): Polls `ps aux` every second. Fires alerts when a PID sustains >80% CPU for 3+ consecutive seconds. Works anywhere with no privileges.

**eBPF mode** (Linux, root): Attaches tracepoints:
- `sched/sched_switch` — tracks per-PID CPU time in 100ms windows
- `syscalls/sys_enter_openat` — counts file opens per PID per second

BPF maps accumulate stats; when a threshold is crossed, a `perf_event_output` fires and the Go userspace reader emits a structured `KernelEvent` to all SSE subscribers.

**Mitigation actions** (applied via normal OS APIs, not eBPF):

| Action | Mechanism | Privilege |
|--------|-----------|-----------|
| `throttle_cpu` | `cpulimit` or cgroup v2 `cpu.max` | root for cgroup |
| `suspend` | `SIGSTOP` | own process or root |
| `resume` | `SIGCONT` | own process or root |
| `set_rlimit_fd` | `prlimit(2)` | root (Linux) |
| `kill` | `SIGKILL` | own process or root |

### LangGraph Agent

The state machine follows this flow:

```
IDLE ──► ANALYZE (LLM + get_processes tool)
              │
              ▼
         PLAN + EXECUTE (LLM + throttle_cpu/suspend/kill tools)
              │
              ▼
         VERIFY (LLM + get_processes, checks if CPU normalized)
              │
         ┌────┴──────────────┐
         │ resolved?          │ no, attempts < 3?
         ▼                    ▼
      RESOLVED            PLAN + EXECUTE (escalate)
```

The LLM (GPT-5.4) writes the "internal monologue" at each step. These are streamed to Redis and displayed live in the dashboard.

### Redis Schema

```
monologue          LIST  (lpush) — agent monologue entries (JSON), capped at 500
incidents          LIST  (lpush) — resolved incident IDs, capped at 100
incident:<ms>      HASH  — data=JSON, timestamp=float
metrics:<pid>      LIST  — {ts, cpu, mem} metrics, capped at 300, TTL 1h
monologue_stream   PubSub channel — real-time monologue streaming
```

## Project Structure

```
neural-ebpf/
├── daemon/
│   ├── cmd/daemon/main.go          # Entrypoint
│   ├── internal/
│   │   ├── monitor/
│   │   │   ├── monitor.go          # Core monitor, pub/sub
│   │   │   ├── mock.go             # ps-polling mode
│   │   │   ├── ebpf.go             # eBPF loader (Linux)
│   │   │   ├── ebpf_stub.go        # Stub for non-Linux
│   │   │   ├── mitigate.go         # Mitigation actions
│   │   │   ├── types.go            # Event/request types
│   │   │   └── util.go             # /proc helpers
│   │   └── api/server.go           # HTTP + SSE server
│   ├── bpf/
│   │   ├── cpu_monitor.bpf.c       # sched_switch tracepoint
│   │   ├── fd_monitor.bpf.c        # openat tracepoint
│   │   └── Makefile                # clang build
│   ├── Dockerfile
│   └── go.mod
├── agent/
│   ├── main.py                     # SSE listener + thread pool
│   ├── agent.py                    # LangGraph state machine
│   ├── tools.py                    # Daemon API tools
│   ├── redis_store.py              # Persistence layer
│   ├── requirements.txt
│   └── Dockerfile
├── dashboard/
│   ├── src/                        # React Surgery Console
│   ├── server.js                   # Node API for daemon/Redis/scripts
│   ├── package.json
│   └── Dockerfile
├── scripts/
│   ├── cpu_leak.py                 # CPU anomaly simulator
│   └── fd_leak.py                  # FD anomaly simulator
├── docker-compose.yml
├── Makefile
└── .env.example
```

## Action Items (Manual Steps Required)

See the **Action Items** section at the bottom of this README for steps that require your environment.

---

### Action Items for You

1. **`go mod tidy`** — Run `cd daemon && go mod tidy` to generate `go.sum` and download dependencies (`cilium/ebpf`, `gorilla/mux`).

2. **Set `OPENAI_API_KEY`** — Copy `.env.example` to `.env` and fill in your OpenAI API key.

3. **eBPF compilation (Linux only)** — On a Linux machine/VM:
   ```bash
   sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
   cd daemon/bpf && make all
   ```
   This generates `cpu_monitor.bpf.o` and `fd_monitor.bpf.o`.

4. **`vmlinux.h`** — The eBPF C programs include `vmlinux.h` (BTF type definitions). Generate it on your target Linux machine:
   ```bash
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > daemon/bpf/vmlinux.h
   ```

5. **Install `cpulimit`** — For CPU throttling to work on macOS: `brew install cpulimit`. On Linux: `apt-get install cpulimit`.

6. **Redis** — `brew services start redis` (macOS) or `docker compose up redis -d`.

7. **Local dependencies** — Create a Python venv for `agent/`, then install `agent/requirements.txt`. Run `npm install` in `dashboard/`.

8. **Test the demo** — Run `make dev-daemon` + `make dev-agent` + `make dev-dashboard` in three terminal tabs, then open `http://localhost:8501` and click CPU Leak.
