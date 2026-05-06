.PHONY: help dev-daemon dev-agent dev-dashboard dev install-tools bpf-compile go-tidy

help:
	@echo ""
	@echo "Neural eBPF — Self-Healing Kernel Agent"
	@echo "========================================"
	@echo "  make dev           Start Redis + all services locally (mock mode)"
	@echo "  make dev-daemon    Run Go daemon in mock mode (macOS/Linux)"
	@echo "  make dev-agent     Run Python agent"
	@echo "  make dev-dashboard Run Streamlit dashboard"
	@echo "  make bpf-compile   Compile eBPF C programs (Linux only)"
	@echo "  make go-tidy       Run go mod tidy"
	@echo "  make install-tools Install Python dependencies"
	@echo "  make docker-up     Start all services via Docker Compose"
	@echo "  make docker-down   Stop Docker Compose services"
	@echo ""

dev-daemon:
	cd daemon && go run ./cmd/daemon --mock --cpu-threshold=80 --fd-threshold=200

dev-agent:
	cd agent && python main.py

dev-dashboard:
	cd dashboard && streamlit run app.py

dev:
	@echo "Starting Redis in Docker, then all services..."
	docker compose up redis -d
	@echo "Open 3 terminals and run:"
	@echo "  make dev-daemon"
	@echo "  make dev-agent"
	@echo "  make dev-dashboard"

bpf-compile:
	$(MAKE) -C daemon/bpf all

go-tidy:
	cd daemon && go mod tidy

install-tools:
	pip install -r agent/requirements.txt
	pip install -r dashboard/requirements.txt

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v

test-cpu-leak:
	python scripts/cpu_leak.py --duration 30 --threads 2

test-fd-leak:
	python scripts/fd_leak.py --duration 30 --rate 300
