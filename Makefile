.PHONY: help dev-daemon dev-agent dev-dashboard dev install-tools bpf-compile go-tidy dashboard-build \
        k8s-up k8s-down k8s-rebuild k8s-status

help:
	@echo ""
	@echo "Neural eBPF — Self-Healing Kernel Agent"
	@echo "========================================"
	@echo "  make dev             Start Redis + all services locally (mock mode)"
	@echo "  make dev-daemon      Run Go daemon in mock mode (macOS/Linux)"
	@echo "  make dev-agent       Run Python agent"
	@echo "  make dev-dashboard   Run React dashboard"
	@echo "  make dashboard-build Build React dashboard"
	@echo "  make bpf-compile     Compile eBPF C programs (Linux only)"
	@echo "  make go-tidy         Run go mod tidy"
	@echo "  make install-tools   Install Python + Node dependencies"
	@echo "  make k8s-up          Build images and deploy full stack to Minikube"
	@echo "  make k8s-down        Tear down Minikube deployment"
	@echo "  make k8s-rebuild     Rebuild images and restart all deployments"
	@echo "  make k8s-status      Show pod status in the neural-ebpf namespace"
	@echo ""

dev-daemon:
	cd daemon && go run ./cmd/daemon --mock --cpu-threshold=80 --fd-threshold=200

dev-agent:
	@if [ ! -d agent/.venv ]; then \
		echo "Creating virtual environment at agent/.venv ..."; \
		python3 -m venv agent/.venv; \
	fi
	@echo "Installing Python dependencies into agent/.venv ..."
	agent/.venv/bin/pip install -q -r agent/requirements.txt
	cd agent && .venv/bin/python main.py

dev-dashboard:
	cd dashboard && npm run dev

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
	@if [ ! -d agent/.venv ]; then \
		echo "Creating virtual environment at agent/.venv ..."; \
		python3 -m venv agent/.venv; \
	fi
	agent/.venv/bin/pip install -r agent/requirements.txt
	cd dashboard && npm install

dashboard-build:
	cd dashboard && npm run build

k8s-up:
	@test -f .env || (echo "Error: .env not found. Copy .env.example and set OPENAI_API_KEY." && exit 1)
	minikube start
	minikube image build -t neural-ebpf/daemon:latest ./daemon
	minikube image build -t neural-ebpf/agent:latest ./agent
	minikube image build -t neural-ebpf/dashboard:latest -f dashboard/Dockerfile .
	kubectl apply -f k8s/00-namespace.yaml
	@OPENAI_KEY=$$(grep ^OPENAI_API_KEY .env | cut -d= -f2-); \
	kubectl create secret generic openai-secret \
		--from-literal=OPENAI_API_KEY=$$OPENAI_KEY \
		-n neural-ebpf \
		--dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f k8s/
	@echo ""
	@echo "Waiting for pods..."
	kubectl wait --for=condition=ready pod -l app=dashboard -n neural-ebpf --timeout=120s
	@echo ""
	@echo "Stack is ready. To open service tunnels (Docker driver on macOS requires these to stay open):"
	@echo "  minikube service dashboard -n neural-ebpf --url"
	@echo "  minikube service daemon -n neural-ebpf --url"

k8s-down:
	kubectl delete namespace neural-ebpf --ignore-not-found
	minikube stop

k8s-rebuild:
	minikube image build -t neural-ebpf/daemon:latest ./daemon
	minikube image build -t neural-ebpf/agent:latest ./agent
	minikube image build -t neural-ebpf/dashboard:latest -f dashboard/Dockerfile .
	kubectl rollout restart deployment -n neural-ebpf

k8s-status:
	kubectl get pods -n neural-ebpf

test-cpu-leak:
	python scripts/cpu_leak.py --duration 30 --threads 2

test-fd-leak:
	python scripts/fd_leak.py --duration 30 --rate 300
