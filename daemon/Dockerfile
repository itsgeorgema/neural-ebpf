FROM golang:1.22-bookworm AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Build the eBPF objects first
RUN apt-get update && apt-get install -y clang llvm libbpf-dev linux-headers-generic bpftool
RUN make -C bpf all

# Build the Go binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /daemon ./cmd/daemon

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates iproute2 cpulimit util-linux && rm -rf /var/lib/apt/lists/*
COPY --from=builder /daemon /daemon
COPY --from=builder /app/bpf/*.o /bpf/
ENTRYPOINT ["/daemon"]
