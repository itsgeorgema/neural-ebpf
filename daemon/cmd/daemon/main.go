package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/itsgeorgema/neural-ebpf/daemon/internal/api"
	"github.com/itsgeorgema/neural-ebpf/daemon/internal/monitor"
)

func main() {
	mock := flag.Bool("mock", false, "Mock mode: use ps-polling instead of eBPF (works on macOS)")
	port := flag.String("port", "8080", "HTTP API listen port")
	cpuThreshold := flag.Float64("cpu-threshold", 80.0, "CPU% threshold to trigger alert")
	fdThreshold := flag.Int("fd-threshold", 200, "Open FD count threshold to trigger alert")
	flag.Parse()

	mon := monitor.New(monitor.Config{
		Mock:         *mock,
		CPUThreshold: *cpuThreshold,
		FDThreshold:  *fdThreshold,
	})

	srv := api.New(mon, *port)

	go func() {
		if err := mon.Start(); err != nil {
			log.Fatalf("monitor failed: %v", err)
		}
	}()

	go func() {
		log.Printf("Neural eBPF daemon listening on :%s (mock=%v, cpu_thresh=%.0f%%, fd_thresh=%d)",
			*port, *mock, *cpuThreshold, *fdThreshold)
		if err := srv.Run(); err != nil {
			log.Fatalf("api server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down daemon...")
	mon.Stop()
}
