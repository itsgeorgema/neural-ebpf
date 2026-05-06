//go:build !linux

package monitor

import "log"

// runEBPF is a stub for non-Linux platforms. Use --mock flag instead.
func (m *Monitor) runEBPF() {
	log.Println("[ebpf] eBPF is Linux-only. Falling back to mock mode.")
	m.cfg.Mock = true
	m.runMockPoller()
}
