package monitor

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

type Config struct {
	Mock            bool
	CPUThreshold    float64
	FDThreshold     int
	WatchdogTimeout time.Duration // 0 = disabled
	// CPUSpikerDelta is the minimum percentage-point rise above a process's
	// rolling 30-second baseline required to fire a CPU anomaly alert.
	// Prevents false positives from processes that legitimately run hot (e.g. WindowServer).
	// Default: 30.0 (alert only if CPU rose ≥30pp above the process's own normal level).
	CPUSpikerDelta float64
}

type Monitor struct {
	cfg       Config
	events    chan KernelEvent
	subs      []chan KernelEvent
	subsMu    sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	processes map[int]*ProcessStats
	procMu    sync.RWMutex
	wdTimeout time.Duration
	wdMu      sync.RWMutex
}

func New(cfg Config) *Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Monitor{
		cfg:       cfg,
		events:    make(chan KernelEvent, 256),
		processes: make(map[int]*ProcessStats),
		ctx:       ctx,
		cancel:    cancel,
		wdTimeout: cfg.WatchdogTimeout,
	}
}

// SetWatchdogTimeout updates the watchdog kill timeout at runtime.
// 0 disables the watchdog.
func (m *Monitor) SetWatchdogTimeout(d time.Duration) {
	m.wdMu.Lock()
	m.wdTimeout = d
	m.wdMu.Unlock()
	log.Printf("[watchdog] timeout set to %.0fs", d.Seconds())
}

func (m *Monitor) getWatchdogTimeout() time.Duration {
	m.wdMu.RLock()
	defer m.wdMu.RUnlock()
	return m.wdTimeout
}

func (m *Monitor) Start() error {
	if m.cfg.Mock {
		log.Println("[monitor] starting in mock mode (ps polling)")
		go m.runMockPoller()
	} else {
		log.Println("[monitor] starting eBPF mode")
		go m.runEBPF()
	}
	go m.fanout()
	return nil
}

func (m *Monitor) Stop() {
	m.cancel()
}

// Subscribe returns a channel that receives all future events. Call Unsubscribe to clean up.
func (m *Monitor) Subscribe() chan KernelEvent {
	ch := make(chan KernelEvent, 64)
	m.subsMu.Lock()
	m.subs = append(m.subs, ch)
	m.subsMu.Unlock()
	return ch
}

func (m *Monitor) Unsubscribe(ch chan KernelEvent) {
	m.subsMu.Lock()
	defer m.subsMu.Unlock()
	for i, s := range m.subs {
		if s == ch {
			m.subs = append(m.subs[:i], m.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

func (m *Monitor) GetProcesses() []ProcessStats {
	m.procMu.RLock()
	defer m.procMu.RUnlock()
	out := make([]ProcessStats, 0, len(m.processes))
	for _, p := range m.processes {
		out = append(out, *p)
	}
	return out
}

func (m *Monitor) Mitigate(req MitigationRequest) MitigationResult {
	switch req.Action {
	case ActionKill:
		return killProcess(req)
	case ActionSuspend:
		return suspendProcess(req)
	case ActionResume:
		return resumeProcess(req)
	case ActionThrottleCPU:
		return throttleCPU(req)
	case ActionSetRlimitFD:
		return setRlimitFD(req)
	default:
		return MitigationResult{Success: false, Message: fmt.Sprintf("unknown action: %s", req.Action)}
	}
}

func (m *Monitor) IsMock() bool {
	return m.cfg.Mock
}

func (m *Monitor) Emit(ev KernelEvent) {
	select {
	case m.events <- ev:
	default:
		log.Println("[monitor] event channel full, dropping event")
	}
}

func (m *Monitor) fanout() {
	for {
		select {
		case ev := <-m.events:
			m.subsMu.Lock()
			for _, ch := range m.subs {
				select {
				case ch <- ev:
				default:
				}
			}
			m.subsMu.Unlock()
		case <-m.ctx.Done():
			return
		}
	}
}

func newEventID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
