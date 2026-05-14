//go:build linux

package monitor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// BPF event struct (must match cpu_monitor.bpf.c)
type bpfCPUEvent struct {
	PID      uint32
	CPU      uint32
	Duration uint64 // nanoseconds
}

func (m *Monitor) runEBPF() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("[ebpf] removeMemlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("bpf/cpu_monitor.bpf.o")
	if err != nil {
		log.Fatalf("[ebpf] load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("[ebpf] new collection: %v", err)
	}
	defer coll.Close()

	// Set threshold in BPF map.
	// bpfWindowNS must match WINDOW_NS in cpu_monitor.bpf.c (100ms).
	// The threshold is expressed as CPU-ns accumulated within that window.
	const bpfWindowNS = 100_000_000
	threshMap := coll.Maps["cpu_threshold"]
	if threshMap != nil {
		key := uint32(0)
		val := uint64(m.cfg.CPUThreshold) * bpfWindowNS / 100
		_ = threshMap.Put(key, val)
	}

	// Attach tracepoint sched/sched_switch
	tp, err := link.Tracepoint("sched", "sched_switch", coll.Programs["trace_sched_switch"], nil)
	if err != nil {
		log.Fatalf("[ebpf] tracepoint: %v", err)
	}
	defer tp.Close()

	// Read from perf ring
	rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize()*64)
	if err != nil {
		log.Fatalf("[ebpf] perf reader: %v", err)
	}
	defer rd.Close()

	log.Println("[ebpf] monitoring sched_switch events")

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			log.Printf("[ebpf] read error: %v", err)
			continue
		}

		var ev bpfCPUEvent
		if err := parseBPFEvent(record.RawSample, &ev); err != nil {
			continue
		}

		name := getProcessName(int(ev.PID))
		stats := ProcessStats{
			PID:        int(ev.PID),
			Name:       name,
			CPUPercent: float64(ev.Duration) / 1e6, // ns in 100ms window → percent (80ms/100ms = 80%)
			FDCount:    getFDCount(int(ev.PID)),
		}

		m.procMu.Lock()
		m.processes[int(ev.PID)] = &stats
		m.procMu.Unlock()

		if stats.CPUPercent >= m.cfg.CPUThreshold {
			kev := KernelEvent{
				ID:        newEventID(),
				Timestamp: time.Now(),
				Type:      EventCPUAnomaly,
				PID:       int(ev.PID),
				Process:   stats,
				Message: fmt.Sprintf("[eBPF] PID %d (%s) exceeded CPU threshold: %.1f%%",
					ev.PID, name, stats.CPUPercent),
			}
			kev.ProcessClass, kev.AnomalyType = ClassifyProcess(&kev)
			m.Emit(kev)
		}
	}
}

func parseBPFEvent(data []byte, ev *bpfCPUEvent) error {
	if len(data) < 16 {
		return fmt.Errorf("short event: %d bytes", len(data))
	}
	ev.PID = binary.LittleEndian.Uint32(data[0:4])
	ev.CPU = binary.LittleEndian.Uint32(data[4:8])
	ev.Duration = binary.LittleEndian.Uint64(data[8:16])
	return nil
}
