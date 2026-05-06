package monitor

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// runMockPoller polls `ps aux` every second to detect anomalies.
// Works on macOS and Linux without any kernel privileges.
func (m *Monitor) runMockPoller() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	// Track consecutive high-CPU seconds per PID to avoid alert storms
	highCPUCount := make(map[int]int)
	alertedPIDs := make(map[int]bool)

	for {
		select {
		case <-ticker.C:
			procs, err := parsePSAux()
			if err != nil {
				log.Printf("[mock] ps error: %v", err)
				continue
			}

			m.procMu.Lock()
			m.processes = make(map[int]*ProcessStats)
			for i := range procs {
				p := &procs[i]
				m.processes[p.PID] = p
			}
			m.procMu.Unlock()

			for _, p := range procs {
				if p.CPUPercent >= m.cfg.CPUThreshold {
					highCPUCount[p.PID]++
					// Alert after 3 consecutive high-CPU seconds
					if highCPUCount[p.PID] >= 3 && !alertedPIDs[p.PID] {
						alertedPIDs[p.PID] = true
						ev := KernelEvent{
							ID:        newEventID(),
							Timestamp: time.Now(),
							Type:      EventCPUAnomaly,
							PID:       p.PID,
							Process:   p,
							Message: fmt.Sprintf("PID %d (%s) consuming %.1f%% CPU for %d consecutive seconds",
								p.PID, p.Name, p.CPUPercent, highCPUCount[p.PID]),
						}
						log.Printf("[mock] ALERT: %s", ev.Message)
						m.Emit(ev)
					}
				} else {
					if alertedPIDs[p.PID] {
						// Process recovered
						ev := KernelEvent{
							ID:        newEventID(),
							Timestamp: time.Now(),
							Type:      EventResolved,
							PID:       p.PID,
							Process:   p,
							Message:   fmt.Sprintf("PID %d (%s) CPU normalized to %.1f%%", p.PID, p.Name, p.CPUPercent),
						}
						m.Emit(ev)
						delete(alertedPIDs, p.PID)
					}
					highCPUCount[p.PID] = 0
				}

				// FD anomaly check (Linux only via /proc; skip on macOS gracefully)
				if p.FDCount >= m.cfg.FDThreshold && !alertedPIDs[-p.PID] {
					alertedPIDs[-p.PID] = true
					ev := KernelEvent{
						ID:        newEventID(),
						Timestamp: time.Now(),
						Type:      EventFDAnomaly,
						PID:       p.PID,
						Process:   p,
						Message:   fmt.Sprintf("PID %d (%s) has %d open file descriptors", p.PID, p.Name, p.FDCount),
					}
					m.Emit(ev)
				}
			}

			// Cleanup PIDs that no longer exist
			for pid := range alertedPIDs {
				absPID := pid
				if absPID < 0 {
					absPID = -pid
				}
				found := false
				for _, p := range procs {
					if p.PID == absPID {
						found = true
						break
					}
				}
				if !found {
					delete(alertedPIDs, pid)
					delete(highCPUCount, pid)
				}
			}

		case <-m.ctx.Done():
			return
		}
	}
}

func parsePSAux() ([]ProcessStats, error) {
	cmd := exec.Command("ps", "aux")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	var procs []ProcessStats
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		cpu, _ := strconv.ParseFloat(fields[2], 64)
		mem, _ := strconv.ParseFloat(fields[3], 64)

		// Process name: last field (command)
		name := fields[10]
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}

		p := ProcessStats{
			PID:        pid,
			Name:       name,
			CPUPercent: cpu,
			MemMB:      mem, // this is %MEM from ps, convert if needed
		}

		// Try to get FD count from /proc (Linux only)
		p.FDCount = getFDCount(pid)

		procs = append(procs, p)
	}
	return procs, nil
}
