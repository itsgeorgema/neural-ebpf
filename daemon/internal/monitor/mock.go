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
	// watchdogDeadlines[pid] = time after which the daemon force-kills if still anomalous
	watchdogDeadlines := make(map[int]time.Time)

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
						// Arm watchdog deadline if configured
						if wd := m.getWatchdogTimeout(); wd > 0 {
							watchdogDeadlines[p.PID] = time.Now().Add(wd)
							log.Printf("[watchdog] armed for PID %d — will force-kill at %s if unresolved",
								p.PID, watchdogDeadlines[p.PID].Format("15:04:05"))
						}
					}
				} else {
					if alertedPIDs[p.PID] {
						// Process recovered — agent succeeded
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
						delete(watchdogDeadlines, p.PID)
					}
					highCPUCount[p.PID] = 0
				}

				// FD anomaly check (Linux only via /proc; skip on macOS gracefully)
				fdKey := -p.PID
				if p.FDCount >= m.cfg.FDThreshold {
					if !alertedPIDs[fdKey] {
						alertedPIDs[fdKey] = true
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
				} else if alertedPIDs[fdKey] {
					delete(alertedPIDs, fdKey)
					ev := KernelEvent{
						ID:        newEventID(),
						Timestamp: time.Now(),
						Type:      EventResolved,
						PID:       p.PID,
						Process:   p,
						Message:   fmt.Sprintf("PID %d (%s) FD count normalized to %d", p.PID, p.Name, p.FDCount),
					}
					m.Emit(ev)
				}
			}

			// Watchdog: force-kill any PID whose deadline has passed and is still anomalous
			now := time.Now()
			for pid, deadline := range watchdogDeadlines {
				if now.Before(deadline) {
					continue
				}
				// Check if still present and still consuming high CPU
				m.procMu.RLock()
				proc, alive := m.processes[pid]
				m.procMu.RUnlock()
				if !alive || proc.CPUPercent < m.cfg.CPUThreshold {
					// Already gone or already recovered — agent succeeded
					delete(watchdogDeadlines, pid)
					continue
				}
				elapsed := now.Sub(deadline.Add(-m.getWatchdogTimeout()))
				log.Printf("[watchdog] AGENT FAILED: PID %d (%s) still at %.1f%% CPU after %.0fs — forcing kill",
					pid, proc.Name, proc.CPUPercent, elapsed.Seconds())
				killProcess(MitigationRequest{
					PID:    pid,
					Action: ActionKill,
					Reason: fmt.Sprintf("watchdog: agent failed to mitigate within %.0fs", m.getWatchdogTimeout().Seconds()),
				})
				ev := KernelEvent{
					ID:        newEventID(),
					Timestamp: now,
					Type:      EventWatchdogKill,
					PID:       pid,
					Process:   *proc,
					Message: fmt.Sprintf("Watchdog force-killed PID %d (%s) after %.0fs — agent failed to mitigate",
						pid, proc.Name, elapsed.Seconds()),
				}
				m.Emit(ev)
				delete(watchdogDeadlines, pid)
				delete(alertedPIDs, pid)
				highCPUCount[pid] = 0
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
					delete(watchdogDeadlines, pid)
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

		// Process name: first word of command column
		name := fields[10]
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}

		// Full command line (executable + all args)
		cmdLine := strings.Join(fields[10:], " ")

		// STAT column (fields[7]) contains "T" when the process is stopped (SIGSTOP).
		stat := ""
		if len(fields) > 7 {
			stat = fields[7]
		}

		p := ProcessStats{
			PID:        pid,
			Name:       name,
			CPUPercent: cpu,
			MemMB:      mem,
			CmdLine:    cmdLine,
			Stopped:    strings.ContainsRune(stat, 'T'),
		}

		procs = append(procs, p)
	}
	populateFDCounts(procs)
	return procs, nil
}
