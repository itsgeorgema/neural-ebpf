package monitor

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// cpuHistoryWindow is the number of 1-second poll samples retained per PID.
// 30 samples = 30 seconds of history used to compute the per-process baseline.
const cpuHistoryWindow = 30

// fdHistoryWindow is the number of 1-second poll samples retained per PID.
// The mock poller uses it to distinguish real FD growth from desktop apps that
// legitimately keep hundreds of descriptors open at a stable baseline.
const fdHistoryWindow = 10

const fdGrowthThreshold = 100

// isCPUSpike returns true when current CPU represents a genuine anomaly rather
// than a process's normal operating level.
//
// Algorithm: sort the recent history and take the 20th percentile as the
// process's "quiet baseline". Alert only if the current reading exceeds that
// baseline by at least spikerDelta percentage points.
//
// Examples with spikerDelta=30:
//   - WindowServer stable at 50%:  baseline≈50%, delta=0  → false (no alert)
//   - WindowServer spikes to 95%:  baseline≈50%, delta=45 → true  (alert)
//   - leak script  0%→90%:         baseline≈2%,  delta=88 → true  (alert)
//
// If fewer than 5 samples exist (new process), falls back to pure threshold.
func isCPUSpike(history []float64, current, spikerDelta float64) bool {
	if len(history) < 5 {
		return true // not enough history — trust the raw threshold
	}
	sorted := make([]float64, len(history))
	copy(sorted, history)
	sort.Float64s(sorted)
	baseline := sorted[len(sorted)/5] // 20th percentile
	return current >= baseline+spikerDelta
}

func isFDLeakGrowth(history []int, current int) bool {
	if len(history) < 5 {
		return false
	}
	minFDs := history[0]
	for _, count := range history[1:] {
		if count < minFDs {
			minFDs = count
		}
	}
	return current >= minFDs+fdGrowthThreshold
}

// runMockPoller polls `ps aux` every second to detect anomalies.
// Works on macOS and Linux without any kernel privileges.
func (m *Monitor) runMockPoller() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	// Track consecutive high-CPU seconds per PID to avoid alert storms
	highCPUCount := make(map[int]int)
	alertedPIDs := make(map[int]bool)
	fdSuppressed := make(map[int]bool)
	// cpuHistory[pid] = rolling window of recent CPU% readings for baseline computation
	cpuHistory := make(map[int][]float64)
	// fdHistory[pid] = rolling window of recent FD counts for leak-growth detection
	fdHistory := make(map[int][]int)
	// watchdogDeadlines[pid] = time after which the daemon force-kills if still anomalous
	watchdogDeadlines := make(map[int]time.Time)

	spikerDelta := m.cfg.CPUSpikerDelta
	if spikerDelta <= 0 {
		spikerDelta = 30.0
	}

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
				// Always update the rolling history so the baseline stays current.
				h := cpuHistory[p.PID]
				h = append(h, p.CPUPercent)
				if len(h) > cpuHistoryWindow {
					h = h[len(h)-cpuHistoryWindow:]
				}
				cpuHistory[p.PID] = h

				fh := fdHistory[p.PID]
				fh = append(fh, p.FDCount)
				if len(fh) > fdHistoryWindow {
					fh = fh[len(fh)-fdHistoryWindow:]
				}
				fdHistory[p.PID] = fh

				if p.CPUPercent >= m.cfg.CPUThreshold {
					highCPUCount[p.PID]++
					// Alert after 3 consecutive high-CPU seconds
					if highCPUCount[p.PID] >= 3 && !alertedPIDs[p.PID] {
						// Classify before deciding whether to alert.
						tmpEv := KernelEvent{PID: p.PID, Process: p, Type: EventCPUAnomaly}
						procClass, _ := ClassifyProcess(&tmpEv)

						// Baseline spike gate — skip if this is just the process's normal level.
						// Leak simulators are exempt: alert immediately (no benefit of the doubt).
						if procClass != ClassLeakSimulator && !isCPUSpike(h, p.CPUPercent, spikerDelta) {
							log.Printf("[mock] suppressed alert for PID %d (%s) at %.1f%% — within normal baseline (class=%s)",
								p.PID, p.Name, p.CPUPercent, procClass)
							continue
						}

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
						ev.ProcessClass, ev.AnomalyType = ClassifyProcess(&ev)
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

				// FD anomaly check — populateFDCounts uses lsof on macOS, /proc on Linux.
				fdKey := -p.PID
				if p.FDCount >= m.cfg.FDThreshold {
					if !alertedPIDs[fdKey] {
						tmpEv := KernelEvent{PID: p.PID, Process: p, Type: EventFDAnomaly}
						procClass, _ := ClassifyProcess(&tmpEv)
						if procClass != ClassLeakSimulator && !isFDLeakGrowth(fh, p.FDCount) {
							if !fdSuppressed[fdKey] {
								log.Printf("[mock] suppressed FD alert for PID %d (%s) at %d FDs — stable baseline (class=%s)",
									p.PID, p.Name, p.FDCount, procClass)
								fdSuppressed[fdKey] = true
							}
							continue
						}

						alertedPIDs[fdKey] = true
						delete(fdSuppressed, fdKey)
						ev := KernelEvent{
							ID:        newEventID(),
							Timestamp: time.Now(),
							Type:      EventFDAnomaly,
							PID:       p.PID,
							Process:   p,
							Message:   fmt.Sprintf("PID %d (%s) has %d open file descriptors", p.PID, p.Name, p.FDCount),
						}
						ev.ProcessClass, ev.AnomalyType = ClassifyProcess(&ev)
						m.Emit(ev)
					}
				} else {
					delete(fdSuppressed, fdKey)
					if alertedPIDs[fdKey] {
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

			// Cleanup state for PIDs that no longer exist.
			livePIDs := make(map[int]bool, len(procs))
			for _, p := range procs {
				livePIDs[p.PID] = true
			}
			for pid := range alertedPIDs {
				absPID := pid
				if absPID < 0 {
					absPID = -pid
				}
				if !livePIDs[absPID] {
					delete(alertedPIDs, pid)
					delete(highCPUCount, pid)
					delete(watchdogDeadlines, pid)
					delete(cpuHistory, pid)
					delete(fdHistory, pid)
					delete(fdSuppressed, pid)
				}
			}
			for pid := range fdSuppressed {
				absPID := pid
				if absPID < 0 {
					absPID = -pid
				}
				if !livePIDs[absPID] {
					delete(fdSuppressed, pid)
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
