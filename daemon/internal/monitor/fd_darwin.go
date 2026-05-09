//go:build darwin

package monitor

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

// populateFDCounts runs a single lsof call for all PIDs and populates FDCount
// for each ProcessStats. One batched call avoids the overhead of per-process lsof.
func populateFDCounts(procs []ProcessStats) {
	if len(procs) == 0 {
		return
	}

	// Build comma-separated PID list
	pidStrs := make([]string, len(procs))
	for i, p := range procs {
		pidStrs[i] = strconv.Itoa(p.PID)
	}

	// -F fp: output only pid (p) and fd (f) fields in parseable format
	// -p ...: limit scan to our PID list
	cmd := exec.Command("lsof", "-F", "fp", "-p", strings.Join(pidStrs, ","))
	var out bytes.Buffer
	cmd.Stdout = &out
	// lsof exits 1 when it can't inspect some PIDs (e.g. root-owned processes on macOS).
	// Parse whatever output arrived rather than bailing on a partial failure.
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return
	}

	// Parse: lines starting with 'p' set current pid, lines starting with 'f'
	// followed by a digit are real open file descriptors (not cwd/txt/mem/etc.)
	counts := make(map[int]int, len(procs))
	var currentPID int
	for _, line := range strings.Split(out.String(), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			if pid, err := strconv.Atoi(line[1:]); err == nil {
				currentPID = pid
			}
		case 'f':
			if line[1] >= '0' && line[1] <= '9' {
				counts[currentPID]++
			}
		}
	}

	for i := range procs {
		if c, ok := counts[procs[i].PID]; ok {
			procs[i].FDCount = c
		}
	}
}
