//go:build linux

package monitor

import (
	"fmt"
	"os"
)

func getFDCount(pid int) int {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0
	}
	return len(entries)
}

func populateFDCounts(procs []ProcessStats) {
	for i := range procs {
		entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", procs[i].PID))
		if err == nil {
			procs[i].FDCount = len(entries)
		}
	}
}
