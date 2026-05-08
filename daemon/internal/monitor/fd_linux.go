//go:build linux

package monitor

import (
	"fmt"
	"os"
)

func populateFDCounts(procs []ProcessStats) {
	for i := range procs {
		entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", procs[i].PID))
		if err == nil {
			procs[i].FDCount = len(entries)
		}
	}
}
