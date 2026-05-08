package monitor

import "time"

type EventType string

const (
	EventCPUAnomaly   EventType = "cpu_anomaly"
	EventFDAnomaly    EventType = "fd_anomaly"
	EventResolved     EventType = "resolved"
	EventWatchdogKill EventType = "watchdog_kill"
)

type ProcessStats struct {
	PID        int     `json:"pid"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	FDCount    int     `json:"fd_count"`
	MemMB      float64 `json:"mem_mb"`
}

type KernelEvent struct {
	ID        string       `json:"id"`
	Timestamp time.Time    `json:"timestamp"`
	Type      EventType    `json:"type"`
	PID       int          `json:"pid"`
	Process   ProcessStats `json:"process"`
	Message   string       `json:"message"`
}

type MitigationAction string

const (
	ActionThrottleCPU  MitigationAction = "throttle_cpu"
	ActionKill         MitigationAction = "kill"
	ActionSuspend      MitigationAction = "suspend"
	ActionResume       MitigationAction = "resume"
	ActionSetRlimitFD  MitigationAction = "set_rlimit_fd"
)

type MitigationRequest struct {
	PID    int              `json:"pid"`
	Action MitigationAction `json:"action"`
	// ThrottlePercent: 0-100, used with ActionThrottleCPU
	ThrottlePercent int    `json:"throttle_percent,omitempty"`
	Reason          string `json:"reason"`
}

type MitigationResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	PID     int    `json:"pid"`
	Action  string `json:"action"`
}
