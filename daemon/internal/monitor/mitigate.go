package monitor

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
)

func killProcess(req MitigationRequest) MitigationResult {
	proc, err := os.FindProcess(req.PID)
	if err != nil {
		return MitigationResult{false, fmt.Sprintf("find process: %v", err), req.PID, string(req.Action)}
	}
	if err := proc.Kill(); err != nil {
		return MitigationResult{false, fmt.Sprintf("kill: %v", err), req.PID, string(req.Action)}
	}
	log.Printf("[mitigate] killed PID %d: %s", req.PID, req.Reason)
	return MitigationResult{true, fmt.Sprintf("PID %d killed", req.PID), req.PID, string(req.Action)}
}

func suspendProcess(req MitigationRequest) MitigationResult {
	proc, err := os.FindProcess(req.PID)
	if err != nil {
		return MitigationResult{false, fmt.Sprintf("find process: %v", err), req.PID, string(req.Action)}
	}
	if err := proc.Signal(syscall.SIGSTOP); err != nil {
		return MitigationResult{false, fmt.Sprintf("SIGSTOP: %v", err), req.PID, string(req.Action)}
	}
	log.Printf("[mitigate] suspended PID %d: %s", req.PID, req.Reason)
	return MitigationResult{true, fmt.Sprintf("PID %d suspended (SIGSTOP)", req.PID), req.PID, string(req.Action)}
}

func resumeProcess(req MitigationRequest) MitigationResult {
	proc, err := os.FindProcess(req.PID)
	if err != nil {
		return MitigationResult{false, fmt.Sprintf("find process: %v", err), req.PID, string(req.Action)}
	}
	if err := proc.Signal(syscall.SIGCONT); err != nil {
		return MitigationResult{false, fmt.Sprintf("SIGCONT: %v", err), req.PID, string(req.Action)}
	}
	log.Printf("[mitigate] resumed PID %d: %s", req.PID, req.Reason)
	return MitigationResult{true, fmt.Sprintf("PID %d resumed (SIGCONT)", req.PID), req.PID, string(req.Action)}
}

// throttleCPU applies CPU throttling using platform-appropriate methods.
// Linux: cpulimit or cgroup v2 CPU bandwidth.
// macOS: cpulimit (if installed) or SIGSTOP/SIGCONT duty-cycle (best-effort).
func throttleCPU(req MitigationRequest) MitigationResult {
	pct := req.ThrottlePercent
	if pct <= 0 || pct > 100 {
		pct = 50
	}

	if runtime.GOOS == "linux" {
		return throttleCPULinux(req.PID, pct, req.Reason)
	}
	return throttleCPUMacOS(req.PID, pct, req.Reason)
}

func throttleCPULinux(pid, pct int, reason string) MitigationResult {
	// Try cpulimit first (user-space, no privileges needed)
	cmd := exec.Command("cpulimit", "--pid", strconv.Itoa(pid), "--limit", strconv.Itoa(pct), "--background")
	if err := cmd.Start(); err == nil {
		log.Printf("[mitigate] cpulimit %d%% on PID %d: %s", pct, pid, reason)
		return MitigationResult{true, fmt.Sprintf("CPU throttled to %d%% via cpulimit", pct), pid, "throttle_cpu"}
	}

	// Fall back to cgroup v2 if available
	if result := throttleCgroupV2(pid, pct); result.Success {
		log.Printf("[mitigate] cgroup CPU %d%% on PID %d: %s", pct, pid, reason)
		return result
	}

	return MitigationResult{false, "cpulimit not found and cgroup v2 not available; install cpulimit", pid, "throttle_cpu"}
}

func throttleCPUMacOS(pid, pct int, reason string) MitigationResult {
	// cpulimit is available on macOS via brew
	cmd := exec.Command("cpulimit", "--pid", strconv.Itoa(pid), "--limit", strconv.Itoa(pct), "--background")
	if err := cmd.Start(); err == nil {
		log.Printf("[mitigate] cpulimit %d%% on PID %d (macOS): %s", pct, pid, reason)
		return MitigationResult{true, fmt.Sprintf("CPU throttled to %d%% via cpulimit", pct), pid, "throttle_cpu"}
	}
	log.Printf("[mitigate] cpulimit not found for PID %d — throttle unavailable on macOS without cpulimit (brew install cpulimit)", pid)
	return MitigationResult{false, "cpulimit not found; install via 'brew install cpulimit' or escalate to kill_process", pid, "throttle_cpu"}
}

func throttleCgroupV2(pid, pct int) MitigationResult {
	cgPath := fmt.Sprintf("/sys/fs/cgroup/neural-ebpf-%d", pid)
	if err := os.MkdirAll(cgPath, 0755); err != nil {
		return MitigationResult{false, fmt.Sprintf("cgroup mkdir: %v", err), pid, "throttle_cpu"}
	}

	// CPU bandwidth: quota = pct% of 100ms period
	period := 100000 // 100ms in microseconds
	quota := period * pct / 100
	cpuMax := fmt.Sprintf("%d %d", quota, period)
	if err := os.WriteFile(cgPath+"/cpu.max", []byte(cpuMax), 0644); err != nil {
		return MitigationResult{false, fmt.Sprintf("cpu.max write: %v", err), pid, "throttle_cpu"}
	}
	if err := os.WriteFile(cgPath+"/cgroup.procs", []byte(strconv.Itoa(pid)), 0644); err != nil {
		return MitigationResult{false, fmt.Sprintf("cgroup.procs write: %v", err), pid, "throttle_cpu"}
	}
	return MitigationResult{true, fmt.Sprintf("cgroup v2 CPU limited to %d%%", pct), pid, "throttle_cpu"}
}

func setRlimitFD(req MitigationRequest) MitigationResult {
	// Can only set rlimits on our own process or children. Use prlimit on Linux.
	if runtime.GOOS != "linux" {
		return MitigationResult{false, "setrlimit on arbitrary PIDs is Linux-only (prlimit)", req.PID, string(req.Action)}
	}
	limit := "256"
	cmd := exec.Command("prlimit", fmt.Sprintf("--pid=%d", req.PID), fmt.Sprintf("--nofile=%s:%s", limit, limit))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return MitigationResult{false, fmt.Sprintf("prlimit: %v: %s", err, out), req.PID, string(req.Action)}
	}
	log.Printf("[mitigate] set RLIMIT_NOFILE=%s on PID %d", limit, req.PID)
	return MitigationResult{true, fmt.Sprintf("FD limit set to %s", limit), req.PID, string(req.Action)}
}
