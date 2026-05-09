package monitor

import "strings"

// ProcessClass categorizes a process by its operational role and tolerance for disruption.
// The daemon stamps every anomaly event with a classification so the Python agent can
// apply the correct decision-matrix branch without re-deriving it from raw process fields.
type ProcessClass string

const (
	// ClassLeakSimulator — test/benchmark scripts with no valuable state.
	// Safe to kill immediately on any anomaly.
	ClassLeakSimulator ProcessClass = "leak_simulator"

	// ClassUserScript — interpreter-run scripts (Python, shell, Node, etc.) that are
	// not system services. CPU anomalies warrant one throttle attempt; FD anomalies
	// require an immediate kill because SIGSTOP does not free file descriptors.
	ClassUserScript ProcessClass = "user_script"

	// ClassSystemService — well-known daemons (nginx, postgres, redis, …) or any
	// process with PID < 500. Must never be killed; throttle-only policy.
	ClassSystemService ProcessClass = "system_service"

	// ClassUnknown — processes that do not match any other class.
	// Treated conservatively: one throttle attempt for CPU, kill for FD anomalies.
	ClassUnknown ProcessClass = "unknown"
)

// AnomalyKind identifies which resource constraint was breached.
type AnomalyKind string

const (
	AnomalyCPU  AnomalyKind = "cpu"
	AnomalyFD   AnomalyKind = "fd"
	AnomalyBoth AnomalyKind = "both"
)

// leakKeywords are substrings that indicate a synthetic load-generator or stress test.
// Matching any keyword in the process name or command line → ClassLeakSimulator.
var leakKeywords = []string{
	"leak", "stress", "flood", "spike", "burn", "bomb", "bench", "fuzz",
}

// systemServicePrefixes are name prefixes that identify known production daemons.
var systemServicePrefixes = []string{
	"nginx", "apache", "httpd", "postgres", "mysql", "mysqld", "redis",
	"memcached", "elastic", "kafka", "zookeeper", "systemd", "init",
	"launchd", "dockerd", "kubelet", "mongod", "etcd", "consul", "java",
}

// scriptInterpreters are process names that indicate a user-level script runner.
var scriptInterpreters = []string{
	"python", "python3", "python2", "bash", "sh", "zsh", "fish",
	"node", "ruby", "perl",
}

// ClassifyProcess determines the ProcessClass and AnomalyKind for an anomaly event.
// It is called by the daemon's event emitters so that every KernelEvent carries
// authoritative classification fields the agent can act on immediately.
func ClassifyProcess(ev *KernelEvent) (ProcessClass, AnomalyKind) {
	name := strings.ToLower(ev.Process.Name)
	cmdLine := strings.ToLower(ev.Process.CmdLine)
	combined := name + " " + cmdLine

	anomaly := anomalyFromEventType(ev.Type)

	// Confirmed test/load-generator script — safe to terminate immediately.
	for _, kw := range leakKeywords {
		if strings.Contains(combined, kw) {
			return ClassLeakSimulator, anomaly
		}
	}

	// Low-PID kernel/init processes and well-known service daemons.
	if ev.PID > 0 && ev.PID < 500 {
		return ClassSystemService, anomaly
	}
	for _, prefix := range systemServicePrefixes {
		if strings.HasPrefix(name, prefix) {
			return ClassSystemService, anomaly
		}
	}

	// Script-interpreter processes that are not already matched as a service.
	for _, interp := range scriptInterpreters {
		if name == interp || strings.HasPrefix(name, interp) {
			return ClassUserScript, anomaly
		}
	}

	return ClassUnknown, anomaly
}

func anomalyFromEventType(t EventType) AnomalyKind {
	if t == EventFDAnomaly {
		return AnomalyFD
	}
	return AnomalyCPU
}
