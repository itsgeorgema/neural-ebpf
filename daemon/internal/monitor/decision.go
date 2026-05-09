package monitor

// RecommendedAction is the canonical first mitigation step for a given
// (ProcessClass, AnomalyKind, attempt) triple.  It mirrors the decision matrix
// encoded in the Python agent's SYSTEM_PROMPT so both layers stay in sync:
// the Go daemon uses it for watchdog escalation; the Python agent receives it
// as a field in KernelEvent and uses it to orient its LLM prompt.
type RecommendedAction struct {
	Action          MitigationAction `json:"action"`
	ThrottlePercent int              `json:"throttle_percent,omitempty"`
	Rationale       string           `json:"rationale"`
}

// FirstAction returns the recommended first mitigation for the supplied context.
// attempt is 0-indexed: 0 = first try, 1 = first escalation, etc.
//
// Decision matrix (must stay in sync with SYSTEM_PROMPT in agent/agent.py):
//
//	CLASS            ANOMALY   ATTEMPT   ACTION
//	leak_simulator   any       any       kill  (no valuable state)
//	user_script      cpu       0         throttle_cpu(50%)
//	user_script      cpu       1+        kill  (throttle failed/rebounded)
//	user_script      fd/both   any       kill  (FDs freed only on exit)
//	system_service   cpu       any       throttle_cpu(30→15%)  (never kill)
//	system_service   fd        any       set_rlimit_fd
//	system_service   both      any       throttle_cpu(30%) then set_rlimit_fd
//	unknown          cpu       0         throttle_cpu(50%)
//	unknown          cpu       1+        kill
//	unknown          fd/both   any       kill
func FirstAction(class ProcessClass, anomaly AnomalyKind, attempt int) RecommendedAction {
	switch class {

	case ClassLeakSimulator:
		return RecommendedAction{
			Action:    ActionKill,
			Rationale: "leak simulators have no valuable state; immediate kill is safest",
		}

	case ClassUserScript:
		switch anomaly {
		case AnomalyCPU:
			if attempt == 0 {
				return RecommendedAction{
					Action:          ActionThrottleCPU,
					ThrottlePercent: 50,
					Rationale:       "user script may have recoverable state; throttle before escalating",
				}
			}
			return RecommendedAction{
				Action:    ActionKill,
				Rationale: "throttle failed or CPU rebounded; escalate to kill",
			}
		default:
			return RecommendedAction{
				Action:    ActionKill,
				Rationale: "FDs are only freed when the process exits; SIGSTOP does not help",
			}
		}

	case ClassSystemService:
		switch anomaly {
		case AnomalyCPU:
			pct := 30
			if attempt > 0 {
				pct = 15
			}
			return RecommendedAction{
				Action:          ActionThrottleCPU,
				ThrottlePercent: pct,
				Rationale:       "system services must not be killed; throttle progressively",
			}
		case AnomalyFD:
			return RecommendedAction{
				Action:    ActionSetRlimitFD,
				Rationale: "cap FD growth at the OS level without disrupting the service",
			}
		default: // both
			return RecommendedAction{
				Action:          ActionThrottleCPU,
				ThrottlePercent: 30,
				Rationale:       "address CPU first; follow with set_fd_limit in a second pass",
			}
		}

	default: // ClassUnknown
		if anomaly == AnomalyCPU && attempt == 0 {
			return RecommendedAction{
				Action:          ActionThrottleCPU,
				ThrottlePercent: 50,
				Rationale:       "unknown class; attempt throttle before committing to kill",
			}
		}
		return RecommendedAction{
			Action:    ActionKill,
			Rationale: "unknown class with FD anomaly or throttle exhausted; kill to free resources",
		}
	}
}
