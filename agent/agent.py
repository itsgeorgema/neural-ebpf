"""
LangGraph state machine for the Neural eBPF self-healing agent.

States: IDLE → ANALYZING → PLANNING → EXECUTING → VERIFYING → RESOLVED | FAILED
"""
import json
import time
from typing import Annotated, TypedDict, Literal
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from tools import ALL_TOOLS
from redis_store import IncidentStore


# ---------------------------------------------------------------------------
# Process classification
# ---------------------------------------------------------------------------

_LEAK_KEYWORDS = {"leak", "stress", "flood", "spike", "burn", "bomb", "bench", "fuzz"}
_SYSTEM_SERVICE_PREFIXES = {
    "nginx", "apache", "httpd", "postgres", "mysql", "mysqld", "redis",
    "memcached", "elastic", "kafka", "zookeeper", "systemd", "init",
    "launchd", "dockerd", "kubelet", "mongod", "etcd", "consul", "java",
}
_SCRIPT_INTERPRETERS = {"python", "python3", "python2", "bash", "sh", "zsh", "fish", "node", "ruby", "perl"}


def classify_process(event: dict) -> tuple[str, str]:
    """Return (process_class, anomaly_type) for a kernel event.

    process_class: leak_simulator | user_script | system_service | unknown
    anomaly_type:  cpu | fd | both
    """
    proc = event.get("process") or {}
    name = (proc.get("name") or "").lower()
    cmd_line = (proc.get("cmd_line") or "").lower()
    pid = int(event.get("pid") or 0)
    event_type = str(event.get("type") or "")

    anomaly_type = "fd" if event_type == "fd_anomaly" else "cpu"

    combined = f"{name} {cmd_line}"

    # Confirmed test/leak script
    if any(kw in combined for kw in _LEAK_KEYWORDS):
        return "leak_simulator", anomaly_type

    # Known system service by name or low PID
    if 0 < pid < 500 or any(name.startswith(s) for s in _SYSTEM_SERVICE_PREFIXES):
        return "system_service", anomaly_type

    # Script interpreter → user script
    if any(name == s or name.startswith(s) for s in _SCRIPT_INTERPRETERS):
        return "user_script", anomaly_type

    return "unknown", anomaly_type


# ---------------------------------------------------------------------------
# System prompt — encodes the full decision matrix
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are Neural eBPF, an autonomous Site Reliability Agent.

You will be told the PROCESS CLASS and ANOMALY TYPE for each incident. Follow the decision matrix EXACTLY.

━━━ TOOLS ━━━
• get_processes      — lists all processes; each entry includes cpu_percent, fd_count, stopped (bool), cmd_line
• throttle_cpu       — cpulimit-based CPU cap (may fail if cpulimit not installed)
• suspend_process    — SIGSTOP: freezes the process; cpu drops to 0 but ALL resources remain held
• resume_process     — SIGCONT: unsuspends a stopped process
• set_fd_limit       — prlimit NOFILE cap (Linux only)
• kill_process       — SIGKILL: terminates the process; all resources freed immediately

━━━ DECISION MATRIX ━━━

CLASS: leak_simulator  (test scripts — no valuable state)
  cpu anomaly  → kill_process immediately. No throttle attempt.
  fd anomaly   → kill_process immediately. SIGSTOP does not free FDs.
  both         → kill_process immediately.

CLASS: user_script  (Python/shell scripts that are not system services)
  cpu anomaly  → throttle_cpu(50%). Verify (see RESOLVED rules).
                 If throttle fails or CPU rebounds after throttle → kill_process.
  fd anomaly   → kill_process. FDs are only freed when the process dies.
  both         → kill_process.

CLASS: system_service  (nginx, postgres, redis, java services, PID < 500)
  cpu anomaly  → throttle_cpu(30%). Verify. Escalate with another throttle step only.
                 Do NOT kill or suspend system services. Log FAILED if throttle exhausted.
  fd anomaly   → set_fd_limit (Linux) to cap growth. Log advisory. Do NOT kill.
  both         → throttle_cpu(30%) for CPU relief. set_fd_limit for FD cap. Log FAILED if unresolved.

CLASS: unknown
  cpu anomaly  → throttle_cpu(50%). If fails → kill_process.
  fd anomaly   → kill_process.
  both         → kill_process.

━━━ SIGSTOP RULES ━━━
• NEVER use suspend_process as a substitute for kill_process.
• suspend_process is ONLY valid as a brief diagnostic pause for user_script or unknown
  when you need a moment before deciding to kill.
• A process with stopped=true is NOT mitigated — its CPU reads 0 trivially, which is
  meaningless. You MUST follow every suspend_process with either resume_process or kill_process.
• NEVER declare RESOLVED while the target process has stopped=true.

━━━ RESOLVED RULES ━━━
✓ RESOLVED via kill:     process no longer appears in get_processes results.
✓ RESOLVED via throttle: process is present, stopped=false, cpu_percent below threshold.
✗ NOT resolved:          process present with stopped=true (SIGSTOP'd — not mitigated).
✗ NOT resolved:          fd_count still at or above threshold after action.
✗ NOT resolved:          throttle returned success:false.

━━━ OUTPUT FORMAT ━━━
Always state: class, anomaly type, chosen action, and why. Be specific about PIDs and metrics."""


MITIGATION_TOOLS = {"throttle_cpu", "suspend_process", "kill_process", "set_fd_limit", "resume_process"}


# ---------------------------------------------------------------------------
# Agent state
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    event: dict
    phase: str
    attempts: int
    resolved: bool
    process_class: str   # leak_simulator | user_script | system_service | unknown
    anomaly_type: str    # cpu | fd | both


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _last_tool_results(messages: list) -> dict[str, ToolMessage]:
    return {m.tool_call_id: m for m in messages if isinstance(m, ToolMessage)}


def _target_stopped_in_last_process_list(messages: list, target_pid: int) -> bool | None:
    """Scan backwards through tool messages for the most recent get_processes result.

    Returns:
      True  — target PID is present with stopped=true (SIGSTOP'd, not mitigated)
      False — target PID absent (killed) or present with stopped=false (running)
      None  — couldn't find a process list in recent messages
    """
    for msg in reversed(messages):
        if not isinstance(msg, ToolMessage):
            continue
        try:
            data = json.loads(msg.content)
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        # Found a process list
        for proc in data:
            if proc.get("pid") == target_pid:
                return bool(proc.get("stopped", False))
        return False  # PID not in list = process is gone = kill worked
    return None


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

def build_graph(store: IncidentStore, model_name: str = "gpt-5.4") -> StateGraph:
    llm = ChatOpenAI(model=model_name, temperature=0).bind_tools(ALL_TOOLS)
    tool_node = ToolNode(ALL_TOOLS)

    def log(state: AgentState, phase: str, content: str):
        entry = {
            "phase": phase,
            "content": content,
            "pid": state["event"].get("pid"),
            "process": state["event"].get("process", {}).get("name", "unknown"),
        }
        store.append_monologue(entry)
        print(f"[{phase}] {content}")

    def analyze_node(state: AgentState) -> dict:
        event = state["event"]
        last_msg = state["messages"][-1] if state["messages"] else None

        # Second pass: tool results arrived — finish analysis
        if isinstance(last_msg, ToolMessage):
            response = llm.invoke([SystemMessage(content=SYSTEM_PROMPT)] + state["messages"])
            log(state, "ANALYZING", response.content or "(analyzing)")
            return {"messages": [response], "phase": "ANALYZING"}

        # First pass: classify, log the alert, ask LLM to call get_processes
        proc_class, anomaly_type = classify_process(event)

        log(state, "ANALYZING",
            f"Kernel alert: {event.get('message')} | "
            f"PID={event.get('pid')} class={proc_class} anomaly={anomaly_type}. "
            f"Querying live process table...")

        prompt = f"""KERNEL ALERT: {json.dumps(event, indent=2)}

PROCESS CLASS: {proc_class}
ANOMALY TYPE: {anomaly_type}

Use get_processes to confirm current system state, then state:
1. The offending process and its current metrics
2. The exact mitigation you will apply per the decision matrix for class={proc_class} / anomaly={anomaly_type}
3. Why this action is correct"""

        messages = state["messages"] + [HumanMessage(content=prompt)]
        response = llm.invoke([SystemMessage(content=SYSTEM_PROMPT)] + messages)
        log(state, "ANALYZING", response.content or "(tool call)")
        return {
            "messages": [HumanMessage(content=prompt), response],
            "phase": "ANALYZING",
            "process_class": proc_class,
            "anomaly_type": anomaly_type,
        }

    def plan_execute_node(state: AgentState) -> dict:
        last_ai = next((m for m in reversed(state["messages"]) if isinstance(m, AIMessage)), None)

        # Re-entering after tool calls completed — log each result
        if last_ai and last_ai.tool_calls:
            tool_msgs = _last_tool_results(state["messages"])
            for tc in last_ai.tool_calls:
                name = tc.get("name", "unknown") if isinstance(tc, dict) else getattr(tc, "name", "unknown")
                args = tc.get("args", {}) if isinstance(tc, dict) else getattr(tc, "args", {})
                tc_id = tc.get("id", "") if isinstance(tc, dict) else getattr(tc, "id", "")
                result_msg = tool_msgs.get(tc_id)
                try:
                    result = json.loads(result_msg.content) if result_msg else {}
                except Exception:
                    result = {"output": getattr(result_msg, "content", "")}

                args_str = ", ".join(f"{k}={v}" for k, v in args.items() if k != "reason")
                outcome = result.get("message") or result.get("output") or str(result)
                log(state, "EXECUTING", f"→ {name}({args_str}): {outcome}")

                if name in MITIGATION_TOOLS:
                    store.log_mitigation(
                        pid=state["event"].get("pid", 0),
                        action=name,
                        result=result if isinstance(result, dict) else {"output": str(result)},
                    )
            return {"phase": "EXECUTING"}

        proc_class = state.get("process_class", "unknown")
        anomaly_type = state.get("anomaly_type", "cpu")
        pid = state["event"].get("pid")
        attempts = state["attempts"]

        prompt = (
            f"Execute the correct mitigation for PID={pid}, class={proc_class}, anomaly={anomaly_type}. "
            f"This is attempt #{attempts + 1}. "
            f"Follow the decision matrix exactly. State which tool you are calling and why."
        )
        messages = state["messages"] + [HumanMessage(content=prompt)]
        response = llm.invoke([SystemMessage(content=SYSTEM_PROMPT)] + messages)
        log(state, "EXECUTING", response.content or "(calling tool)")
        return {
            "messages": [HumanMessage(content=prompt), response],
            "phase": "EXECUTING",
            "attempts": state["attempts"] + 1,
        }

    def verify_node(state: AgentState) -> dict:
        last_msg = state["messages"][-1] if state["messages"] else None
        target_pid = state["event"].get("pid")

        # Second pass: tool results arrived — evaluate
        if isinstance(last_msg, ToolMessage):
            # Hard guard: if the target process is stopped, the LLM must not declare success
            stopped_check = _target_stopped_in_last_process_list(state["messages"], target_pid)
            if stopped_check is True:
                log(state, "VERIFYING",
                    f"PID {target_pid} is SIGSTOP'd (stopped=true). "
                    f"This is NOT mitigated — cpu=0 is trivial for a frozen process. Escalating to kill.")
                return {"messages": [], "phase": "VERIFYING", "resolved": False}

            response = llm.invoke([SystemMessage(content=SYSTEM_PROMPT)] + state["messages"])
            log(state, "VERIFYING", response.content or "(verifying)")
            content = (response.content or "").lower()
            resolved = (
                "resolved" in content
                or "success" in content
                or "normalized" in content
                or "no longer" in content
                or "absent" in content
                or "not found" in content
            )
            return {"messages": [response], "phase": "VERIFYING", "resolved": resolved}

        # First pass: call get_processes and evaluate
        log(state, "VERIFYING", "Verifying mitigation effectiveness...")
        proc_class = state.get("process_class", "unknown")
        anomaly_type = state.get("anomaly_type", "cpu")
        prompt = (
            f"Use get_processes to verify mitigation of PID={target_pid} "
            f"(class={proc_class}, anomaly={anomaly_type}). "
            f"Check the RESOLVED RULES in your instructions: "
            f"• If stopped=true → NOT resolved, you must kill next. "
            f"• If PID absent → RESOLVED (kill succeeded). "
            f"• If running with cpu below threshold → RESOLVED (throttle succeeded). "
            f"State clearly: RESOLVED or NOT RESOLVED, and why."
        )
        messages = state["messages"] + [HumanMessage(content=prompt)]
        response = llm.invoke([SystemMessage(content=SYSTEM_PROMPT)] + messages)
        log(state, "VERIFYING", response.content or "(tool call)")
        content = (response.content or "").lower()
        resolved = (
            "resolved" in content
            or "success" in content
            or "normalized" in content
            or "no longer" in content
            or "absent" in content
            or "not found" in content
        )
        return {"messages": [HumanMessage(content=prompt), response], "phase": "VERIFYING", "resolved": resolved}

    def resolved_node(state: AgentState) -> dict:
        attempts = sum(
            1 for m in state["messages"]
            if isinstance(m, ToolMessage) and getattr(m, "name", None) in MITIGATION_TOOLS
        )
        genuinely_resolved = state.get("resolved", False)
        proc_class = state.get("process_class", "unknown")
        anomaly_type = state.get("anomaly_type", "cpu")

        if not genuinely_resolved:
            log(state, "FAILED",
                f"Exhausted {attempts} mitigation attempt(s) without resolving "
                f"PID {state['event'].get('pid')} (class={proc_class}, anomaly={anomaly_type}). "
                f"Daemon watchdog will force-kill if process is still running.")
            store.save_incident({
                "event": state["event"],
                "resolution": "agent_failed",
                "attempts": attempts,
                "process_class": proc_class,
                "anomaly_type": anomaly_type,
                "timestamp": time.time(),
            })
            return {"phase": "FAILED", "resolved": False}

        log(state, "RESOLVED",
            f"Incident resolved after {attempts} attempt(s) — "
            f"PID {state['event'].get('pid')} (class={proc_class}, anomaly={anomaly_type}) "
            f"is no longer anomalous.")
        store.save_incident({
            "event": state["event"],
            "resolution": "mitigated",
            "attempts": attempts,
            "process_class": proc_class,
            "anomaly_type": anomaly_type,
            "timestamp": time.time(),
        })
        return {"phase": "RESOLVED", "resolved": True}

    # ---------------------------------------------------------------------------
    # Routing
    # ---------------------------------------------------------------------------

    def route_after_analyze(state: AgentState) -> Literal["tools", "plan_execute"]:
        last = state["messages"][-1] if state["messages"] else None
        if isinstance(last, AIMessage) and last.tool_calls:
            return "tools"
        return "plan_execute"

    def route_after_execute(state: AgentState) -> Literal["tools", "verify"]:
        last = state["messages"][-1] if state["messages"] else None
        if isinstance(last, AIMessage) and last.tool_calls:
            return "tools"
        return "verify"

    def route_after_verify(state: AgentState) -> Literal["tools", "resolved", "plan_execute"]:
        last = state["messages"][-1] if state["messages"] else None
        if isinstance(last, AIMessage) and last.tool_calls:
            return "tools"
        real_attempts = sum(
            1 for m in state["messages"]
            if isinstance(m, ToolMessage) and getattr(m, "name", None) in MITIGATION_TOOLS
        )
        if state.get("resolved") or real_attempts >= 3:
            return "resolved"
        return "plan_execute"

    def route_after_tools(state: AgentState) -> Literal["analyze", "plan_execute", "verify"]:
        phase = state.get("phase", "EXECUTING")
        if phase == "ANALYZING":
            return "analyze"
        if phase == "VERIFYING":
            return "verify"
        return "plan_execute"

    # ---------------------------------------------------------------------------
    # Graph assembly
    # ---------------------------------------------------------------------------

    graph = StateGraph(AgentState)
    graph.add_node("analyze", analyze_node)
    graph.add_node("tools", tool_node)
    graph.add_node("plan_execute", plan_execute_node)
    graph.add_node("verify", verify_node)
    graph.add_node("resolved", resolved_node)

    graph.set_entry_point("analyze")
    graph.add_conditional_edges("analyze", route_after_analyze)
    graph.add_conditional_edges("plan_execute", route_after_execute)
    graph.add_conditional_edges("verify", route_after_verify)
    graph.add_conditional_edges("tools", route_after_tools)
    graph.add_edge("resolved", END)

    return graph.compile()


def handle_event(event: dict, store: IncidentStore):
    """Entry point: run the agent for one kernel event."""
    graph = build_graph(store)
    initial_state: AgentState = {
        "messages": [],
        "event": event,
        "phase": "IDLE",
        "attempts": 0,
        "resolved": False,
        "process_class": "unknown",
        "anomaly_type": "cpu",
    }
    final_state = graph.invoke(initial_state)
    return final_state
