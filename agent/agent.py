"""
LangGraph state machine for the Neural eBPF self-healing agent.

States: IDLE → ANALYZING → PLANNING → EXECUTING → VERIFYING → RESOLVED
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


SYSTEM_PROMPT = """You are Neural eBPF, an autonomous Site Reliability Agent operating at the kernel level.

Your mission: Detect, analyze, and mitigate runaway processes on a Linux system using eBPF telemetry.

You have access to these tools:
- get_processes: See all monitored processes with CPU%, memory, and FD counts
- throttle_cpu: Apply CPU bandwidth throttling to a PID (preferred first response)
- suspend_process: SIGSTOP a process (immediate but harsh)
- resume_process: SIGCONT a suspended process
- set_fd_limit: Restrict file descriptor count (Linux only)
- kill_process: SIGKILL a process (last resort only)

Decision framework:
1. ANALYZE: What process is misbehaving? What are its stats?
2. PLAN: What is the least-invasive mitigation? Start with throttle_cpu at 50%.
3. EXECUTE: Apply the mitigation.
4. VERIFY: Re-check processes. Did CPU normalize? If not, escalate.
5. ESCALATE: If throttle fails, try suspend. If still unresolved after 30s, kill.

Always explain your reasoning step by step. Be specific about PIDs and percentages.
Format your monologue clearly so it can be displayed in the Surgery Console UI."""


MITIGATION_TOOLS = {"throttle_cpu", "suspend_process", "kill_process", "set_fd_limit", "resume_process"}


class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    event: dict          # The triggering kernel event
    phase: str           # current phase name for UI display
    attempts: int        # mitigation attempt count
    resolved: bool


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

    def _last_tool_results(messages: list) -> dict[str, ToolMessage]:
        """Return {tool_call_id: ToolMessage} for the most recent batch of tool results."""
        return {m.tool_call_id: m for m in messages if isinstance(m, ToolMessage)}

    def analyze_node(state: AgentState) -> dict:
        event = state["event"]
        last_msg = state["messages"][-1] if state["messages"] else None

        # Second pass: tool results just arrived — complete the analysis
        if isinstance(last_msg, ToolMessage):
            response = llm.invoke([SystemMessage(content=SYSTEM_PROMPT)] + state["messages"])
            log(state, "ANALYZING", response.content or "(analyzing)")
            return {"messages": [response], "phase": "ANALYZING"}

        # First pass: log the alert and ask LLM to call get_processes
        log(state, "ANALYZING",
            f"Kernel alert received: {event.get('message')}. "
            f"PID={event.get('pid')}, type={event.get('type')}. "
            f"Querying live process table...")

        prompt = f"""KERNEL ALERT: {json.dumps(event, indent=2)}

Analyze this incident. Use get_processes to get current system state, then explain:
1. Which process is the offender and why
2. What the root cause likely is
3. Your proposed mitigation plan (start least invasive)"""

        messages = state["messages"] + [HumanMessage(content=prompt)]
        response = llm.invoke([SystemMessage(content=SYSTEM_PROMPT)] + messages)
        log(state, "ANALYZING", response.content or "(tool call)")
        return {"messages": [HumanMessage(content=prompt), response], "phase": "ANALYZING"}

    def plan_execute_node(state: AgentState) -> dict:
        last_ai = next((m for m in reversed(state["messages"]) if isinstance(m, AIMessage)), None)

        # Re-entering after mitigation tool calls completed — log each result to monologue
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

        prompt = "Now execute your mitigation plan using the available tools. Start with throttle_cpu."
        messages = state["messages"] + [HumanMessage(content=prompt)]
        response = llm.invoke([SystemMessage(content=SYSTEM_PROMPT)] + messages)
        log(state, "EXECUTING", response.content or "(calling tool)")
        return {"messages": [HumanMessage(content=prompt), response], "phase": "EXECUTING", "attempts": state["attempts"] + 1}

    def verify_node(state: AgentState) -> dict:
        last_msg = state["messages"][-1] if state["messages"] else None

        # Second pass: tool results just arrived — complete the verification
        if isinstance(last_msg, ToolMessage):
            response = llm.invoke([SystemMessage(content=SYSTEM_PROMPT)] + state["messages"])
            log(state, "VERIFYING", response.content or "(verifying)")
            resolved = "success" in (response.content or "").lower() or "normalized" in (response.content or "").lower()
            return {"messages": [response], "phase": "VERIFYING", "resolved": resolved}

        # First pass: ask LLM to re-check and evaluate
        log(state, "VERIFYING", "Verifying mitigation effectiveness...")
        prompt = (
            "Use get_processes to verify the mitigation worked. "
            "If the target process CPU is now below threshold, declare success. "
            "If still high and attempts < 3, escalate to a stronger action. "
            "If attempts >= 3, consider kill as last resort."
        )
        messages = state["messages"] + [HumanMessage(content=prompt)]
        response = llm.invoke([SystemMessage(content=SYSTEM_PROMPT)] + messages)
        log(state, "VERIFYING", response.content or "(tool call)")
        resolved = "success" in (response.content or "").lower() or "normalized" in (response.content or "").lower()
        return {"messages": [HumanMessage(content=prompt), response], "phase": "VERIFYING", "resolved": resolved}

    def resolved_node(state: AgentState) -> dict:
        attempts = sum(
            1 for m in state["messages"]
            if isinstance(m, ToolMessage) and getattr(m, "name", None) in MITIGATION_TOOLS
        )
        log(state, "RESOLVED",
            f"Incident resolved after {attempts} mitigation attempt(s). "
            f"PID {state['event'].get('pid')} is no longer anomalous.")
        incident = {
            "event": state["event"],
            "resolution": "mitigated",
            "attempts": attempts,
            "timestamp": time.time(),
        }
        store.save_incident(incident)
        return {"phase": "RESOLVED", "resolved": True}

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
        """Route tool results back to the node that called them, based on current phase."""
        phase = state.get("phase", "EXECUTING")
        if phase == "ANALYZING":
            return "analyze"
        if phase == "VERIFYING":
            return "verify"
        return "plan_execute"

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
    }
    final_state = graph.invoke(initial_state)
    return final_state
