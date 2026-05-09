"""Daemon API tools available to the LangGraph agent."""
import httpx
from langchain_core.tools import tool


DAEMON_URL = "http://localhost:8080"


@tool
def get_processes() -> list[dict]:
    """Get all currently monitored processes with their CPU%, memory, and FD counts."""
    resp = httpx.get(f"{DAEMON_URL}/processes", timeout=5)
    resp.raise_for_status()
    return resp.json()


@tool
def kill_process(pid: int, reason: str) -> dict:
    """SIGKILL a process. Terminates it immediately; all resources (CPU, memory, FDs) are freed.
    Use for: leak_simulator (always), user_script/unknown with fd anomaly, throttle failure escalation."""
    resp = httpx.post(f"{DAEMON_URL}/mitigate", json={
        "pid": pid,
        "action": "kill",
        "reason": reason,
    }, timeout=5)
    return resp.json()


@tool
def suspend_process(pid: int, reason: str) -> dict:
    """SIGSTOP a process. CPU drops to 0 but ALL resources remain held (memory, FDs, handles).
    WARNING: A stopped process is NOT mitigated. cpu=0 is trivial for a frozen process.
    Only valid as a brief diagnostic pause before kill_process or resume_process.
    NEVER use on system_service. NEVER declare RESOLVED while target has stopped=true."""
    resp = httpx.post(f"{DAEMON_URL}/mitigate", json={
        "pid": pid,
        "action": "suspend",
        "reason": reason,
    }, timeout=5)
    return resp.json()


@tool
def resume_process(pid: int, reason: str) -> dict:
    """Resume (SIGCONT) a previously suspended process."""
    resp = httpx.post(f"{DAEMON_URL}/mitigate", json={
        "pid": pid,
        "action": "resume",
        "reason": reason,
    }, timeout=5)
    return resp.json()


@tool
def throttle_cpu(pid: int, throttle_percent: int, reason: str) -> dict:
    """Cap CPU usage via cpulimit (requires cpulimit to be installed; may return success=false).
    Use for: user_script/unknown cpu anomaly (50%), system_service cpu anomaly (30%).
    Does NOT affect FD count or memory. Check success field in response before declaring resolved."""
    resp = httpx.post(f"{DAEMON_URL}/mitigate", json={
        "pid": pid,
        "action": "throttle_cpu",
        "throttle_percent": throttle_percent,
        "reason": reason,
    }, timeout=5)
    return resp.json()


@tool
def set_fd_limit(pid: int, reason: str) -> dict:
    """Restrict a process's open file descriptor limit to 256 (Linux only)."""
    resp = httpx.post(f"{DAEMON_URL}/mitigate", json={
        "pid": pid,
        "action": "set_rlimit_fd",
        "reason": reason,
    }, timeout=5)
    return resp.json()


ALL_TOOLS = [get_processes, kill_process, suspend_process, resume_process, throttle_cpu, set_fd_limit]
