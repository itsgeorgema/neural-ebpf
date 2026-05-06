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
    """Kill a process by PID. Use only as a last resort when throttling fails."""
    resp = httpx.post(f"{DAEMON_URL}/mitigate", json={
        "pid": pid,
        "action": "kill",
        "reason": reason,
    }, timeout=5)
    return resp.json()


@tool
def suspend_process(pid: int, reason: str) -> dict:
    """Suspend (SIGSTOP) a process. It will stop consuming CPU immediately."""
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
    """Throttle a process's CPU usage to at most throttle_percent (1-100).
    Uses cpulimit or cgroup v2 under the hood. Prefer this over kill."""
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
