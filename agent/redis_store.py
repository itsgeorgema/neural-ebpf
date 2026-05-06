"""Redis store for incident/fix pairs and agent monologue history."""
import json
import time
from typing import Optional
import redis


class IncidentStore:
    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        self.r = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self.incident_key = "incidents"
        self.monologue_key = "monologue"
        self.metrics_key = "metrics"

    def save_incident(self, incident: dict) -> str:
        incident_id = f"incident:{int(time.time() * 1000)}"
        self.r.hset(incident_id, mapping={
            "data": json.dumps(incident),
            "timestamp": time.time(),
        })
        self.r.lpush(self.incident_key, incident_id)
        self.r.ltrim(self.incident_key, 0, 99)  # keep last 100
        return incident_id

    def get_recent_incidents(self, n: int = 10) -> list[dict]:
        ids = self.r.lrange(self.incident_key, 0, n - 1)
        result = []
        for id_ in ids:
            raw = self.r.hget(id_, "data")
            if raw:
                result.append(json.loads(raw))
        return result

    def append_monologue(self, entry: dict):
        entry["timestamp"] = time.time()
        self.r.lpush(self.monologue_key, json.dumps(entry))
        self.r.ltrim(self.monologue_key, 0, 499)
        # Publish for real-time streaming
        self.r.publish("monologue_stream", json.dumps(entry))

    def get_monologue(self, n: int = 50) -> list[dict]:
        raw = self.r.lrange(self.monologue_key, 0, n - 1)
        return [json.loads(x) for x in raw]

    def push_metric(self, pid: int, cpu: float, mem: float):
        key = f"metrics:{pid}"
        entry = {"ts": time.time(), "cpu": cpu, "mem": mem}
        self.r.lpush(key, json.dumps(entry))
        self.r.ltrim(key, 0, 299)
        self.r.expire(key, 3600)

    def get_metrics(self, pid: int, n: int = 60) -> list[dict]:
        key = f"metrics:{pid}"
        raw = self.r.lrange(key, 0, n - 1)
        return [json.loads(x) for x in reversed(raw)]

    def ping(self) -> bool:
        try:
            return self.r.ping()
        except Exception:
            return False
