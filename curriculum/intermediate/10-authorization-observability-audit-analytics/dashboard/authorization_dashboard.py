"""Minimal analytics starter for the course."""
import pandas as pd

def authorization_kpis(events: pd.DataFrame) -> dict:
    return {
        "decisions": len(events),
        "allow_rate": float((events["decision"] == "allow").mean()) if len(events) else 0.0,
        "deny_rate": float((events["decision"] == "deny").mean()) if len(events) else 0.0,
        "p95_latency_ms": float(events["latency_ms"].quantile(.95)) if len(events) else 0.0,
    }
