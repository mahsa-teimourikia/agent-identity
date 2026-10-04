"""Vendor-neutral dashboard projections over the reusable audit pipeline."""

from dataclasses import asdict


def authorization_kpis(pipeline, protected_operations) -> dict:
    """Return metrics whose populations and denominators are explicit in lab.py."""
    return asdict(pipeline.metrics(protected_operations))


def finding_rows(pipeline) -> list[dict]:
    """Keep detected signals distinct from confirmed forbidden outcomes."""
    return [asdict(finding) for finding in pipeline.findings()]


def policy_version_rows(pipeline) -> list[dict]:
    counts: dict[str, dict[str, int | str]] = {}
    for event in pipeline.decisions.values():
        version = event.policy.policy_version
        row = counts.setdefault(
            version, {"policy_version": version, "allows": 0, "denies": 0}
        )
        key = "allows" if event.decision.outcome.value == "allow" else "denies"
        row[key] += 1
    return [counts[key] for key in sorted(counts)]
