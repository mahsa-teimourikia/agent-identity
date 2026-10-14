"""Lifecycle API compatibility layer backed by the durable governance lab."""

from lab import GovernanceError, GovernanceStore  # noqa: F401

LIFECYCLE = {
    "pending_approval": {"active"},
    "active": {"suspended", "quarantined", "retired"},
    "suspended": {"quarantined", "retired"},
    "quarantined": {"suspended", "retired"},
    "retired": set(),
}
