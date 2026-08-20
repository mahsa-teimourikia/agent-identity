ALLOWED_STATES={
"draft":{"pending_approval"},
"pending_approval":{"approved","revoked"},
"approved":{"active","revoked"},
"active":{"suspended","quarantined","retired","revoked"},
"suspended":{"active","retired","revoked"},
"quarantined":{"suspended","revoked"},
"retired":{"revoked"},
"revoked":set()
}
def transition(current,target):
    if target not in ALLOWED_STATES[current]:
        raise ValueError(f"illegal transition {current}->{target}")
    return target
def workload_bound(agent,workload_id):
    return workload_id in set(agent.get("approved_workloads",[]))
