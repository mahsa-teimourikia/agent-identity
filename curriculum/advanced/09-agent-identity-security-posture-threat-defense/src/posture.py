WEIGHTS={"inventory":.10,"least_privilege":.15,"credential_hygiene":.15,"delegation":.15,"detection":.15,"runtime_binding":.10,"external_trust":.10,"response":.10}
CRITICAL={"leaked_active_credential","revoked_but_active","compromised_trust_root","unaudited_critical_identity"}
def score(dimensions,critical_findings=()):
    raw=round(100*sum(dimensions[k]*WEIGHTS[k] for k in WEIGHTS))
    critical=CRITICAL.intersection(critical_findings)
    return {"score":min(raw,25) if critical else raw,"critical":sorted(critical),"dimensions":dimensions}
