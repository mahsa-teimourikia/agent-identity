def detect(event):
    findings=[]
    if event.get("identity_status")=="revoked": findings.append("revoked_identity_used")
    if event.get("delegated_scope",set())-event.get("parent_scope",set()): findings.append("delegation_escalation")
    if event.get("token_age_minutes",0)>event.get("max_token_age_minutes",60): findings.append("excessive_token_lifetime")
    if event.get("human_using_nhi"): findings.append("human_use_of_nhi")
    if event.get("monitoring_disabled"): findings.append("telemetry_suppression")
    if event.get("unexpected_audience"): findings.append("audience_anomaly")
    return findings
