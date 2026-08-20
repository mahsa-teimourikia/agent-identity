def evaluate(agent):
    findings=[]
    if not agent.get("owner"): findings.append(("AG-OWNER","critical"))
    if agent.get("environment")=="prod" and agent.get("credential_type")=="static_api_key":
        findings.append(("CR-STATIC-PROD","critical"))
    if agent.get("review_age_days",0)>agent.get("review_interval_days",90):
        findings.append(("GV-REVIEW-OVERDUE","high"))
    if not agent.get("monitoring",False): findings.append(("AU-MONITORING","high"))
    return findings
def gate(findings):
    return not any(sev=="critical" for _,sev in findings)
