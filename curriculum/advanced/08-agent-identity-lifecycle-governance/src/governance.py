RISK_SCORE={"low":1,"medium":2,"high":3,"critical":4}
def required_approvers(risk):
    return {
      "low":{"owner"},
      "medium":{"owner","platform"},
      "high":{"owner","security"},
      "critical":{"owner","security","risk","business_authority"}
    }[risk]
def sod_ok(requester,approvers):
    return requester not in set(approvers)
def posture(record):
    checks={
      "owner":bool(record.get("owner")),
      "short_lived":record.get("short_lived",False),
      "review_current":record.get("review_current",False),
      "monitoring":record.get("monitoring",False),
      "runtime_bound":record.get("runtime_bound",False),
      "least_privilege":record.get("least_privilege",False)
    }
    score=round(100*sum(checks.values())/len(checks))
    critical_fail=record.get("forbidden_static_secret",False) or record.get("revoked_but_active",False)
    return {"score":0 if critical_fail else score,"checks":checks,"critical_fail":critical_fail}
