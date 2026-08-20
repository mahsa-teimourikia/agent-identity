def build_profile(evidence):
    return {
      "identity": "high" if evidence.get("agent_registered") else "none",
      "workload": "high" if evidence.get("workload_attested") else "none",
      "supply_chain": "high" if evidence.get("provenance_verified") else "none",
      "evaluation": "high" if evidence.get("evaluation_passed") else "low",
      "governance": "high" if evidence.get("governance_approved") else "none",
      "quarantined": bool(evidence.get("quarantined"))
    }

def sensitive_write(profile):
    if profile["quarantined"]: return "deny"
    required=("identity","workload","supply_chain","evaluation","governance")
    return "allow" if all(profile[x]=="high" for x in required) else "step_up"
