def containment_plan(finding):
    return {
      "stolen_token":["revoke_token","disable_renewal","quarantine_agent","investigate"],
      "delegation_escalation":["remove_delegation","quarantine_child","review_parent"],
      "workload_compromise":["quarantine_workload","revoke_sessions","rotate_keys","re_attest"],
      "federation_compromise":["block_new_sessions","security_review","suspend_federation_if_approved"]
    }.get(finding,["investigate"])
