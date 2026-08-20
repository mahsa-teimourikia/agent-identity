PLAYBOOKS={
"leaked_token":["revoke_token","disable_renewal","investigate_use","rotate_if_needed"],
"delegation_escalation":["remove_delegation","quarantine_child","review_parent"],
"workload_compromise":["quarantine_workload","revoke_sessions","re_attest","rotate_keys"],
"trust_compromise":["block_new_sessions","security_review","suspend_federation_if_approved"]
}
def plan(finding): return PLAYBOOKS.get(finding,["investigate"])
