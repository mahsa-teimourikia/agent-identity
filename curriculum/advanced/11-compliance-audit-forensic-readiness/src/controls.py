from dataclasses import dataclass
@dataclass
class Control:
    control_id:str; name:str; domain:str; control_type:str; frequency:str
    evidence_required:list[str]; critical:bool=False
CONTROL_CATALOG=[
 Control("AG-01","Registered identity","Governance","preventive","continuous",["registry_record"],True),
 Control("AG-02","Named accountable owner","Governance","preventive","continuous",["owner_record"],True),
 Control("AC-01","Least privilege","Authorization","preventive","continuous",["entitlements","usage"]),
 Control("CR-01","Short-lived production credential","Credential","preventive","continuous",["credential_config","issuance_events"],True),
 Control("DG-01","Delegation attenuation","Delegation","preventive","continuous",["delegation_events","policy_decisions"],True),
 Control("AU-01","Critical action evidence","Audit","detective","continuous",["authz","enforcement","action"],True),
]
