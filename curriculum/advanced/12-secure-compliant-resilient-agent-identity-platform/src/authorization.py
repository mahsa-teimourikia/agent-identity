import secrets
from .models import Decision
def authorize(ctx,intent,agent,workload,delegation,relationships,risk="low"):
    deny=lambda reason: Decision("deny",secrets.token_hex(8),reason)
    if not agent.get("registered"): return deny("AGENT_UNREGISTERED")
    if workload.get("agent_id") != ctx.agent_id or not workload.get("approved"): return deny("WORKLOAD_BINDING")
    if delegation and delegation.get("tenant") != ctx.tenant_id: return deny("TENANT_MISMATCH")
    if delegation and intent.action not in delegation["actions"]: return deny("ACTION_OUT_OF_SCOPE")
    if delegation and intent.resource not in delegation["resources"]: return deny("RESOURCE_OUT_OF_SCOPE")
    if relationships.get((ctx.principal_id,"assigned_to",intent.resource)) is not True: return deny("RELATIONSHIP")
    if risk=="critical": return deny("CRITICAL_RISK")
    if risk=="high": return Decision("step_up",secrets.token_hex(8),"HIGH_RISK",{},["human_approval","audit"])
    constraints={}
    if intent.action=="claim.update":
        constraints={"allowed_fields":{"status","notes"}}
    return Decision("allow",secrets.token_hex(8),"TASK_SCOPE",constraints,["audit"])
