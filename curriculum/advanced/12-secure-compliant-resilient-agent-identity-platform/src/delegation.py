from datetime import datetime,timezone
def attenuated(parent,child):
    return (
      set(child["actions"]).issubset(parent["actions"]) and
      set(child["resources"]).issubset(parent["resources"]) and
      child["expires_at"] <= parent["expires_at"] and
      child["depth"] <= parent.get("max_depth",parent.get("depth",0)+1)
    )
def valid(d,agent,action,resource,now=None):
    now=now or datetime.now(timezone.utc)
    return (not d.get("revoked",False) and d["delegatee"]==agent and
            action in d["actions"] and resource in d["resources"] and now<d["expires_at"])
