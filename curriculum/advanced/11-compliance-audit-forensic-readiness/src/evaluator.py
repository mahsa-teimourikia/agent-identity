from dataclasses import dataclass
@dataclass
class Result:
    control_id:str; subject:str; status:str; reason:str; critical:bool=False
def evaluate_agent(agent):
    out=[]
    out.append(Result("AG-01",agent["id"],"pass" if agent.get("registered") else "fail","registration",True))
    out.append(Result("AG-02",agent["id"],"pass" if agent.get("owner") else "fail","owner",True))
    if agent.get("environment")=="prod":
        ok=agent.get("credential_type") not in {"static_api_key","client_secret"} and agent.get("credential_lifetime_minutes",10)<=60
        out.append(Result("CR-01",agent["id"],"pass" if ok else "fail","production credential",True))
    return out
def gate(results):
    return not any(r.status=="fail" and r.critical for r in results)
