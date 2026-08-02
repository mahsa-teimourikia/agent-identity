from dataclasses import dataclass
@dataclass(frozen=True)
class Request: tenant:str; resource_tenant:str; team:str; resource_team:str; action:str; risk:str
def allow(r):
    if r.tenant!=r.resource_tenant:return False,'tenant mismatch'
    if r.team!=r.resource_team:return False,'relationship mismatch'
    if r.action=='refund:write' and r.risk!='low':return False,'approval required'
    return (True,'allowed') if r.action in {'ticket:read','ticket:comment','refund:write'} else (False,'unknown action')
if __name__=='__main__':
    r=Request('acme','acme','support','support','ticket:read','low'); assert allow(r)[0]
    assert not allow(Request('acme','other','support','support','ticket:read','low'))[0]
    print('PASS: ABAC/ReBAC policy combines tenant, team, action, risk')
