from dataclasses import dataclass
@dataclass(frozen=True)
class Grant: subject:str; audience:str; scopes:frozenset; expires_at:int
def exchange(parent,audience,requested,now,ttl):
    if parent.expires_at<=now or not requested<=parent.scopes: raise ValueError('scope escalation')
    return Grant(parent.subject,audience,frozenset(requested),min(parent.expires_at,now+ttl))
if __name__=='__main__':
    p=Grant('user:42','orchestrator',frozenset({'read','comment'}),1000); c=exchange(p,'tickets',{'read'},100,60)
    assert c.scopes=={'read'} and c.expires_at==160
    try: exchange(p,'billing',{'refund'},100,60)
    except ValueError: pass
    else: raise AssertionError('escalation accepted')
    print('PASS: exchange is audience-bound and down-scoped')
