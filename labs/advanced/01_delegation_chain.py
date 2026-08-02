from dataclasses import dataclass
@dataclass(frozen=True)
class Delegation: delegator:str; delegate:str; actions:frozenset; audience:str; depth:int; max_depth:int
def delegate(p,child,audience,actions):
    if p.depth>=p.max_depth or not actions<=p.actions: raise ValueError('delegation bound exceeded')
    return Delegation(p.delegate,child,frozenset(actions),audience,p.depth+1,p.max_depth)
if __name__=='__main__':
    p=Delegation('user','orchestrator',frozenset({'read','comment'}),'tickets',0,1); c=delegate(p,'specialist','tickets',{'read'}); assert c.depth==1
    try: delegate(c,'third','tickets',{'read'})
    except ValueError: pass
    else: raise AssertionError('depth ignored')
    print('PASS: typed delegation intersects scope and caps depth')
