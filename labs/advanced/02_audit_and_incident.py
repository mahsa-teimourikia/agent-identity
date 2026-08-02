from dataclasses import dataclass
@dataclass(frozen=True)
class Event: actor:str; action:str; resource:str; decision:str; policy_version:str; token_id:str
def contain(events,revoked,token): revoked.add(token); return [e for e in events if e.token_id==token]
if __name__=='__main__':
    es=[Event('agent','read','ticket','allow','v4','tok-1'),Event('agent','refund','order','deny','v4','tok-1')]; r=set(); assert len(contain(es,r,'tok-1'))==2 and r=={'tok-1'}
    print('PASS: kill switch revokes token and finds affected events')
