from dataclasses import dataclass
@dataclass(frozen=True)
class IdentityContext:
    issuer:str; subject:str; tenant:str; audience:str; scopes:frozenset; expires_at:int
def validate(c,now,issuer,audience,tenant):
    if c.issuer!=issuer:return False,'untrusted issuer'
    if c.audience!=audience:return False,'wrong audience'
    if c.tenant!=tenant:return False,'cross-tenant request'
    if c.expires_at<=now:return False,'expired credential'
    return True,'accepted'
if __name__=='__main__':
    good=IdentityContext('issuer','agent://support/7','acme','tickets',frozenset({'read'}),100)
    bad=IdentityContext('issuer','agent://support/7','other','tickets',frozenset({'read'}),100)
    assert validate(good,1,'issuer','tickets','acme')[0] and not validate(bad,1,'issuer','tickets','acme')[0]
    print('PASS: identity validates issuer, audience, tenant, expiry')
