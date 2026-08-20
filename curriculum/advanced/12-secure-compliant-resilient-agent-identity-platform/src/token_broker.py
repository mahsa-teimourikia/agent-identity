from datetime import datetime,timedelta,timezone
import secrets
def issue(subject,audience,scope,lifetime_minutes=10,actor=None):
    now=datetime.now(timezone.utc)
    return {"jti":secrets.token_hex(12),"sub":subject,"act":actor,"aud":audience,
            "scope":sorted(set(scope)),"iat":now,"exp":now+timedelta(minutes=lifetime_minutes)}
def exchange(parent,audience,scope,lifetime_minutes=5,actor=None):
    if not set(scope).issubset(parent["scope"]):
        raise PermissionError("scope escalation")
    return issue(parent["sub"],audience,scope,lifetime_minutes,actor=actor or parent.get("act"))
def usable(token,audience,action,now=None,revoked=None):
    now=now or datetime.now(timezone.utc); revoked=revoked or set()
    return token["jti"] not in revoked and token["aud"]==audience and action in token["scope"] and now<token["exp"]
