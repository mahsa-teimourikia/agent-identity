from datetime import datetime,timedelta,timezone
import secrets
def issue(subject,audience,scopes,lifetime_minutes=10):
    now=datetime.now(timezone.utc)
    return {"id":secrets.token_hex(8),"sub":subject,"aud":audience,
            "scope":list(scopes),"iat":now,"exp":now+timedelta(minutes=lifetime_minutes)}
def usable(token,audience,scope,now=None):
    now=now or datetime.now(timezone.utc)
    return token["aud"]==audience and scope in token["scope"] and now<token["exp"]
