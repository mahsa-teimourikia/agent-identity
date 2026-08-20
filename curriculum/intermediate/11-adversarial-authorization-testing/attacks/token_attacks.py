"""Safe, local simulations of authorization token validation failures."""
import time
from dataclasses import dataclass

@dataclass
class Token:
    sub: str
    iss: str
    aud: str
    exp: int
    jti: str
    scope: set[str]

def validate_token(token, *, issuer, audience, now=None, seen_jti=None):
    now = now or int(time.time())
    if token.iss != issuer:
        return False, "INVALID_ISSUER"
    if token.aud != audience:
        return False, "INVALID_AUDIENCE"
    if token.exp <= now:
        return False, "TOKEN_EXPIRED"
    if seen_jti is not None and token.jti in seen_jti:
        return False, "TOKEN_REPLAY"
    return True, "TOKEN_VALID"
