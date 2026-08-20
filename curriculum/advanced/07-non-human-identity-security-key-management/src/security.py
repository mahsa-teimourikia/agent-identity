import re
SECRET_PATTERNS=[
 re.compile(r"Bearer\s+[A-Za-z0-9._~-]+",re.I),
 re.compile(r"AKIA[A-Z0-9]{16}"),
 re.compile(r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----")
]
def redact(text):
    for p in SECRET_PATTERNS:text=p.sub("[REDACTED]",text)
    return text
def blast_radius(credential):
    return {"resources":credential.get("resources",[]),
            "scopes":credential.get("scopes",[]),
            "minutes":credential.get("lifetime_minutes")}
