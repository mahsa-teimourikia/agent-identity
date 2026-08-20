import json,hashlib
from datetime import datetime,timezone
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),default=str)
def sha256(x):return hashlib.sha256(canonical(x).encode()).hexdigest()
def artifact(name,source,data):
    return {"name":name,"source":source,"collected_at":datetime.now(timezone.utc).isoformat(),
            "sha256":sha256(data),"data":data}
def manifest(control_id,period,artifacts):
    return {"control_id":control_id,"period":period,
            "artifacts":[{k:a[k] for k in ("name","source","collected_at","sha256")} for a in artifacts]}
