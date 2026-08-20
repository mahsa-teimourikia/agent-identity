import json
def build(scope,controls,results,evidence,exceptions,findings):
    return {"scope":scope,"control_matrix":controls,"results":results,
            "evidence_manifest":evidence,"exceptions":exceptions,"findings":findings}
def save(pack,path):
    with open(path,"w") as f:json.dump(pack,f,indent=2,default=str)
