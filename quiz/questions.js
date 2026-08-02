const QUESTIONS=[
{level:'beginner',text:'Which claim identifies the intended API?',options:['audience','display name','prompt'],answer:0,explanation:'Audience binding prevents replay at another resource server.'},
{level:'beginner',text:'What should an unknown action do?',options:['Allow','Deny and audit','Ask the model'],answer:1,explanation:'Policy should fail closed.'},
{level:'beginner',text:'Which is a workload identity?',options:['agent://support/7','a prompt phrase','a UI color'],answer:0,explanation:'A stable workload subject identifies a deployment.'},
{level:'intermediate',text:'A child token may contain…',options:['any scope','only parent-contained scopes','all tenant scopes'],answer:1,explanation:'Exchange is monotonic and down-scoping.'},
{level:'intermediate',text:'Why use short expiry?',options:['limit replay blast radius','improve prose','avoid tests'],answer:0,explanation:'Expiry bounds stolen credential usefulness.'},
{level:'intermediate',text:'Risk can trigger…',options:['step-up approval','scope escalation','permanent access'],answer:0,explanation:'Risk gates sensitive operations.'},
{level:'intermediate',text:'ReBAC evaluates…',options:['resource relationships','only a role','model confidence'],answer:0,explanation:'Relationship-based authorization expresses teams and ownership.'},
{level:'advanced',text:'What limits delegation laundering?',options:['unbounded hops','scope intersection and depth limits','forwarded bearer token'],answer:1,explanation:'Bounded delegation prevents transitive privilege growth.'},
{level:'advanced',text:'What belongs in an audit event?',options:['policy version and token id','the secret','only final text'],answer:0,explanation:'Versioned decisions are reproducible without secrets.'},
{level:'advanced',text:'What does a kill switch do?',options:['block a principal quickly','retrain the model','widen access'],answer:0,explanation:'Containment should not wait for redeploy.'},
{level:'advanced',text:'Why treat retrieved instructions as untrusted?',options:['prompt injection can redirect tools','they are always wrong','it removes auth'],answer:0,explanation:'External policy checks remain authoritative.'},
{level:'advanced',text:'Which is a good release gate?',options:['negative cross-tenant tests','no audit trail','permanent admin tokens'],answer:0,explanation:'Adversarial tests demonstrate fail-closed boundaries.'}];
