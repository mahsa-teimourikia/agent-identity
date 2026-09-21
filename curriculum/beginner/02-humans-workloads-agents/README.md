# Beginner 02 — Humans, Workloads and Agents

> **Goal:** learn to model the different identities participating in an agentic system instead of collapsing a user, application, logical agent, runtime workload, tool, and resource into one security principal.

The first course established that agent identity, authentication, authorization, and delegation are different concerns. This chapter goes deeper into **what exactly receives an identity**.

In an enterprise agent system, a single business action can involve a human employee, an interactive client, a logical agent, an orchestration service, a container or serverless workload, several tools, sub-agents, and protected resources. Each exists for a different reason and has a different lifecycle, owner, credential, and authorization boundary.

---

## Learning outcomes

You will be able to:

- distinguish human, application, agent, workload, service/tool, and resource identities;
- explain logical identity versus runtime identity;
- model ownership and delegation separately;
- distinguish an OAuth client from the human using it;
- distinguish a service account from the software using it;
- understand workload identity and attestation at a conceptual level;
- map identity across Kubernetes, cloud, serverless, and agent runtimes;
- preserve identity context through multi-hop calls;
- recognize shared-account, credential-reuse, environment-confusion, and attribution anti-patterns;
- design an agent identity registry.

## Prerequisites, success criteria, and non-goals

Complete [Course 01 — Agent Identity Foundations](../01-agent-identity-foundations/README.md) first. You need basic Python and API concepts; the lab requires no account, cluster, credential, or network access.

The practical work succeeds when:

- one valid employee → travel planner → booking specialist request remains available;
- nine identity-collision, environment, lifecycle, tenant, chain, and task-substitution cases fail closed;
- unauthorized success falls from `9/9` in the shared-platform baseline to `0/9` in the provenance-bound control;
- the valid decision preserves the human, application, logical-agent chain, workload, deployment binding, and delegation edges; and
- denials distinguish presented names from identities that were actually validated.

This course does not verify JWTs, operate SPIRE, configure cloud federation, or implement a production authorization engine. Course 03 adds credential verification; later courses add workload identity and policy systems. Here, `IdentityEvidence` is the sanitized result of an authenticator so the learner can concentrate on identity classes and relationships.

---

# 1. One action, many actors

Consider a travel assistant:

```text
Employee
   |
   v
Web Application
   |
   v
Travel Agent
   |
   v
Agent Runtime / Pod
   |
   +------> Calendar Tool
   +------> Travel Policy API
   +------> Booking Agent
                    |
                    v
                Booking API
```

"Who made the booking?" has several valid answers:

- the **employee** requested it;
- the **travel agent** decided to invoke a booking capability;
- a particular **runtime workload** executed the code;
- a **booking sub-agent** may have performed a delegated step;
- an OAuth **client/application** obtained a token;
- the **booking API** changed the reservation.

Security architecture needs enough identity information to answer the intended question precisely.

---

# 2. Identity taxonomy

## Human identity

Represents a natural person.

Examples:

- Microsoft Entra ID user;
- Okta workforce user;
- Google Workspace account;
- customer identity;
- privileged administrator.

Typical properties:

```yaml
id: user:alice
employee_id: E-1048
department: finance
manager: user:carol
groups:
  - procurement-requesters
assurance:
  mfa: true
```

Human identities carry organizational meaning: employment status, role, consent, accountability, and ownership.

They should not normally become the runtime identity of autonomous software.

---

## Application / client identity

An application identity represents software registered with an identity provider.

In OAuth terminology, a **client** is an application making protected-resource requests with authorization from a resource owner or on its own behalf.

Examples include:

```text
client:web-travel-portal
client:procurement-backend
client:mcp-client
```

A client registration can have:

- client ID;
- redirect URIs;
- permitted grant types;
- authentication method;
- allowed audiences/scopes;
- owner;
- credentials.

A client ID is not necessarily the identity of a logical AI agent. One application may host several agents, and one agent may execute across several workloads.

---

## Service account / service principal

Platforms often provide non-human identities:

- Microsoft Entra service principals / managed identities;
- AWS IAM roles;
- Google Cloud service accounts;
- Kubernetes ServiceAccounts.

These are useful building blocks, but terminology differs by platform.

A key design question is:

> Does this platform principal identify the logical agent, the deployed application, the workload, or merely a shared execution environment?

Do not assume a service account automatically gives you meaningful **agent-level** attribution.

---

## Logical agent identity

The logical agent represents the autonomous/semi-autonomous software entity as a security actor.

Examples:

```text
agent:travel-planner
agent:refund-specialist
agent:underwriting-assistant
agent:vendor-research
```

Useful metadata includes:

```yaml
id: agent:travel-planner
owner: team:travel-platform
purpose: employee travel planning
risk_tier: medium
production_status: approved
allowed_delegation_depth: 1
```

Why create a distinct logical identity?

Because you may need to:

- assign agent-specific policy;
- disable one agent without disabling its owner;
- distinguish two agents using the same infrastructure;
- audit agent actions;
- constrain delegation;
- bind an agent to approved workloads or versions;
- manage its lifecycle.

---

# 3. Logical agent versus workload

This distinction is fundamental.

A logical agent is a conceptual security actor:

```text
agent:travel-planner
```

A workload is executing software:

```text
Kubernetes pod
ECS task
Lambda invocation/environment
VM process
Cloud Run instance
container
serverless function
```

One logical agent can execute in many environments:

```text
                   agent:travel-planner
                           |
            +--------------+--------------+
            |              |              |
            v              v              v
           DEV           STAGING         PROD
            |              |              |
         workload        workload        workload
```

Production policy should not rely solely on the logical name.

For example:

```text
agent == travel-planner
AND
workload.trust_domain == corp.example
AND
workload.environment == production
```

This allows a system to reject a valid logical agent running from an unapproved environment.

---

# 4. Workload identity

A workload identity is an identity assigned to running software so it can authenticate without embedding long-lived secrets.

Modern patterns favor:

- platform-issued identity;
- attestation;
- short-lived credentials;
- automatic rotation;
- federation into external identity systems.

SPIFFE formalizes this around **SPIFFE IDs**, **SVIDs**, trust domains, and the Workload API.

Conceptually:

```text
Workload starts
     |
     v
Platform / agent attests workload
     |
     v
Identity system verifies selectors/evidence
     |
     v
Short-lived workload credential issued
     |
     v
Workload authenticates to service
```

Later courses build this with SPIFFE/SPIRE.

---

# 5. Workload attestation

The difficult question is not merely "what name should the workload have?"

It is:

> Why should the identity system believe this running process is entitled to that name?

Attestation can use evidence such as:

- Kubernetes namespace;
- Kubernetes ServiceAccount;
- pod labels;
- cloud instance identity;
- VM metadata;
- process information;
- node identity;
- container properties.

Example conceptual registration:

```text
If:
  namespace      = "agents-prod"
  serviceAccount = "travel-agent"
then:
  issue identity = spiffe://corp.example/prod/travel-agent
```

This moves trust away from static secrets baked into code.

---

# 6. SPIFFE ID mental model

A SPIFFE ID is a URI identifying a workload or other entity:

```text
spiffe://corp.example/prod/travel-agent
```

Components:

```text
spiffe://corp.example / prod / travel-agent
       ^ trust domain   ^ path
```

The URI is an identifier, not itself a credential.

An SVID is a verifiable identity document representing the SPIFFE ID. Common profiles include X.509-SVID and JWT-SVID.

That mirrors the distinction from Course 01:

```text
SPIFFE ID = identity
SVID      = evidence / credential
```

---

# 7. Human ownership is not execution identity

A human may own an agent:

```text
Alice ----owns----> Forecast Agent
```

That does not imply:

```text
Forecast Agent == Alice
```

Ownership is a **relationship**, not identity equality.

This distinction becomes important for:

- employee departure;
- team ownership transfer;
- audit;
- separation of duties;
- production support;
- revocation.

Enterprise agents should usually be organizational assets with explicit accountable owners, not shadow identities tied permanently to one employee's credentials.

---

# 8. Delegation is also a relationship

Likewise:

```text
Alice ----delegates----> Travel Agent
```

does not mean the agent becomes Alice.

A useful model is:

```text
identity:
  requester: user:alice
  actor: agent:travel-planner
  workload: spiffe://corp.example/prod/travel-agent

authority:
  delegated_by: user:alice
  task: trip:483
  scopes:
    - itinerary:read
    - flight:search
  expires_at: ...
```

Identity describes actors. Delegation describes authority between actors.

---

# 9. Resource identity

Authorization also needs a stable way to name the thing being protected.

Examples:

```text
document:policy-173
customer:8372
project:atlas
calendar:user:alice
purchase-order:PO-382
tool:create-refund
```

Without resource identity, authorization tends to collapse into coarse rules such as:

```text
agent may call documents_api
```

Fine-grained systems instead ask:

```text
May agent:research,
acting for user:alice,
read document:policy-173?
```

---

# 10. Tools and services are principals too

A tool may be a local function, remote API, MCP server, database facade, or another agent.

Remote services often need identities for both ends of the connection:

```text
Agent Workload --authenticated request--> Tool Service
Agent Workload <--authenticated service--- Tool Service
```

Mutual authentication matters in zero-trust architectures: the agent should also know that it is talking to the intended service.

---

# 11. Identity mapping

Real enterprise systems must map identities between domains.

Example:

```text
Entra user
   |
   | oid = 4f8...
   v
Internal user principal
   |
   | delegates
   v
Logical agent
   |
   | approved deployment mapping
   v
SPIFFE workload
   |
   | federates
   v
Cloud role
```

A mapping should be explicit and auditable.

Dangerous pattern:

```python
cloud_role = f"role/{agent_name}"
```

A name transformation is not proof of entitlement.

Secure mapping requires a trusted issuer, registration, policy, federation rule, or attestation.

---

# 12. Identity propagation

A multi-hop request can lose attribution:

```text
User -> Agent API -> Agent -> Tool Gateway -> Service -> Database
```

If every hop forwards only:

```text
Authorization: Bearer <service-token>
```

the final service may know the immediate caller but not the originating user or logical agent.

The correct solution is **not blindly forward all credentials**.

Instead distinguish:

1. authentication of the immediate caller;
2. trusted representation of upstream subject/actor context;
3. delegated authority;
4. trace/audit context.

Later OAuth courses examine token exchange rather than unsafe token passthrough.

---

# 13. Direct versus indirect identity

Suppose a tool receives:

```text
mTLS peer = workload:tool-gateway
```

but an application-level security context says:

```text
requester = user:alice
actor = agent:travel-planner
```

These are not contradictory.

They answer different questions:

```text
Who directly connected?       workload:tool-gateway
Who initiated business intent? user:alice
Which agent is acting?         agent:travel-planner
```

Production authorization may use all three.

---

# 14. Multi-agent identity

Multi-agent architectures increase the need for explicit identity.

```text
User
 |
 v
Supervisor Agent
 | \
 |  +----> Research Agent
 |
 +-------> Booking Agent
```

Never reduce this to:

```text
user -> "agent system"
```

Preserve:

```text
requester
current actor
parent actor
delegation chain
task
workload
```

A child agent should have independently constrainable authority.

---

# 15. Environment identity

Development and production must not be interchangeable.

Bad:

```text
service-account:travel-agent
```

used everywhere.

Better:

```text
spiffe://corp.example/dev/travel-agent
spiffe://corp.example/staging/travel-agent
spiffe://corp.example/prod/travel-agent
```

or equivalent cloud/platform identities.

Benefits:

- blast-radius reduction;
- clearer policy;
- safer CI/CD;
- independent revocation;
- better audit attribution.

---

# 16. Identity lifecycle differences

Different identity classes have different lifecycle triggers.

| Identity | Created when | Rotated/changed when | Disabled when |
|---|---|---|---|
| Human | join/customer signup | role/security changes | departure/account closure |
| App/client | application registration | credential/config change | application retired |
| Agent | agent onboarding | ownership/risk/purpose changes | agent retired |
| Workload | deployment/runtime | continuously/ephemerally | workload terminates |
| Service/tool | service onboarding | deployment/security changes | service retired |
| Resource | resource creation | ownership/classification change | deletion/archive |

Treating these as one identity creates lifecycle bugs.

---

# 17. Identity registry

An enterprise agent inventory should connect logical identity to governance metadata.

Example:

```json
{
  "id": "agent:travel-planner",
  "owner": "team:employee-experience",
  "purpose": "employee travel planning",
  "risk_tier": "medium",
  "approved_workloads": [
    "spiffe://corp.example/prod/travel-agent"
  ],
  "tools": [
    "tool:travel-policy",
    "tool:flight-search"
  ],
  "status": "active"
}
```

This is not a replacement for an IdP. It is a governance/control-plane view of the agent.

---

# 18. Anti-patterns

## Agent runs as the employee

Using an employee's credentials makes revocation, attribution, least privilege, and automation lifecycle difficult.

## One service account for all agents

You lose independent policy and forensic attribution.

## Same workload identity across environments

A compromised development workload can gain production-equivalent identity.

## Agent name from the prompt

Natural-language claims are not authenticated principal information.

## OAuth client ID == agent identity

Sometimes they map one-to-one, but this must be an architectural decision, not an assumption.

## Service account == workload instance

A platform account may be shared by many runtime instances. Decide what granularity your threat model requires.

## Owner == actor

The team or employee responsible for an agent is not the principal executing each action.

---

# 19. Enterprise reference model

A useful conceptual model is:

```text
+-------------------+
| HUMAN DIRECTORY   |
| users / groups    |
+---------+---------+
          |
          | owns / delegates
          v
+-------------------+
| AGENT REGISTRY    |
| logical agents    |
| owner / purpose   |
| risk / status     |
+---------+---------+
          |
          | approved deployment
          v
+-------------------+
| WORKLOAD IDENTITY |
| attestation       |
| short-lived creds |
+---------+---------+
          |
          | authenticates
          v
+-------------------+
| POLICY / TOOLS    |
| action/resource   |
| authorization     |
+-------------------+
```

The systems may be separate products. The important point is preserving the relationships.

---

# 20. State of the art and common tooling (September 2026)

The market is converging on separate human/workforce, application, workload, and agent control-plane identities. The exact product vocabulary is not portable, so architecture diagrams and audit schemas should use explicit roles rather than vendor nouns.

## Established practice

| Technology | Identity it establishes | What it does well | What it does not establish |
| --- | --- | --- | --- |
| Workforce IdP + OIDC | interactive human/session | assurance, lifecycle, groups, consent | runtime workload or agent authority |
| OAuth client registration | application/client | redirect, client authentication, grant policy | which logical agent ran inside the client |
| Kubernetes ServiceAccount projected token | pod-associated Kubernetes principal | bounded, rotating token mounted for a pod | portable cross-system identity by itself |
| AWS roles / EKS Pod Identity, Azure managed identity, Google Workload Identity Federation | cloud or federated workload principal | removes many static keys; integrates with cloud IAM | human requester, agent chain, business delegation |
| SPIFFE/SPIRE | attested workload identity and trust domain | portable SVID issuance, rotation, federation, mTLS/JWT profiles | application-level authorization or logical-agent governance |
| Agent inventory / registry | governed logical agent | owner, purpose, risk, status, approved deployment | cryptographic runtime authentication |
| OPA, Cedar, OpenFGA | policy or relationship decision | resource/action policy and graph relationships | trustworthy inputs or workload attestation |

The current Kubernetes bound service-account-token mechanism binds a projected token to a Pod and audience; it should not be treated like the older indefinitely reusable secret-token model ([Kubernetes administration guide](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)). Google’s current guidance similarly distinguishes Kubernetes ServiceAccounts from IAM service accounts and recommends workload federation rather than key files ([GKE workload identity](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)).

## Emerging agent-specific practice

- NIST’s 2026 software/AI-agent identity work explicitly connects identification, authorization, auditing, non-repudiation, and prompt-injection controls. It is an active applied-security initiative, not a final universal agent identity standard ([NIST concept paper announcement](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents)).
- Cloud identity platforms are adding agent-specific identity and lifecycle constructs. Use them where helpful, but document how each maps to requester, actor, workload, owner, and resource because provider semantics differ.
- OpenFGA models agents as principals and supports task-scoped relationships, expiration, call limits, agent binding, and narrower sub-agent tasks ([OpenFGA agent modeling](https://openfga.dev/docs/modeling/agents)). Those are authorization relationships, not proof that a running process is that agent.
- SPIFFE’s stable Workload API describes X.509-SVID, JWT-SVID, and WIT-SVID profiles; the API implementation identifies the local caller out of band before returning entitled identity material ([SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/)).

## Standards frontier

The IETF WIMSE working group is developing workload identifiers, credentials, mTLS, HTTP signatures, proof tokens, operational practice, and an architecture for identity across systems. The July 2026 architecture remains an active Internet-Draft rather than an RFC ([WIMSE architecture](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch)). Execution-context and AI-agent-specific proposals are frontier work; production designs should not describe drafts as settled interoperability guarantees.

Portable logical-agent identity, instance-level identity, cross-organization delegation, trustworthy execution evidence, and consistent requester/actor propagation remain integration problems. An agent card, model name, prompt role, framework session, service-account name, or registry row may add context; none alone proves the full path.

---

# 21. Worked travel-booking trace

The lab’s valid path has six distinct security identities:

```text
requester     user:alice
application   client:travel-portal
parent actor  agent:travel-planner
current actor agent:booking-specialist
workload      spiffe://corp.example/prod/booking-specialist
resource      trip:483
```

The resource-side gate validates two separate delegation edges:

```text
user:alice → agent:travel-planner → agent:booking-specialist
             task trip:483          booking:create on trip:483
```

It also requires the application, current actor, workload, production environment, and deployment version to match one approved binding. A corporate workload credential alone is insufficient.

The public record distinguishes presented from validated fields. If a research workload claims to be the booking specialist, the denial can retain the evidence and presented label for investigation without asserting that the booking identity was authenticated.

# 22. Practical lab

The canonical implementation is [`lab.py`](lab.py). From the repository root:

```bash
python3 curriculum/beginner/02-humans-workloads-agents/lab.py
uv run pytest curriculum/beginner/02-humans-workloads-agents/tests -q
```

Use the [guided notebook](humans_workloads_agents.ipynb) for the baseline → identity graph → controlled trace → experiments → evaluation → failure-injection sequence.

| Case | Changed identity fact | Expected | Boundary exercised |
| --- | --- | --- | --- |
| Valid multi-hop booking | none | allow | all identities and edges agree |
| Spoofed logical agent | authenticated workload | deny | label cannot override runtime |
| Development runtime | environment | deny | dev cannot inherit production identity |
| Application collision | OAuth/application client | deny | client is part of deployment provenance |
| Unknown requester | human principal | deny | prompt subject is not a directory identity |
| Cross-tenant context | propagated tenant | deny | all authorities must agree |
| Missing parent actor | actor relationship | deny | sub-agent cannot erase its parent |
| Cyclic actor chain | chain topology | deny | no repeated or unbounded actors |
| Task substitution | delegated task | deny | authority is task/resource bound |
| Disabled workload | lifecycle | deny | runtime revocation is independent |

# 23. Evaluation

The lab evaluates the same labelled cases against two designs:

- **collapsed baseline:** any corporate workload becomes `service-account:agents-prod`;
- **provenance-bound gate:** validates every identity class, approved deployment, chain edge, tenant, task, and resource.

```text
valid_task_success_rate = allowed valid cases / valid cases
unauthorized_success_rate = allowed invalid cases / invalid cases
invalid_block_rate = denied invalid cases / invalid cases
valid_provenance_completeness_rate = complete valid decisions / valid cases
invalid_identity_collision_rate = invalid allows using a valid audit principal / invalid cases
```

| Metric | Better | Baseline | Controlled |
| --- | --- | ---: | ---: |
| Valid task success | higher | `1/1` | `1/1` |
| Unauthorized success | lower | `9/9` | `0/9` |
| Invalid block rate | higher | `0/9` | `9/9` |
| Valid provenance completeness | higher | `0/1` | `1/1` |
| Invalid identity collision | lower | `9/9` | `0/9` |

These figures prove only the fixture’s invariants. A production evaluation should add credential/key rotation, registry and directory staleness, partial dependency failure, duplicate/replayed envelopes, concurrent lifecycle change, tenant/risk slices, latency percentiles, and false-denial investigation.

# 24. Failure modes and production upgrades

| Failure | Consequence | Upgrade |
| --- | --- | --- |
| Shared platform/service account | actions collide in audit and policy | distinct workload identity plus logical-agent binding |
| Prompt-provided requester or actor | forged provenance | derive from authenticated session and governed mappings |
| Same identity in dev and prod | lower-trust runtime gains production standing | environment-specific principals/trust domains |
| Blind token forwarding | downstream sees impersonated user or excessive rights | per-hop authentication and attenuated token exchange |
| Unsigned propagation headers | caller rewrites identity chain | trusted hop, signed envelope, or tokenized actor context |
| Unbounded actor list | cycles, chain confusion, denial of service | canonical order, maximum depth, duplicate detection |
| Owner treated as actor | governance relationship becomes runtime permission | separate owner/sponsor, requester, actor, and workload fields |
| Registry outage fails open | unknown deployment gains identity | fail closed for effects; narrowly govern cached/read-only paths |
| Raw credentials in audit | replay and privacy exposure | log stable IDs, evidence references, versions, and reason codes |

Production systems also need an identity namespace policy, immutable subject mappings, ownership transfer, joiner/mover/leaver events, deployment admission, versioned bindings, rapid workload disablement, cache invalidation, correlation across hops, privacy retention, and incident runbooks.

# 25. Design review checklist

For every enterprise agent ask:

- Which principal initiated business intent, and how was the human session authenticated?
- Which application/client received it, and can several agents share that client?
- Which logical agent is the current actor, and who owns or sponsors it?
- Which exact workload and environment executed it, and what attested that mapping?
- Which parent actors and delegation edges explain the current actor’s authority?
- Which service was the immediate authenticated peer, and which service is the intended audience?
- Which authoritative system owns tenant and resource identity?
- Can the resource reject a missing, reordered, duplicated, or overlong actor chain?
- Can one agent, deployment, credential, owner, or environment be disabled independently?
- Can audit records distinguish presented values from validated identities without storing secrets?

# 26. Exercises

1. Add a second valid direct path in which the travel planner reads an itinerary without invoking the booking specialist. Define its correct parent and chain.
2. Add a maximum delegation depth of one and explain whether the valid booking path counts one or two delegations.
3. Replace the development workload with a staging workload and decide whether environment is encoded in the identifier, registry, evidence, or all three.
4. Simulate a registry binding update during a request. Define whether the resource uses snapshot, version, or latest-state semantics.
5. Design a signed propagation envelope. Name its issuer, audience, replay key, lifetime, and which fields must never be caller-controlled.
6. Map the lab identities to Kubernetes + SPIRE, AWS EKS Pod Identity, Azure managed identity, or GKE Workload Identity Federation. Identify what each platform still cannot express.

# 27. Checkpoint

The booking API authenticates `spiffe://corp.example/prod/research-assistant`, while the request envelope claims `agent:booking-specialist` and names a valid employee. What should it do?

- A. Allow because both workloads are in the corporate trust domain.
- B. Allow because the employee is valid.
- C. Deny because the authenticated workload is not the approved deployment for the claimed current actor and application.

**Answer: C.** Authentication of a corporate workload is useful evidence, but the resource must also validate the logical-agent/workload/application binding and delegation path.

# 28. Key takeaways

1. Human, application, logical-agent, workload, service, and resource identities answer different questions.
2. Ownership, sponsorship, deployment, and delegation are relationships—not identity equality.
3. Logical-agent identity supports governance; workload identity proves which software is running.
4. The immediate peer, business requester, and current actor can all differ legitimately.
5. Multi-agent chains require canonical order, bounded depth, task binding, and independent actors.
6. Environment and lifecycle are security facts; dev, prod, active, and disabled are not interchangeable.
7. Preserve identity provenance through trusted context without forwarding broad credentials blindly.
8. A model proposes identity-labelled actions; trusted systems establish and validate identities.

# References

## Standards and primary guidance

- NIST NCCoE, [Software and AI Agent Identity and Authorization concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf), 2026.
- NIST SP 800-207, [Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final).
- SPIFFE, [SPIFFE standard](https://spiffe.io/docs/latest/spiffe-specs/), [SPIFFE ID](https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/), and [Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/).
- SPIRE, [workload registration and attestation](https://spiffe.io/docs/latest/spire-about/spire-concepts/).
- IETF, [OAuth 2.0 Token Exchange, RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html).
- IETF WIMSE, [Workload Identity in a Multi System Environment Architecture](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch), active Internet-Draft.

## Official implementation guidance

- Kubernetes, [Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/) and [ServiceAccount token administration](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/).
- AWS, [workload access from EKS](https://docs.aws.amazon.com/eks/latest/userguide/service-accounts.html).
- Microsoft, [Entra workload identities](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview).
- Google Cloud, [identities for workloads](https://cloud.google.com/iam/docs/workload-identities) and [Workload Identity Federation best practices](https://cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation).
- OpenFGA, [authorization modeling for agents](https://openfga.dev/docs/modeling/agents).

## Next course

Continue to [Beginner 03 — Authentication, Credentials and Tokens](../03-authentication-credentials-tokens/README.md) to move from *what receives an identity* to *how a principal proves it*: keys, certificates, JWT/JWS/JWK, bearer versus sender-constrained credentials, validation, expiry, and rotation.
