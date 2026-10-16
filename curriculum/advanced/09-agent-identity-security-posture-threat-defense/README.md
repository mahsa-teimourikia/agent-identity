# Advanced 09 — Agent Identity Security Posture Management & Threat Defense

![Agent Identity Security Posture Management & Threat Defense](images/identity-posture-threat-defense.png)

> **Goal:** turn agent identity from a static access-control configuration into a continuously observed, graph-analyzed, attack-tested and rapidly defensible security system.

## Northstar Mutual incident lab

Northstar Mutual operates a research agent that delegates retrieval to a vector tool and can reach a claims API and its signing key through approved service relationships. A compromised external vendor session reaches the research agent, widens a child delegation, replays a proof, attempts persistence, and suppresses telemetry. You are the identity defense engineer responsible for breaking that path without disabling the entire platform.

The executable lab builds one coherent control plane:

```text
signed source event → strict normalization → rule + graph detection
       → scoped response → recovery gates → tamper-evident evidence
                           ↘ labelled evaluation + release gate
```

You will use commonly deployed Python libraries: **Pydantic** for strict event contracts, **PyJWT + cryptography** for Ed25519-signed teaching envelopes, **NetworkX** for identity-graph analysis, **PyYAML** for safe detection configuration, **pandas** for analysis, and **pytest** for adversarial verification. The repository also includes illustrative OPA/Rego and Cedar policies.

### Run the lab

From this course directory:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python lab.py
pytest -q
```

The deterministic release gate expects the hardened pipeline to classify all **30/30** labelled cases with zero false positives and zero false negatives. The deliberately weak opaque-risk baseline classifies **12/30**, with 17 false negatives and one false positive. These fixtures test control logic; they are not a claim of real-world efficacy.

### Security invariants

- Parsing is not trust: only an authenticated, authorized telemetry source can create a `VerifiedEvent`.
- Issuer, audience, tenant, validity, event authority, sequence, and replay state are checked before detection.
- Detection rules select allowlisted functions; YAML cannot inject executable expressions.
- A widened delegation, revoked identity, unhealthy telemetry, wrong audience, cross-environment use, and runtime-binding mismatch are deterministic controls—not model opinions.
- A behavioral anomaly queues human review; it cannot independently disable production authority.
- Containment is allowlisted, idempotent, and scoped to the credential, delegation, client, or workload that breaks the path.
- Recovery requires current credential state, healthy telemetry, re-attestation, persistence removal, and incident approval.
- Evidence is hash-chained, but a production system still needs independent signed checkpoints, trusted time, retention controls, and append-only storage.

### Lab boundary

Everything runs locally, without credentials or network calls. The JWT is a **Security Event Token-shaped teaching envelope**, not a complete OpenID Shared Signals transmitter/receiver implementation. The custom YAML schema demonstrates safe detection-as-code but does not claim Sigma compatibility. The graph priority value is a transparent ordinal index, not breach probability. OPA and Cedar files illustrate preventive policy controls; deploying either requires its real engine, policy lifecycle, and integration tests.

Agent ecosystems create a new security graph:

```text
Human / Agent / Workload
        ↓
Credential / Delegation
        ↓
Agent / Sub-agent / Tool
        ↓
API / MCP / Cloud Role
        ↓
Data / KMS / Business Action
```

The key question is no longer only **"is this identity authenticated?"** It is also:

> **If this identity is compromised, where can the attacker go next—and how quickly can we detect and stop it?**

## Learning outcomes

You will learn to build identity graphs; discover attack paths and toxic privilege combinations; quantify blast radius; detect stolen credentials, anomalous delegation and lateral movement; design Identity Threat Detection and Response (ITDR); continuously score posture; map OWASP NHI risks into detections; use workload and federation telemetry; automate containment; run identity red-team exercises; and measure detection/response effectiveness.


# 1. From IAM to identity threat defense

Traditional IAM asks whether an identity may access a resource. Identity threat defense also asks whether the identity, credential, delegation path, runtime, and observed behavior still make sense **now**.

For agents this matters because identity is connected to tools, delegated authority, credentials, sub-agents, APIs, data stores, cloud roles, and external trust. A valid credential can therefore be part of an invalid attack path.


# 2. Threat model

Model the attacker across stages:

```text
initial access → credential theft → privilege escalation → delegation abuse
→ lateral movement → sensitive resource access → persistence → evasion → impact
```

The defender needs controls at every transition, not only at login.


# 3. Agent-specific identity attack surface

Inventory agents, sub-agents, workload identities, OAuth clients, API keys, certificates, SVIDs, cloud roles, tool gateways, MCP servers, CI/CD principals, federation relationships, external agents, policy engines, audit systems, and emergency identities.


# 4. Identity graph

Represent identity relationships as a graph. Nodes can be principals, credentials, services, tools, resources, policies, sessions and trust domains. Edges can represent `AUTHENTICATES_AS`, `HAS_ROLE`, `CAN_ACCESS`, `CAN_DELEGATE`, `CAN_MINT`, `TRUSTS`, `RUNS_AS`, and `OWNS`.

Graph analysis exposes risk hidden by flat IAM tables.


# 5. Attack paths

An attack path is a sequence of relationships that turns one compromise into a valuable outcome.

```text
stolen research-agent token
→ research agent
→ delegated data-agent
→ vector store
→ sensitive documents
```

The shortest path is not always the most likely path; weight edges by exploitability, privilege, detectability, and business impact.


# 6. Choke points

A choke point is a node or edge whose removal blocks many high-impact attack paths. Examples include a credential broker, broad cloud role, delegation gateway, shared OAuth client, signing key, or trust relationship. Prioritize remediation by **risk reduction per change**, not by finding count.


# 7. Blast radius

Blast radius asks what a compromised identity can ultimately influence. Include direct permissions, delegated permissions, credential-minting capability, transitive trust, tool calls, writable policy/configuration, and identities it can create.


# 8. Toxic combinations

Individually reasonable privileges may become dangerous in combination. Examples: `read secrets + deploy workload`, `create agent + delegate authority`, `write policy + approve policy`, or `invoke signer + control signed payload`. Detect combinations, not only single permissions.


# 9. Credential exposure

Search for credentials in repositories, build artifacts, environment variables, logs, traces, notebooks, prompts, ticket systems, container layers and secret stores with excessive readers. Detection should create a lifecycle response: validate → revoke → rotate → investigate use.


# 10. Secret leakage and OWASP NHI

OWASP's 2025 Non-Human Identities Top 10 explicitly includes secret leakage, long-lived secrets, overprivileged NHIs, insecure authentication, NHI reuse, environment isolation, third-party NHI risk and improper offboarding. Agent identity programs should map these risks into controls and detections.


# 11. Long-lived credential risk

Risk rises with credential lifetime because theft remains useful longer. Measure credential age, maximum lifetime, last rotation, ability to renew, audience, scope, sender constraint, and whether the credential can mint another credential.


# 12. Credential replay

Detect use of the same credential or proof from impossible or unusual contexts. For sender-constrained protocols, verify proof binding. For replay-sensitive assertions, track `jti`, nonce, time window, HTTP method/resource binding, or protocol-specific replay controls.


# 13. Credential stuffing does not map cleanly

Machine identity attacks differ from password attacks. The analogous problems are leaked API keys, copied client secrets, stolen tokens, cloned certificates, compromised signing keys, and abuse of federation/bootstrap trust. Detection engineering must reflect machine credential semantics.


# 14. Identity impersonation

A technically valid credential may represent the wrong expected principal. Validate issuer, subject, audience, trust domain, workload binding, deployment binding, tenant and intended use—not just signature validity.


# 15. Workload identity compromise

With SPIFFE/SPIRE or cloud workload identity, investigate the workload attestation boundary: which process/node obtained the identity, whether selectors changed, whether the workload endpoint was exposed, and whether a compromised workload can continuously renew credentials.


# 16. Federation risk

Federation expands authentication across administrative boundaries. Treat foreign trust domains, OIDC issuers, certificate authorities and partner identity systems as attack-surface nodes. Review trust establishment, bundle/key changes and termination.


# 17. Third-party NHI risk

External agents and SaaS integrations can bring their own credentials, lifecycle and incident-response constraints. Record provider, owner, trust mechanism, permissions, evidence, termination mechanism, and breach notification path.


# 18. Delegation abuse

Agent systems make delegation a first-class threat. Detect authority that becomes broader, longer-lived, deeper, re-delegatable, cross-tenant, cross-environment or unrelated to the parent task.


# 19. Delegation graph

Model delegation edges separately from static entitlement edges. Store parent, child, actions, resources, validity window, depth, redelegation flag, approver, purpose and trace ID. This enables both policy validation and forensic reconstruction.


# 20. Privilege escalation

Escalation can happen through IAM changes, token exchange, tool capabilities, sub-agent creation, policy modification, role assumption, signing services, CI/CD, or confused-deputy behavior. Detect **effective authority** changes, not only IAM role changes.


# 21. Lateral movement through tools

An agent can pivot without network-shell behavior: compromised agent → permitted tool → service identity → data store. Tool invocation therefore belongs in identity telemetry and attack-path analysis.


# 22. MCP and tool identity risk

For MCP/tool ecosystems, track which agent identity invoked which server/tool, under which user/delegated authority, which credential was used by the execution layer, and which resource was affected. Tool discovery should not imply tool authorization.


# 23. Confused deputy

A privileged tool or broker may perform an operation for an attacker-controlled agent. Bind caller identity, represented user/principal, delegation, target resource, action and policy decision at the privileged service.


# 24. Identity reuse

Shared service accounts, OAuth clients, API keys and generic agent identities destroy attribution and enlarge blast radius. Prefer per-workload/per-agent identities and narrowly scoped runtime credentials.


# 25. Human use of NHI

Humans impersonating production machine identities for debugging can defeat attribution and behavior baselines. Separate human emergency access from workload identity and make impersonation explicit, temporary and audited.


# 26. Environment isolation

Do not let development identities authenticate to production merely because naming looks similar. Use separate trust domains/accounts/projects, audiences, issuers, roles and policies where appropriate.


# 27. Persistence

Attackers may persist through new OAuth clients, API keys, certificates, sub-agents, federation relationships, policy changes, delegated grants, CI/CD secrets or modified workload registration. Hunt for identity creation after compromise.


# 28. Defense evasion

Identity attackers may suppress logs, disable monitoring, use trusted tools, rotate to another credential, reduce noisy activity or exploit shared identities. Treat telemetry health and audit configuration as security controls.


# 29. Identity telemetry model

Normalize events around: timestamp, principal, workload, credential fingerprint, represented subject, action, resource, decision, policy version, delegation chain, session/trace, source context, risk signals and result.


# 30. Signal sources

Useful sources include IdP/OAuth logs, SPIFFE/SPIRE telemetry, cloud IAM/STS, KMS, secret managers, API gateways, MCP/tool gateways, application authorization, Kubernetes audit, CI/CD, EDR, SIEM, policy engines and governance inventory.


# 31. ITDR loop

A practical identity threat detection and response loop is:

```text
collect → normalize → correlate → detect → investigate → prioritize
→ contain → revoke/rotate → recover → validate → learn
```

Automate deterministic containment but preserve human oversight for high-impact actions.


# 32. Behavioral detection

Baseline expected audiences, resources, tools, hours, environments, delegation patterns, token exchange rates, KMS use and action frequencies. Behavioral anomalies are signals—not proof—so combine them with entitlement and context.


# 33. Rule-based detection

Rules remain valuable for high-confidence invariants: revoked identity used, forbidden audience, stale key after rotation, self-approved privilege, delegation beyond parent, static prod credential, human use of workload identity, or monitoring disabled.


# 34. Graph-based detection

Graph queries can identify paths such as `external agent → can delegate → privileged agent → can access → restricted data` or principals that can both modify and approve identity policy. Recompute when entitlements or trust change.


# 35. Risk scoring

Score risk using exposure, privilege, credential weakness, delegation, external trust, exploitability, detectability and business impact. Keep component scores visible; do not let a single average hide a critical condition.


# 36. Posture management

Posture is the continuously evaluated security state of identities and their relationships. Dimensions can include inventory coverage, ownership, credential hygiene, least privilege, delegation security, trust hygiene, detection coverage, runtime binding, response readiness and audit integrity.


# 37. Critical overrides

Some conditions should override aggregate posture: known leaked active credential, revoked-but-active identity, unrestricted signing oracle, unaudited critical identity, compromised trust root, or active cross-tenant delegation violation.


# 38. Continuous exposure management

Prioritize exposures that create exploitable paths to high-value resources. The unit of work is not 'fix every finding'; it is 'remove the paths that matter most while preserving required business capability.'


# 39. Detection coverage

Map threat scenarios to telemetry and detections. A control is not operationally complete if the organization cannot tell whether it is being bypassed. Track scenarios with no signal source, no rule, no owner or no response playbook.


# 40. Shared Signals, CAEP and RISC

OpenID Shared Signals Framework, CAEP and RISC became Final Specifications in 2025. They provide standardized ways to exchange security events and changes in state. They are useful building blocks for continuous identity response, though agent-specific semantics may require additional event profiles.


# 41. Automated containment

Possible actions: deny token exchange, revoke token/client, quarantine workload, remove delegation, disable tool, block signing, force re-attestation, reduce to read-only, suspend federation or require human approval. Choose the smallest action that safely breaks the attack path.


# 42. Kill switches

A kill switch should be scoped, authenticated, tested and observable. Prefer multiple levels: revoke one credential, suspend one agent, remove one capability, quarantine a workload, or stop a trust relationship—rather than only an enterprise-wide off switch.


# 43. Recovery

Recovery requires more than issuing a new token. Re-establish trustworthy runtime state, rotate affected keys, remove persistence, re-attest workloads, re-evaluate delegation, validate policy, restore monitoring, and then selectively restore authority.


# 44. Forensics

Preserve identity timelines, policy decisions, credential issuance, token exchanges, delegation chains, tool calls, KMS operations, administrative changes, workload evidence and audit integrity. Stable correlation IDs make cross-system reconstruction feasible.


# 45. Red teaming agent identity

Test identity boundaries deliberately: steal a simulated token, replay it, request a broader exchanged token, create an excessive delegation, pivot through a tool, abuse a signer, impersonate a workload, alter trust, suppress telemetry, and attempt persistence.


# 46. Purple-team loop

For every attack simulation record: preconditions, technique, expected signal, actual signal, prevention result, detection latency, response latency, residual path and remediation. Feed findings back into policy and course exercises.


# 47. Detection-as-code

Version rules, graph queries, thresholds and test fixtures. Unit-test both positive and negative cases so a detection does not silently disappear during schema or telemetry changes.


# 48. Response-as-code

Encode safe response workflows with approvals and guardrails. Example: `high-confidence leaked token → revoke automatically`; `suspected production workload compromise → quarantine + page owner`; `critical trust-domain compromise → security approval for federation suspension`.


# 49. Metrics

Track exposed credentials, long-lived credentials, attack paths to crown jewels, toxic combinations, high-risk delegations, detection coverage, mean time to detect, mean time to contain, mean time to revoke, stale identities, critical posture failures and recurrence.


# 50. Reference architecture

```text
Identity / Credential / Tool / Cloud / Policy Telemetry
                       ↓
               Normalize + Correlate
                       ↓
                  Identity Graph
                 ↙             ↘
          Posture Engine      Detection Engine
                 ↘             ↙
                 Risk Prioritizer
                       ↓
             Response Orchestrator
        revoke | quarantine | reduce | rotate
                       ↓
                 Evidence Store
                       ↓
          Governance + Continuous Improvement
```


# 51. Production principles

1. Identity is the new perimeter only if identity relationships are visible.  
2. Assume credentials can be stolen.  
3. Minimize privilege and credential lifetime.  
4. Model delegation explicitly.  
5. Detect attack paths, not only bad events.  
6. Correlate identity with runtime and tool activity.  
7. Make response fast and scoped.  
8. Preserve evidence.  
9. Continuously test defenses.  
10. Automate with human oversight.


# 52. Enterprise checklist

Before production, confirm identity graph coverage, crown-jewel tagging, credential inventory, delegation visibility, external trust inventory, high-confidence detections, replay controls, posture thresholds, response playbooks, revocation tests, telemetry-health alerts, forensic retention, red-team scenarios, owners and measurable SLAs.

# State of the art and standards

## NIST: software and AI agent identity

NIST NCCoE's February 2026 paper focuses on applying identity standards and best practices to agentic AI, with explicit attention to identification, authorization, auditing, non-repudiation and prompt-injection-related controls. It is an **Initial Public Draft**, not a final standard, so use it as emerging direction rather than a conformance baseline.

https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd

## NIST incident response

NIST SP 800-61 Revision 3, finalized in April 2025, integrates incident response into Cybersecurity Framework 2.0 risk management. This course's prepare, detect, contain, recover, validate and learn loop follows that operational framing.

https://csrc.nist.gov/pubs/sp/800/61/r3/final

## OWASP Non-Human Identities Top 10 — 2025

The OWASP NHI Top 10 is an OWASP incubator project and a useful threat taxonomy for machine identities: improper offboarding, secret leakage, vulnerable third-party NHI, insecure authentication, overprivilege, insecure cloud deployment, long-lived secrets, environment isolation, NHI reuse and human use of NHI.

https://owasp.org/projects/non-human-identities-top-10

## SPIFFE

SPIFFE provides workload identity standards for heterogeneous infrastructure. Its current standard family includes SPIFFE IDs, X.509-SVID, JWT-SVID, WIT-SVID, Workload API, Broker API and Federation.

https://spiffe.io/docs/latest/spiffe-specs/

## OpenID Shared Signals

Shared Signals Framework 1.0, CAEP 1.0 and RISC 1.0 were approved as OpenID Final Specifications in September 2025. They are relevant to continuous security-event exchange and near-real-time identity response.

https://openid.net/three-shared-signals-final-specifications-approved/

The CAEP Interoperability Profile remains a draft as of this course update. Evaluate it separately from the final SSF/CAEP/RISC specifications.

https://openid.net/specs/openid-caep-interoperability-profile-1_0.html

## Threat knowledge and portable detections

- MITRE ATT&CK T1078.004 covers abuse of valid cloud accounts: https://attack.mitre.org/techniques/T1078/004/
- MITRE ATLAS tracks adversary tactics and techniques for AI-enabled systems: https://atlas.mitre.org/
- The Sigma specification defines a portable rule structure for log detections: https://sigmahq.io/sigma-specification/

The lab maps scenarios to these bodies where useful. Its YAML is deliberately smaller than Sigma, because exposing the translation boundary is more accurate than implying compatibility.

## Additional frameworks to map into the program

- NIST SP 800-207 — Zero Trust Architecture
- MITRE ATT&CK — enterprise adversary behaviors and detection thinking
- MITRE ATLAS — AI-system threat knowledge base
- CIS Controls — operational defensive controls
- SLSA — software supply-chain provenance
- OAuth 2.0 / Token Exchange / mTLS / DPoP — credential and sender-constraint foundations
- OPA and Cedar — policy-as-code examples used throughout the curriculum

## Tool and integration choices

| Need | Lab choice | Common production alternatives | Boundary |
|---|---|---|---|
| Event validation | Pydantic | JSON Schema, Protobuf, Avro | A valid shape is not an authenticated source. |
| Signed event | PyJWT + Ed25519 | OpenID SSF transmitter/receiver, managed event bus | The lab envelope is SET-shaped, not a complete protocol implementation. |
| Relationship analysis | NetworkX | Neo4j, Amazon Neptune, graph analytics platforms | In-memory graphs do not provide enterprise freshness or scale. |
| Detection-as-code | allowlisted PyYAML | Sigma, SIEM-native rules, OCSF-backed pipelines | Translate and test against the actual event schema. |
| Preventive policy | OPA/Rego and Cedar examples | cloud IAM, Zanzibar-style engines, vendor policy services | Prevention and detection remain separate controls. |
| Analysis and tests | pandas + pytest | notebooks, data warehouses, security validation platforms | Fixture metrics require production shadow evaluation before rollout. |

# Practical notebook

The accompanying notebook follows the Northstar incident end to end. It imports the same `lab.py` implementation exercised by tests; validates a signed source event; rejects unauthorized and replayed telemetry; enumerates attack paths and blast radius; compares remediation choices; loads and executes versioned rules; injects failures; performs scoped containment; distinguishes deterministic findings from a behavioral review signal; verifies evidence and recovery; and compares a weak baseline with the hardened 30-case release gate.

## Production upgrade path

1. Replace local keys and files with managed key custody, an SSF-capable transmitter/receiver or authenticated event bus, and a schema registry.
2. Populate the graph from authoritative IAM, workload, delegation, tool, cloud and data inventories with freshness SLOs.
3. Translate portable rules to Sigma or the target SIEM, normalize with OCSF/ECS where appropriate, and shadow-test before enforcement.
4. Put response behind production approvals, rate limits, segregation of duties, rollback, ticketing and on-call integration.
5. Anchor evidence externally and validate retention, privacy, data residency, trusted time and legal-hold requirements.
6. Recalibrate labelled datasets continuously; report precision, recall, latency, coverage and residual attack paths by scenario.

# Next course

## Advanced 10 — Identity Observability, Telemetry & Forensics for Agents

The next module will go deeper into OpenTelemetry-style identity correlation, authorization decision telemetry, agent/tool traces, credential and delegation events, security event schemas, CAEP/SSF integration patterns, evidence pipelines, tamper resistance, forensic reconstruction, SIEM integration, detection engineering and audit-ready identity observability.
