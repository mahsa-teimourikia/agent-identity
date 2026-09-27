QUESTIONS_DB = {
    # BEGINNER
    "01-agent-identity-foundations": [
        ("A schema-valid purchase request claims to be from the procurement agent, but verified workload evidence identifies an unapproved development runtime. What should the purchasing API do?", ["Allow it because the declared agent name is correct", "Deny it because the verified workload is not bound to that production agent", "Ask the language model whether the request looks safe"], 1, "The enforcement point must bind verified workload evidence to the governed logical agent and fail closed on a mismatch."),
        ("Why should human, workload, and agent identities remain distinct?", ["To confuse attackers", "They should not remain distinct", "To prevent a development deployment from silently receiving production authority"], 2, "Separating them allows distinct enforcement and boundaries."),
        ("What does delegation mean in the context of agent identity?", ["Giving an agent full permanent access to everything", "Intentionally giving another principal bounded authority", "Writing the code for an agent"], 1, "Delegation passes bounded authority intentionally.")
    ],
    "02-humans-workloads-agents": [
        ("The booking API authenticates the corporate research workload, but the request envelope claims the booking-specialist agent and names a valid employee. What should it do?", ["Allow because the employee is valid", "Allow because both workloads use the corporate trust domain", "Deny because the workload is not the approved deployment for the claimed agent and application"], 2, "A corporate workload credential does not prove a different logical agent, application binding, or delegation path."),
        ("In an agent request context, what does the 'requester' represent?", ["The tool being called", "The principal that initiated the business intent", "The IP address of the server"], 1, "Requester maps to who originally asked for the action."),
        ("Why is it dangerous to simply forward a user's token directly to an agent?", ["Because tokens are heavy", "It hides the agent as an actor and gives it all of the user's permissions", "Because tokens expire too quickly"], 1, "Forwarding a bearer token is impersonation, masking the true actor and bypassing least privilege.")
    ],
    "03-authentication-credentials-tokens": [
        ("A signed token contains an unknown kid and a jku URL controlled by the caller. What should the purchasing API do?", ["Fetch the URL to discover the verification key", "Decode the claims and accept if the issuer string looks familiar", "Deny because key discovery must be configured for a trusted issuer, not redirected by token headers"], 2, "A key ID selects among issuer-bound trusted keys; received jku or x5u values must not create a trust anchor or SSRF path."),
        ("Which of the following is a type of credential providing evidence of identity?", ["A signed JWT", "A plain text JSON file", "A username"], 0, "Signed JWTs provide cryptographic evidence that can be verified."),
        ("What happens if a bearer token is leaked?", ["Nothing, they are secure by default", "It can lead to impersonation because possession is usually enough to use it", "The token automatically self-destructs"], 1, "Bearer tokens are susceptible to theft and replay.")
    ],
    "04-authorization-for-agents": [
        ("A refund agent has the broad `refund_agent` role and proposes a refund for another tenant's order. What should the tool gateway do?", ["Execute because the role permits refunds", "Ask the model whether the tenant mismatch is intentional", "Deny because role eligibility does not satisfy tenant, resource, task, and delegation constraints"], 2, "The PEP must enforce a resource-level, default-deny decision using trusted tenant and delegation data; a broad role alone is insufficient."),
        ("What is the primary difference between authentication and authorization?", ["They are the exact same concept.", "Authentication proves who you are; authorization decides what you can do.", "Authorization checks passwords; authentication checks permissions."], 1, "Authentication verifies identity, authorization checks permissions."),
        ("A manager approved a CAD 450 refund, but the agent changes it to CAD 460 before execution. What is required?", ["Reuse the approval because the order is unchanged", "Deny and require a new approval bound to the changed proposal digest", "Allow if the model explains the change"], 1, "Consequential approval must bind the exact action, resource, amount, tenant, policy version, and lifetime; changing the proposal invalidates it."),
        ("The PDP times out while the agent is about to create a refund. What should this write path do?", ["Fail open to preserve availability", "Let the agent apply its cached judgment", "Fail closed, record the dependency failure, and create no execution receipt"], 2, "A policy outage must not become an authorization bypass for a consequential side effect.")
    ],
    "05-least-privilege-tool-access": [
        ("An MCP server marks a tool as read-only, but the server is not trusted and the tool accepts an arbitrary URL. What should the client gateway do?", ["Grant automatic access because the annotation says read-only", "Treat the annotation as a hint and independently enforce authorization, strict arguments, and egress policy", "Ask the language model whether the URL looks safe"], 1, "MCP annotations are not enforcement guarantees; the trusted gateway must validate and authorize the call and network destination."),
        ("A booking response is lost after the airline may have committed the purchase. What is the safe next step?", ["Retry with a new operation ID", "Reconcile the original stable operation ID and request digest before any retry", "Assume the booking failed and issue another approval"], 1, "Unknown outcomes require reconciliation. Reusing the stable operation ID prevents a transport retry from becoming a duplicate effect."),
        ("A tool argument is schema-valid but targets another tenant's trip. What should happen?", ["Execute because schema validation passed", "Deny using authoritative resource ownership and tenant policy", "Let the tool credential decide after execution"], 1, "Schema validity proves shape, not authority. Resource authorization must run before the downstream call.")
    ],
    "06-agent-identity-lifecycle": [
        ("A provisioning workflow requests one capability that is absent from the independently approved agent manifest. What should the lifecycle controller do?", ["Provision it because the workflow has the provisioner role", "Deny it because provisioning must not widen the approved manifest and blueprint", "Ask the model whether the new capability is useful"], 1, "A provisioner may materialize approved intent but cannot expand it. The controller must bind exact manifest capabilities to the approved blueprint."),
        ("A retirement workflow removed the workload binding and grants, but credential cleanup timed out. What is the correct lifecycle state?", ["Retired, because most cleanup finished", "Active, so the agent can retry itself", "Retiring with a visible partial outcome, then resume the same idempotent operation"], 2, "Retirement is terminal only after every downstream category is verified. Partial cleanup must remain visible and retry under the same stable operation ID."),
        ("Two sponsor reviews read record version 7 and submit different decisions. The first commits version 8. What should happen to the second?", ["Overwrite version 8 because the sponsor role is valid", "Reject it as stale and require the reviewer to reload current state", "Merge the decisions using a language model"], 1, "Role eligibility does not make stale state current. Optimistic concurrency prevents a last-writer-wins lifecycle decision."),
        ("Security suspended an agent after suspected credential theft. What is required before reactivation?", ["A status toggle by the technical owner", "A new prompt instructing the agent to be careful", "Independent request-bound approval, rotated credential generation, and revalidation of activation invariants"], 2, "Reactivation is a new authorization decision; it must not restore compromised authority through a simple reversible flag.")
    ],

    # INTERMEDIATE
    "01-workload-identity-spiffe-spire": [
        ("A pod's attested selectors match two active SPIRE registration entries with different SPIFFE IDs. What should issuance do?", ["Choose the entry with the longest path", "Issue both identities so the pod can choose", "Deny issuance and repair the registration collision"], 2, "Multiple matches make the observed runtime-to-identity mapping ambiguous. The control plane must fail closed and repair the selector policy."),
        ("A partner workload presents a valid X.509-SVID chaining to its configured federated bundle. May it charge a Northstar booking?", ["Yes, federation grants reciprocal access", "Only if local authorization permits that exact authenticated SPIFFE ID, action, and resource", "Yes, if both trust domains use SPIRE"], 1, "Federation makes a partner identity verifiable; it does not create application authority. Local resource authorization remains mandatory."),
        ("A later full-state Workload API response omits an SVID that was present before. What must the client do?", ["Keep using it until the process restarts", "Stop using and remove the omitted SVID from its cache", "Merge the response and retain every credential ever observed"], 1, "Fetch responses represent complete current state. Omission or redaction means the prior SVID is no longer available for use."),
        ("During root rotation, generation-2 SVIDs are issued before verifiers receive the generation-2 root. What is the likely result and correction?", ["Authentication outages; distribute an old-plus-new overlap bundle before new issuance", "Automatic trust because the SPIFFE ID is unchanged", "Authorization bypass; add broader resource roles"], 0, "Identity stability does not bypass cryptographic trust. Ordered bundle overlap lets verifiers trust both generations during the transition.")
    ],
    "02-oauth-oidc-for-agents": [
        ("A travel agent has a correctly signed access token for the travel API and tries to use it at the payment API. What should the payment API do?", ["Accept it because the issuer and signature are valid", "Deny it because the token is not audience/resource-bound to the payment API", "Ask the model whether payment is part of the trip"], 1, "Signature validity does not override audience. Every resource server must accept only tokens issued for its own canonical resource."),
        ("A DPoP proof has a valid signature from the public key embedded in that proof, but the access token's cnf.jkt names a different key. What is the correct result?", ["Allow because either valid key proves possession", "Deny because the proof key is not the sender key bound into the token", "Remove cnf and treat it as a bearer token"], 1, "The embedded proof key is not authority. Its RFC 7638 thumbprint must match the access token confirmation claim."),
        ("An Authorization Code callback contains the correct state and code but an issuer different from the issuer stored with the transaction. What should the client do?", ["Redeem the code at the new issuer", "Deny before token redemption to prevent authorization-server mix-up", "Ignore issuer when PKCE is present"], 1, "PKCE does not replace issuer validation. The response must remain bound to the authorization server selected for that transaction."),
        ("A Client Credentials token is issued to an agent workload. Which user should the resource server infer?", ["The most recent interactive user", "The agent's owner", "No user; the client is acting on its own behalf"], 2, "Client Credentials represents machine/client authority. A human subject requires an independently validated delegated flow.")
    ],
    "03-token-exchange-delegation-impersonation": [
        ("What is the difference between delegation and impersonation?", ["Impersonation hides the agent actor, while delegation preserves both subject and actor.", "They are identical.", "Delegation requires a VPN."], 0, "Delegation retains the actor chain for auditing."),
        ("What does token exchange attenuation mean?", ["Increasing the permissions of a token", "Down-scoping a parent grant into a narrower, shorter-lived child token", "Translating the token to XML"], 1, "Attenuation reduces the blast radius of a delegated token."),
        ("Which RFC defines OAuth Token Exchange?", ["RFC 793", "RFC 8693", "RFC 6749"], 1, "RFC 8693 standardizes exchanging one token for another to facilitate delegation.")
    ],
    "04-fine-grained-authorization": [
        ("Why use OpenFGA or Cedar for agents?", ["To write HTML", "To move from static roles to deterministic, resource-level authorization", "To bypass authentication"], 1, "Policy-as-code engines enable fine-grained, verifiable decisions."),
        ("What is Policy-as-Code?", ["Writing passwords in code", "Managing authorization logic externally from application source code as versioned policies", "Compiling policies to machine code"], 1, "Policy-as-Code decouples authorization decisions from business logic."),
        ("Which of the following is a key feature of ABAC (Attribute-Based Access Control)?", ["It relies solely on static roles", "It evaluates dynamic attributes like time, environment, and user state", "It uses only network IPs"], 1, "ABAC uses rich attributes for complex authorization logic.")
    ],
    "05-dynamic-authorization-cae": [
        ("What is Continuous Access Evaluation (CAE)?", ["Checking access only at login", "Re-evaluating permissions if risk or context changes during a session", "A type of firewall"], 1, "CAE allows revoking access mid-session if conditions change."),
        ("How does CAE respond to a critical security event (e.g., account deletion)?", ["It waits for the token to expire", "It immediately triggers re-authorization or revocation of existing sessions", "It emails the administrator"], 1, "CAE relies on real-time event signaling to instantly enforce changes."),
        ("What is the main benefit of CAE for long-running agents?", ["It prevents the agent from timing out", "It ensures the agent's authority can be revoked immediately if a threat is detected", "It speeds up token validation"], 1, "CAE mitigates the risk of long-lived access tokens.")
    ],
    "06-mcp-tool-authorization": [
        ("How does MCP (Model Context Protocol) improve security?", ["By removing all authentication", "By standardizing resource access and tool invocation boundaries", "By encrypting passwords"], 1, "MCP provides a structured boundary for agents to discover and use tools securely."),
        ("In an MCP architecture, where should authorization policies be enforced?", ["Inside the LLM prompt", "At the MCP Server, before executing the tool", "In the browser"], 1, "The MCP server is the PEP (Policy Enforcement Point) protecting the target resources."),
        ("Why shouldn't the LLM client alone enforce tool authorization?", ["Clients are secure", "The client is untrusted and can be bypassed or manipulated via prompt injection", "Clients lack network access"], 1, "Client-side enforcement is inherently insecure.")
    ],
    "07-risk-assurance-stepup": [
        ("When should step-up authorization be triggered?", ["For every request", "When an agent attempts a high-risk action", "Never"], 1, "High-risk actions may require additional human approval or stronger MFA."),
        ("What defines the 'risk' of an action?", ["The number of bytes in the payload", "The potential impact (e.g., financial loss, data deletion) and context", "The time of day"], 1, "Risk reflects business impact and context anomalies."),
        ("What does 'assurance level' mean in the context of identity?", ["The confidence that the entity is who they claim to be", "The speed of the network", "The length of the password"], 0, "Higher assurance levels require stronger authentication methods.")
    ],
    "08-workload-assurance-runtime-attestation": [
        ("What does runtime attestation verify?", ["The user's password", "The cryptographic integrity and identity of the running workload", "The color of the UI"], 1, "Attestation proves the software running is exactly what is expected."),
        ("Why is node attestation important for agent security?", ["It makes servers faster", "It ensures the host running the agent is trustworthy before issuing credentials", "It provides a GUI"], 1, "Node attestation anchors trust to the underlying hardware or platform."),
        ("What role does a TPM (Trusted Platform Module) play in attestation?", ["It acts as a router", "It securely stores cryptographic keys and provides hardware measurements of the system state", "It generates passwords"], 1, "TPMs provide hardware-backed security assertions.")
    ],
    "09-authorization-governance": [
        ("Why is governance important for agent authorization?", ["To ensure permissions are periodically recertified and measurable", "To write more code", "To slow down development"], 0, "Governance prevents standing privilege accumulation over time."),
        ("What is 'Least Privilege at Scale'?", ["Giving everyone admin access", "Automating the enforcement and review of minimal necessary access across a large fleet of agents", "Manually approving every database query"], 1, "Scaling least privilege requires automation and policy lifecycle management."),
        ("What is the purpose of an entitlement review?", ["To increase cloud usage", "To audit and revoke unnecessary permissions granted to human and non-human identities", "To write documentation"], 1, "Reviews ensure access aligns with current business needs.")
    ],
    "10-authorization-observability-audit-analytics": [
        ("What belongs in a good audit event for an agent action?", ["Just the final text", "Requester, actor, workload, resource, and policy version", "The user's secret password"], 1, "Audit events must contain the full delegation chain and context."),
        ("Why should the policy version be included in an audit log?", ["To make the log file larger", "To exactly reproduce the authorization decision at the time it occurred", "Because it is required by HTML"], 1, "Policies change; versioning ensures historical decisions are explainable."),
        ("How do analytics help with agent authorization?", ["By finding syntax errors", "By identifying anomalies, detecting unused permissions, and triggering alerts for risky behavior", "By formatting logs"], 1, "Analytics turn raw audit logs into actionable security insights.")
    ],
    "11-adversarial-authorization-testing": [
        ("What is the goal of adversarial authorization testing?", ["To prove the system resists realistic privilege escalation and bypasses", "To test UI responsiveness", "To check syntax errors"], 0, "Testing proves the boundaries fail closed."),
        ("What is a confused deputy attack?", ["When an agent forgets its password", "When an attacker tricks a privileged agent into misusing its authority on the attacker's behalf", "When two agents talk to each other"], 1, "The agent is 'confused' into using its own authority to serve an unauthorized request."),
        ("Why should cross-tenant boundaries be tested adversarially?", ["To ensure an agent cannot read data from Tenant B while acting for Tenant A", "To improve latency", "To test database indexes"], 0, "Cross-tenant isolation is a critical boundary in SaaS platforms.")
    ],
    "12-integrating-authorization-agents-guardrails": [
        ("Why shouldn't authorization rely on the LLM prompt?", ["Because prompts are fast", "Because prompts are untrusted input and can be bypassed (prompt injection)", "Because LLMs are too expensive"], 1, "Enforcement must happen in trusted application code (PEP/PDP), not the LLM."),
        ("What is an agent guardrail?", ["A physical fence around servers", "A strict, deterministic check (like policy engines or content filters) that cannot be bypassed by the LLM", "A prompt instruction saying 'be safe'"], 1, "Guardrails are implemented in code, outside the model."),
        ("Where should the Policy Enforcement Point (PEP) be located for an agent?", ["Inside the system prompt", "At the tool gateway or resource boundary, intercepting agent actions", "In the user's browser"], 1, "The PEP must intercept and authorize the action before it reaches the resource.")
    ],
    "13-capstone-secure-agent-identity": [
        ("What does a comprehensive secure architecture require?", ["Only a strong password", "Integration of workload identity, delegation, policy engines, and observability", "A single shared agent token"], 1, "Production readiness requires defense in depth."),
        ("What is the primary value of a capstone architecture?", ["It demonstrates how isolated security concepts work together in a realistic enterprise scenario", "It provides a single line of code", "It removes the need for security"], 0, "The capstone unifies the concepts into a cohesive architecture."),
        ("In a production system, what happens immediately after an agent is suspected of compromise?", ["Wait for the next release cycle", "The agent's identity and credentials are automatically revoked or quarantined", "The user is logged out"], 1, "Automated incident response is critical for resilient systems.")
    ],

    # ADVANCED
    "01-advanced-authorization-models": [
        ("What is ReBAC?", ["Role-Based Access Control", "Relationship-Based Access Control", "Random-Based Access Control"], 1, "ReBAC models permissions based on relationships (e.g. owner, team member)."),
        ("How does a hybrid authorization model improve security?", ["By ignoring all rules", "By combining RBAC, ABAC, and ReBAC to handle complex temporal, risk, and relationship contexts", "By relying on simple passwords"], 1, "Hybrid models provide the flexibility needed for dynamic agent operations."),
        ("What is 'temporal context' in authorization?", ["Permissions based on the time of day or a specific time window", "Permissions based on the user's location", "Permissions based on relationships"], 0, "Temporal context restricts access to specific timeframes.")
    ],
    "02-cryptographic-delegation-capabilities": [
        ("What limits delegation laundering in a capability system?", ["Unbounded hops", "Scope intersection and depth limits", "Forwarding bearer tokens"], 1, "Bounded delegation prevents transitive privilege growth."),
        ("What is a capability in this context?", ["The speed of the processor", "An unforgeable token of authority granting specific rights to a resource", "A feature in the UI"], 1, "Capabilities inherently tie the bearer to specific permissions."),
        ("How does cryptographic provenance help with agent actions?", ["It speeds up execution", "It creates a verifiable, tamper-proof chain of exactly who delegated what to whom", "It hides the agent's identity"], 1, "Provenance ensures accountability across delegation chains.")
    ],
    "03-cross-domain-identity-federation": [
        ("What does cross-domain federation solve?", ["Allowing agents to work safely across different organizations and trust boundaries", "Making passwords stronger", "Compiling code faster"], 0, "It maps identities without sharing a single centralized provider."),
        ("What is a common protocol for identity federation?", ["FTP", "SAML or OIDC", "SMTP"], 1, "SAML and OIDC are standard protocols for federated identity."),
        ("Why avoid collapsing all parties into one identity namespace?", ["It creates a single massive point of failure and violates trust boundaries", "It makes routing too easy", "It saves database space"], 0, "Federation maintains independent control over identities in different domains.")
    ],
    "04-agent-attestations-verifiable-credentials": [
        ("What makes Verifiable Credentials (VCs) useful for agents?", ["They allow independently verifiable, cryptographically signed claims about an agent", "They are easy to type", "They replace all other auth"], 0, "VCs provide portable evidence of claims."),
        ("What is the role of an Issuer in a Verifiable Credential system?", ["To consume the credential", "To cryptographically sign and assert claims about the subject", "To host the website"], 1, "Issuers create and sign the credentials."),
        ("Why must verifiable evidence be freshness-aware?", ["To look modern", "To ensure the credential hasn't been revoked since it was issued", "To match the UI theme"], 1, "Freshness prevents the use of stale or revoked credentials.")
    ],
    "05-continuous-adaptive-trust": [
        ("Adaptive trust focuses on:", ["Static one-time checks", "Continuously adjusting trust based on behavior, environment, and risk", "Hardcoded IP allowlists"], 1, "Trust should degrade if anomalies are detected."),
        ("What is a 'control loop' in continuous trust?", ["A `for` loop in Python", "A mechanism that constantly evaluates signals and updates access decisions in real-time", "A network switch"], 1, "Control loops enable dynamic, real-time security postures."),
        ("How should a system respond if an agent exhibits highly anomalous behavior?", ["Send a weekly report", "Automatically quarantine the agent or step-up authentication", "Ignore it if the token is valid"], 1, "Adaptive trust requires automated, proactive mitigation.")
    ],
    "06-decentralized-identity-multi-agent-trust": [
        ("When is Decentralized Identity (DID) most applicable?", ["In a single trusted enterprise", "In multi-agent ecosystems without a single shared identity provider", "For local scripts"], 1, "DIDs enable trust across disparate networks."),
        ("What is a Decentralized Identifier (DID)?", ["A centralized email address", "A globally unique identifier that does not require a centralized registry", "A social media handle"], 1, "DIDs provide cryptographic autonomy."),
        ("Why use DIDs for multi-agent systems?", ["To allow agents from different vendors to establish trust independently", "To bypass cryptography", "To store big data"], 0, "DIDs facilitate interoperability without a central authority.")
    ],
    "07-non-human-identity-security-key-management": [
        ("Why is key rotation critical for non-human identities?", ["To change file names", "To limit the window of compromise if a credential leaks", "To save disk space"], 1, "Rotation bounds the usefulness of stolen keys."),
        ("What is secretless federation?", ["Using empty passwords", "Authenticating via workload identity and short-lived tokens instead of storing static secrets", "Deleting all keys"], 1, "Secretless federation eliminates the risk of hardcoded, long-lived secrets."),
        ("Why should machine credentials be heavily monitored?", ["To measure network speed", "To detect exfiltration or misuse of non-human accounts quickly", "To bill the user"], 1, "Non-human identities are prime targets for lateral movement.")
    ],
    "08-agent-identity-lifecycle-governance": [
        ("What is a key aspect of operational excellence for agent identity?", ["Manual ssh access", "Automated provisioning, continuous monitoring, and auditable retirement", "Using root for everything"], 1, "Automation ensures consistency and security at scale."),
        ("Why is 'risk-tiering' important for agent governance?", ["To charge more money", "To apply stricter controls and reviews to agents with higher risk profiles", "To sort them alphabetically"], 1, "High-risk agents require more rigorous governance than low-risk ones."),
        ("What does 'auditable retirement' mean?", ["Deleting the logs", "Ensuring the agent is securely decommissioned and a permanent record of its lifecycle is retained", "Retiring the server hardware"], 1, "Retirement must leave an audit trail for compliance.")
    ],
    "09-agent-identity-security-posture-threat-defense": [
        ("What does Security Posture Management do?", ["Detects misconfigurations and excessive permissions proactively", "Writes the code", "Designs the UI"], 0, "It hardens the environment before an attack happens."),
        ("What is threat defense in the context of agent identity?", ["Ignoring threats", "Actively identifying and neutralizing malicious activity targeting agent identities", "Writing unit tests"], 1, "Threat defense focuses on active response to attacks."),
        ("How does posture management differ from incident response?", ["They are the same", "Posture management is proactive hardening; incident response is reactive mitigation", "Posture management is only for networks"], 1, "Posture is about prevention; response is about containment.")
    ],
    "10-identity-observability-telemetry-forensics": [
        ("Why use trace IDs across agent hops?", ["To make logs longer", "To reconstruct the full context of a multi-agent transaction for forensics", "To encrypt data"], 1, "Trace IDs correlate events across distributed systems."),
        ("What is telemetry in identity observability?", ["Telescopes", "Continuous emission of structured data regarding identity and authorization events", "Video surveillance"], 1, "Telemetry provides the raw data needed for observability."),
        ("Why is privacy-aware observability important?", ["To sell user data", "To ensure sensitive information (like PII or secrets) is not exposed in logs", "To compress logs"], 1, "Logging secrets creates massive security vulnerabilities.")
    ],
    "11-compliance-audit-forensic-readiness": [
        ("What makes a system forensically ready?", ["Having no logs", "Logging immutable, tamper-evident records of identity decisions", "Only logging errors"], 1, "Evidence must be trustworthy to an external auditor."),
        ("Why must audit logs be tamper-evident?", ["To prevent attackers from erasing their tracks", "To compress the files", "To make them easier to read"], 0, "Tamper-evident logs ensure the integrity of the forensic evidence."),
        ("How does a compliance framework impact agent identity?", ["It has no impact", "It mandates specific controls for access, logging, and data handling", "It requires the use of certain programming languages"], 1, "Compliance dictates rigorous security and auditing standards.")
    ],
    "12-secure-compliant-resilient-agent-identity-platform": [
        ("What defines a resilient enterprise agent identity platform?", ["No single point of failure, rapid revocation, and defense in depth", "A single giant database", "Ignoring security for speed"], 0, "Resilience ensures the system survives compromise attempts safely."),
        ("Why is defense in depth necessary for agent platforms?", ["To use more servers", "Because no single security control is perfect, and layers of defense mitigate failures", "To slow down the agent"], 1, "Layered security provides robust protection."),
        ("What is the ultimate goal of a secure agent identity architecture?", ["To prevent agents from doing any work", "To enable agents to operate autonomously while cryptographically enforcing trust, security, and accountability", "To replace human workers completely"], 1, "Security must enable safe, accountable autonomous action.")
    ]
}

def get_questions_for_module(module_name):
    # Returns a list of question tuples. If not found, provides a fallback.
    return QUESTIONS_DB.get(module_name, [
        (f"What is the main topic of {module_name}?", ["The concepts taught in this module.", "An unrelated topic.", "Nothing."], 0, "Refer to the module README."),
        (f"What is a key consideration in {module_name}?", ["Security and identity best practices", "Ignoring security", "Using default passwords"], 0, "Security is fundamental.")
    ])
