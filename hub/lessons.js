const REPO = 'https://github.com/mahsa-teimourikia/agent-identity';
const LESSONS = [
  {
    "id": "beginner/01-agent-identity-foundations",
    "module": "01-agent-identity-foundations",
    "level": "beginner",
    "step": 1,
    "levelStep": 1,
    "title": "Agent Identity Foundations",
    "summary": "explain, implement, evaluate, and productionize the identity boundary that keeps a human requester, logical agent, runtime workload, delegated authority, and protected resource distinct",
    "detail": "explain, implement, evaluate, and productionize the identity boundary that keeps a human requester, logical agent, runtime workload, delegated authority, and protected resource distinct",
    "outcomes": [
      "distinguish identity, authentication, authorization, delegation, approval, and accountability",
      "model human, logical-agent, workload, service/tool, and resource principals",
      "preserve requester, actor, workload, tenant, audience, task, and authority as separate facts",
      "identify trust boundaries and name the trust anchor at every crossing",
      "implement an evidence-bound policy-enforcement point outside the model",
      "compare a caller-declared baseline with a controlled design using labelled adversarial cases"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/01-agent-identity-foundations/README.md",
    "references": [
      {
        "label": "Software and AI Agent Identity and Authorization concept paper",
        "url": "https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf"
      },
      {
        "label": "AI Agent Standards Initiative",
        "url": "https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure"
      },
      {
        "label": "Zero Trust Architecture",
        "url": "https://csrc.nist.gov/pubs/sp/800/207/final"
      },
      {
        "label": "OAuth 2.0 Token Exchange, RFC 8693",
        "url": "https://www.rfc-editor.org/rfc/rfc8693.html"
      },
      {
        "label": "OAuth 2.0 Security Best Current Practice, RFC 9700",
        "url": "https://www.rfc-editor.org/rfc/rfc9700.html"
      }
    ],
    "checkpoint": {
      "id": "beginner/01-agent-identity-foundations/q-1",
      "text": "A schema-valid purchase request claims to be from the procurement agent, but verified workload evidence identifies an unapproved development runtime. What should the purchasing API do?",
      "options": [
        "Deny it because the verified workload is not bound to that production agent",
        "Ask the language model whether the request looks safe",
        "Allow it because the declared agent name is correct"
      ],
      "answer": 0,
      "explanation": "The enforcement point must bind verified workload evidence to the governed logical agent and fail closed on a mismatch."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/01-agent-identity-foundations/lab.py",
    "run": "python3 curriculum/beginner/01-agent-identity-foundations/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/01-agent-identity-foundations/agent_identity_foundations.ipynb"
  },
  {
    "id": "beginner/02-humans-workloads-agents",
    "module": "02-humans-workloads-agents",
    "level": "beginner",
    "step": 2,
    "levelStep": 2,
    "title": "Humans, Workloads and Agents",
    "summary": "learn to model the different identities participating in an agentic system instead of collapsing a user, application, logical agent, runtime workload, tool, and resource into one security principal",
    "detail": "learn to model the different identities participating in an agentic system instead of collapsing a user, application, logical agent, runtime workload, tool, and resource into one security principal",
    "outcomes": [
      "distinguish human, application, agent, workload, service/tool, and resource identities",
      "explain logical identity versus runtime identity",
      "model ownership and delegation separately",
      "distinguish an OAuth client from the human using it",
      "distinguish a service account from the software using it",
      "understand workload identity and attestation at a conceptual level"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/02-humans-workloads-agents/README.md",
    "references": [
      {
        "label": "Software and AI Agent Identity and Authorization concept paper",
        "url": "https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf"
      },
      {
        "label": "Zero Trust Architecture",
        "url": "https://csrc.nist.gov/pubs/sp/800/207/final"
      },
      {
        "label": "SPIFFE standard",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/"
      },
      {
        "label": "SPIFFE ID",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/"
      },
      {
        "label": "Workload API",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/"
      }
    ],
    "checkpoint": {
      "id": "beginner/02-humans-workloads-agents/q-1",
      "text": "The booking API authenticates the corporate research workload, but the request envelope claims the booking-specialist agent and names a valid employee. What should it do?",
      "options": [
        "Deny because the workload is not the approved deployment for the claimed agent and application",
        "Allow because the employee is valid",
        "Allow because both workloads use the corporate trust domain"
      ],
      "answer": 0,
      "explanation": "A corporate workload credential does not prove a different logical agent, application binding, or delegation path."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/02-humans-workloads-agents/lab.py",
    "run": "python3 curriculum/beginner/02-humans-workloads-agents/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/02-humans-workloads-agents/humans_workloads_agents.ipynb"
  },
  {
    "id": "beginner/03-authentication-credentials-tokens",
    "module": "03-authentication-credentials-tokens",
    "level": "beginner",
    "step": 3,
    "levelStep": 3,
    "title": "Authentication, Credentials and Tokens",
    "summary": "understand how humans, agents, workloads, and services prove identity, how credentials differ, and how to validate tokens safely before moving into OAuth/OIDC and production workload identity",
    "detail": "understand how humans, agents, workloads, and services prove identity, how credentials differ, and how to validate tokens safely before moving into OAuth/OIDC and production workload identity",
    "outcomes": [
      "distinguish identifiers, secrets, keys, credentials, certificates, and tokens",
      "explain shared-secret versus asymmetric authentication",
      "explain bearer versus sender-constrained credentials",
      "understand JWT, JWS, JWK, and JWKS roles",
      "create and verify signed JWTs",
      "validate issuer, audience, expiry, not-before, token type, and algorithm"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/03-authentication-credentials-tokens/README.md",
    "references": [
      {
        "label": "JSON Web Token, RFC 7519",
        "url": "https://www.rfc-editor.org/rfc/rfc7519.html"
      },
      {
        "label": "JSON Web Signature, RFC 7515",
        "url": "https://www.rfc-editor.org/rfc/rfc7515.html"
      },
      {
        "label": "JSON Web Key, RFC 7517",
        "url": "https://www.rfc-editor.org/rfc/rfc7517.html"
      },
      {
        "label": "JSON Web Token Best Current Practices, RFC 8725",
        "url": "https://www.rfc-editor.org/rfc/rfc8725.html"
      },
      {
        "label": "OAuth 2.0 Bearer Token Usage, RFC 6750",
        "url": "https://www.rfc-editor.org/rfc/rfc6750.html"
      }
    ],
    "checkpoint": {
      "id": "beginner/03-authentication-credentials-tokens/q-1",
      "text": "A signed token contains an unknown kid and a jku URL controlled by the caller. What should the purchasing API do?",
      "options": [
        "Deny because key discovery must be configured for a trusted issuer, not redirected by token headers",
        "Fetch the URL to discover the verification key",
        "Decode the claims and accept if the issuer string looks familiar"
      ],
      "answer": 0,
      "explanation": "A key ID selects among issuer-bound trusted keys; received jku or x5u values must not create a trust anchor or SSRF path."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/03-authentication-credentials-tokens/lab.py",
    "run": "python3 curriculum/beginner/03-authentication-credentials-tokens/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/03-authentication-credentials-tokens/authentication_credentials_tokens.ipynb"
  },
  {
    "id": "beginner/04-authorization-for-agents",
    "module": "04-authorization-for-agents",
    "level": "beginner",
    "step": 4,
    "levelStep": 4,
    "title": "Authorization for Agents",
    "summary": "Build and evaluate a default-deny authorization boundary that binds verified identity, task delegation, resource state, amount limits, and exact approval evidence before an agent action executes",
    "detail": "Build and evaluate a default-deny authorization boundary that binds verified identity, task delegation, resource state, amount limits, and exact approval evidence before an agent action executes",
    "outcomes": [
      "distinguish authentication, authorization, delegation, consent, and approval",
      "model a decision as principal/requester, actor, workload, action, resource, context, and policy",
      "explain when RBAC, ABAC, ReBAC, capabilities, or a composition is appropriate",
      "place a Policy Enforcement Point (PEP) and Policy Decision Point (PDP) outside the model",
      "enforce default deny, tenant isolation, resource lifecycle, task scope, amount bounds, and fail-closed behavior",
      "issue narrower child authority without privilege amplification"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/04-authorization-for-agents/README.md",
    "references": [
      {
        "label": "Guide to Attribute Based Access Control (ABAC), SP 800-162",
        "url": "https://csrc.nist.gov/pubs/sp/800/162/upd2/final"
      },
      {
        "label": "Role Based Access Control project",
        "url": "https://csrc.nist.gov/projects/role-based-access-control"
      },
      {
        "label": "Zanzibar: Google's Consistent, Global Authorization System",
        "url": "https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/"
      },
      {
        "label": "Authorization API 1.0",
        "url": "https://openid.net/specs/authorization-api-1_0.html"
      },
      {
        "label": "specification status and emerging profiles",
        "url": "https://openid.net/wg/authzen/specifications/"
      }
    ],
    "checkpoint": {
      "id": "beginner/04-authorization-for-agents/q-1",
      "text": "A refund agent has the broad `refund_agent` role and proposes a refund for another tenant's order. What should the tool gateway do?",
      "options": [
        "Deny because role eligibility does not satisfy tenant, resource, task, and delegation constraints",
        "Execute because the role permits refunds",
        "Ask the model whether the tenant mismatch is intentional"
      ],
      "answer": 0,
      "explanation": "The PEP must enforce a resource-level, default-deny decision using trusted tenant and delegation data; a broad role alone is insufficient."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/04-authorization-for-agents/lab.py",
    "run": "python3 curriculum/beginner/04-authorization-for-agents/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/04-authorization-for-agents/authorization_for_agents.ipynb"
  },
  {
    "id": "beginner/05-least-privilege-tool-access",
    "module": "05-least-privilege-tool-access",
    "level": "beginner",
    "step": 5,
    "levelStep": 5,
    "title": "Least-Privilege Tool Access for Agents",
    "summary": "Build and evaluate a least-privilege tool gateway that gives an agent only the capabilities required for one task and prevents model output from becoming authority",
    "detail": "Build and evaluate a least-privilege tool gateway that gives an agent only the capabilities required for one task and prevents model output from becoming authority",
    "outcomes": [
      "explain why tool discovery and tool execution are separate authorization boundaries",
      "design narrow business capabilities instead of generic shell, SQL, or HTTP primitives",
      "derive requester, actor, workload, and tenant from authenticated application state",
      "define strict input and output contracts with Pydantic and JSON Schema",
      "enforce task, resource, argument, amount, recipient, egress, and lifecycle constraints",
      "bind high-risk approval to one exact operation and consume it safely"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/05-least-privilege-tool-access/README.md",
    "references": [
      {
        "label": "2026-07-28 tools specification",
        "url": "https://modelcontextprotocol.io/specification/2026-07-28/server/tools"
      },
      {
        "label": "2026-07-28 authorization specification",
        "url": "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization"
      },
      {
        "label": "security best practices",
        "url": "https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices"
      },
      {
        "label": "2026-07-28 specification release notes",
        "url": "https://blog.modelcontextprotocol.io/posts/2026-07-28/"
      },
      {
        "label": "official Python SDK",
        "url": "https://github.com/modelcontextprotocol/python-sdk"
      }
    ],
    "checkpoint": {
      "id": "beginner/05-least-privilege-tool-access/q-1",
      "text": "An MCP server marks a tool as read-only, but the server is not trusted and the tool accepts an arbitrary URL. What should the client gateway do?",
      "options": [
        "Grant automatic access because the annotation says read-only",
        "Treat the annotation as a hint and independently enforce authorization, strict arguments, and egress policy",
        "Ask the language model whether the URL looks safe"
      ],
      "answer": 1,
      "explanation": "MCP annotations are not enforcement guarantees; the trusted gateway must validate and authorize the call and network destination."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/05-least-privilege-tool-access/lab.py",
    "run": "python3 curriculum/beginner/05-least-privilege-tool-access/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/05-least-privilege-tool-access/least_privilege_tool_access.ipynb"
  },
  {
    "id": "beginner/06-agent-identity-lifecycle",
    "module": "06-agent-identity-lifecycle",
    "level": "beginner",
    "step": 6,
    "levelStep": 6,
    "title": "Agent Identity Lifecycle",
    "summary": "design, implement, attack-test, evaluate, and productionize a governed agent-identity lifecycle in which registration, ownership, provisioning, runtime binding, review, suspension, revocation, and retirement are deterministic, authorized, and auditable",
    "detail": "design, implement, attack-test, evaluate, and productionize a governed agent-identity lifecycle in which registration, ownership, provisioning, runtime binding, review, suspension, revocation, and retirement are deterministic, authorized, and auditable",
    "outcomes": [
      "distinguish logical-agent, deployment/workload, credential, access, and session lifecycles",
      "model legal lifecycle states and fail-closed transitions",
      "register an agent against an approved blueprint and accountable humans",
      "bind provisioning to an approved manifest and attested workload",
      "enforce activation invariants, review deadlines, and separation of duties",
      "process material changes without silently inheriting old approval"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/06-agent-identity-lifecycle/README.md",
    "references": [
      {
        "label": "Accelerating the Adoption of Software and Artificial Intelligence Agent Identity and Authorization — Initial Public Draft",
        "url": "https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd"
      },
      {
        "label": "Software and AI Agent Identity and Authorization project status",
        "url": "https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization"
      },
      {
        "label": "Microsoft Entra Agent ID documentation",
        "url": "https://learn.microsoft.com/en-us/entra/agent-id/"
      },
      {
        "label": "Agent identity blueprints",
        "url": "https://learn.microsoft.com/en-us/entra/agent-id/agent-blueprint"
      },
      {
        "label": "Administrative relationships: owners, sponsors, and managers",
        "url": "https://learn.microsoft.com/en-us/entra/agent-id/agent-owners-sponsors-managers"
      }
    ],
    "checkpoint": {
      "id": "beginner/06-agent-identity-lifecycle/q-1",
      "text": "A provisioning workflow requests one capability that is absent from the independently approved agent manifest. What should the lifecycle controller do?",
      "options": [
        "Provision it because the workflow has the provisioner role",
        "Deny it because provisioning must not widen the approved manifest and blueprint",
        "Ask the model whether the new capability is useful"
      ],
      "answer": 1,
      "explanation": "A provisioner may materialize approved intent but cannot expand it. The controller must bind exact manifest capabilities to the approved blueprint."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/06-agent-identity-lifecycle/lab.py",
    "run": "python3 curriculum/beginner/06-agent-identity-lifecycle/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/beginner/06-agent-identity-lifecycle/agent_identity_lifecycle.ipynb"
  },
  {
    "id": "intermediate/01-workload-identity-spiffe-spire",
    "module": "01-workload-identity-spiffe-spire",
    "level": "intermediate",
    "step": 7,
    "levelStep": 1,
    "title": "Workload Identity with SPIFFE and SPIRE",
    "summary": "Design, implement, attack-test, and productionize workload identity for an AI-agent runtime using attestation, short-lived SVIDs, exact peer verification, lifecycle-aware authorization, rotation, and federation—without shipping a long-lived workload secret",
    "detail": "Design, implement, attack-test, and productionize workload identity for an AI-agent runtime using attestation, short-lived SVIDs, exact peer verification, lifecycle-aware authorization, rotation, and federation—without shipping a long-lived workload secret",
    "outcomes": [
      "distinguish human, logical-agent, workload, node, service, and resource identities",
      "explain how a trust domain, SPIFFE ID, SVID, bundle, Workload API, node attestation, and workload attestation fit together",
      "design registration entries whose selectors map one observed runtime to exactly one identity",
      "validate X.509-SVID chain, time, profile, URI SAN, trust domain, exact peer, and lifecycle",
      "validate JWT-SVID key, algorithm, subject, audience, time, lifetime, exact peer, and lifecycle",
      "consume full-state Workload API updates correctly, including rotation and redaction"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/01-workload-identity-spiffe-spire/README.md",
    "references": [
      {
        "label": "SPIFFE overview",
        "url": "https://spiffe.io/docs/latest/spiffe-about/overview/"
      },
      {
        "label": "SPIRE concepts",
        "url": "https://spiffe.io/docs/latest/spire-about/spire-concepts/"
      },
      {
        "label": "Workload API specification",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/"
      },
      {
        "label": "SPIFFE ID specification",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/"
      },
      {
        "label": "SPIFFE specifications index",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/"
      }
    ],
    "checkpoint": {
      "id": "intermediate/01-workload-identity-spiffe-spire/q-1",
      "text": "A pod's attested selectors match two active SPIRE registration entries with different SPIFFE IDs. What should issuance do?",
      "options": [
        "Choose the entry with the longest path",
        "Issue both identities so the pod can choose",
        "Deny issuance and repair the registration collision"
      ],
      "answer": 2,
      "explanation": "Multiple matches make the observed runtime-to-identity mapping ambiguous. The control plane must fail closed and repair the selector policy."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/01-workload-identity-spiffe-spire/lab.py",
    "run": "python3 curriculum/intermediate/01-workload-identity-spiffe-spire/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/01-workload-identity-spiffe-spire/workload_identity_spiffe_spire.ipynb"
  },
  {
    "id": "intermediate/02-oauth-oidc-for-agents",
    "module": "02-oauth-oidc-for-agents",
    "level": "intermediate",
    "step": 8,
    "levelStep": 2,
    "title": "OAuth and OpenID Connect for Agents",
    "summary": "implement, attack-test, and productionize OAuth/OIDC for an agent that acts as a workload or for a user, while preserving subject, agent, client, workload, audience, task, and resource boundaries",
    "detail": "implement, attack-test, and productionize OAuth/OIDC for an agent that acts as a workload or for a user, while preserving subject, agent, client, workload, audience, task, and resource boundaries",
    "outcomes": [
      "distinguish OAuth authorization, OIDC authentication, workload authentication, and resource authorization",
      "model resource owner, client, authorization server, OpenID Provider, and resource server roles",
      "keep the user subject, logical agent, OAuth client, and runtime workload distinct",
      "implement Authorization Code with PKCE, exact redirect/state/issuer validation, one-time code use, and OIDC nonce validation",
      "explain Client Credentials without inventing a human subject",
      "issue audience/resource-restricted, short-lived JWT access tokens using the RFC 9068 profile"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/02-oauth-oidc-for-agents/README.md",
    "references": [
      {
        "label": "OAuth 2.0",
        "url": "https://www.rfc-editor.org/rfc/rfc6749.html"
      },
      {
        "label": "OpenID Connect Core",
        "url": "https://openid.net/specs/openid-connect-core-1_0.html"
      },
      {
        "label": "OAuth Security Best Current Practice",
        "url": "https://www.rfc-editor.org/rfc/rfc9700.html"
      },
      {
        "label": "JWT Profile for OAuth access tokens",
        "url": "https://www.rfc-editor.org/rfc/rfc9068.html"
      },
      {
        "label": "RFC 9207",
        "url": "https://www.rfc-editor.org/rfc/rfc9207.html"
      }
    ],
    "checkpoint": {
      "id": "intermediate/02-oauth-oidc-for-agents/q-1",
      "text": "A travel agent has a correctly signed access token for the travel API and tries to use it at the payment API. What should the payment API do?",
      "options": [
        "Deny it because the token is not audience/resource-bound to the payment API",
        "Ask the model whether payment is part of the trip",
        "Accept it because the issuer and signature are valid"
      ],
      "answer": 0,
      "explanation": "Signature validity does not override audience. Every resource server must accept only tokens issued for its own canonical resource."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/02-oauth-oidc-for-agents/lab.py",
    "run": "python3 curriculum/intermediate/02-oauth-oidc-for-agents/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/02-oauth-oidc-for-agents/oauth_oidc_for_agents.ipynb"
  },
  {
    "id": "intermediate/03-token-exchange-delegation-impersonation",
    "module": "03-token-exchange-delegation-impersonation",
    "level": "intermediate",
    "step": 9,
    "levelStep": 3,
    "title": "Token Exchange, Delegation, and Impersonation",
    "summary": "implement, attack-test, and productionize an OAuth 2.0 Token Exchange broker that preserves subject and actor accountability while every derived credential becomes narrower, shorter-lived, lifecycle-aware, and bound to its presenter",
    "detail": "implement, attack-test, and productionize an OAuth 2.0 Token Exchange broker that preserves subject and actor accountability while every derived credential becomes narrower, shorter-lived, lifecycle-aware, and bound to its presenter",
    "outcomes": [
      "construct and validate the RFC 8693 token request and response contract",
      "distinguish the OAuth client, authenticated workload, subject, current actor, prior actors, and resource server",
      "model delegation and impersonation without confusing either with authentication",
      "validate input credential type, profile, issuer, audience, key, time, client, workload, and lifecycle",
      "derive nested issuer-qualified act claims without changing the underlying subject",
      "enforce monotonic attenuation across scope, audience, resource, action, amount, purpose, lifetime, depth, redelegation, and sender key"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/03-token-exchange-delegation-impersonation/README.md",
    "references": [
      {
        "label": "RFC 8693",
        "url": "https://www.rfc-editor.org/rfc/rfc8693.html"
      },
      {
        "label": "DPoP",
        "url": "https://www.rfc-editor.org/rfc/rfc9449.html"
      },
      {
        "label": "OAuth mTLS",
        "url": "https://www.rfc-editor.org/rfc/rfc8705.html"
      },
      {
        "label": "RFC 9700",
        "url": "https://www.rfc-editor.org/rfc/rfc9700.html"
      },
      {
        "label": "RFC 9068",
        "url": "https://www.rfc-editor.org/rfc/rfc9068.html"
      }
    ],
    "checkpoint": {
      "id": "intermediate/03-token-exchange-delegation-impersonation/q-1",
      "text": "A child token contains Alice as sub and an outer act for the Flight Specialist with a nested Travel Supervisor. Which actor may drive current actor-based authorization?",
      "options": [
        "Both actors receive the union of their permissions",
        "The Flight Specialist, because the outermost act is current",
        "The Travel Supervisor, because it appeared first in time"
      ],
      "answer": 1,
      "explanation": "RFC 8693 makes the outermost act the current actor. Nested actors are history and must not resurrect prior privilege."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/03-token-exchange-delegation-impersonation/lab.py",
    "run": "python3 curriculum/intermediate/03-token-exchange-delegation-impersonation/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/03-token-exchange-delegation-impersonation/token_exchange_delegation.ipynb"
  },
  {
    "id": "intermediate/04-fine-grained-authorization",
    "module": "04-fine-grained-authorization",
    "level": "intermediate",
    "step": 10,
    "levelStep": 4,
    "title": "Fine-Grained Authorization for AI Agents",
    "summary": "Derive trusted authorization facts, compose attribute and relationship policy, enforce obligations, and detect semantic drift before an agent action reaches a business effect",
    "detail": "Derive trusted authorization facts, compose attribute and relationship policy, enforce obligations, and detect semantic drift before an agent action reaches a business effect",
    "outcomes": [
      "separate authentication, delegation, policy decision, policy enforcement, and side effects",
      "derive subject, agent, workload, tenant, task, and resource facts from trusted systems rather than model arguments",
      "model RBAC, ABAC, ReBAC, and policy-as-code as complementary tools",
      "express the same core invariants in a reference evaluator, OPA/Rego, Cedar, and OpenFGA",
      "use AuthZEN's subject-action-resource-context (SARC) request shape at the PEP/PDP boundary",
      "bind approvals to an exact proposal and enforce every returned obligation"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/04-fine-grained-authorization/README.md",
    "references": [
      {
        "label": "OpenID AuthZEN specifications",
        "url": "https://openid.net/wg/authzen/specifications/"
      },
      {
        "label": "AuthZEN Authorization API 1.0",
        "url": "https://openid.net/specs/authorization-api-1_0.html"
      },
      {
        "label": "NIST SP 800-162: Guide to Attribute Based Access Control",
        "url": "https://csrc.nist.gov/pubs/sp/800/162/upd2/final"
      },
      {
        "label": "NIST SP 800-207: Zero Trust Architecture",
        "url": "https://csrc.nist.gov/pubs/sp/800/207/final"
      },
      {
        "label": "OPA policy language",
        "url": "https://www.openpolicyagent.org/docs/policy-language"
      }
    ],
    "checkpoint": {
      "id": "intermediate/04-fine-grained-authorization/q-1",
      "text": "An OpenFGA check confirms the claims agent is assigned and delegated to a task linked to the claim. May the PEP create a payment?",
      "options": [
        "Yes, if the model says the payment is urgent",
        "Yes; the relationship allow is sufficient",
        "Only after the attribute policy also validates workload, tenant, state, risk, amount, exact approval, and obligations"
      ],
      "answer": 2,
      "explanation": "Relationship authority is one required plane. The PEP must also enforce trusted contextual policy and every mandatory obligation before the effect."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/04-fine-grained-authorization/lab.py",
    "run": "python3 curriculum/intermediate/04-fine-grained-authorization/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/04-fine-grained-authorization/fine_grained_authorization.ipynb"
  },
  {
    "id": "intermediate/05-dynamic-authorization-cae",
    "module": "05-dynamic-authorization-cae",
    "level": "intermediate",
    "step": 11,
    "levelStep": 5,
    "title": "Dynamic Authorization & Continuous Access Evaluation",
    "summary": "build and test a continuous-authorization control loop for a long-running agent: validate standards-conformant security event tokens, durably project subject-scoped state, bound stale authority with decision leases, re-authorize at every side effect, and prove behavior under duplicates, gaps, reordering, outages, and revocation races",
    "detail": "build and test a continuous-authorization control loop for a long-running agent: validate standards-conformant security event tokens, durably project subject-scoped state, bound stale authority with decision leases, re-authorize at every side effect, and prove behavior under duplicates, gaps, reordering, outages, and revocation races",
    "outcomes": [
      "distinguish credential validity, relationship authority, and current contextual authorization",
      "explain SSF, CAEP, Security Event Tokens (SETs), and push/poll delivery roles",
      "validate a signed SET's algorithm, key, issuer, audience, media type, required claims, subject identifier, event type, and freshness",
      "persist an authenticated event before acknowledging it and process it asynchronously and idempotently",
      "scope events to the correct subject and order independent signal domains without dropping late revocations",
      "define safe cache keys and short decision leases that bind exact proposals and trusted state versions"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/05-dynamic-authorization-cae/README.md",
    "references": [
      {
        "label": "OpenID Shared Signals Framework 1.0 Final",
        "url": "https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html"
      },
      {
        "label": "OpenID Continuous Access Evaluation Profile 1.0 Final",
        "url": "https://openid.net/specs/openid-caep-1_0-final.html"
      },
      {
        "label": "OpenID CAEP Interoperability Profile 1.0 — draft",
        "url": "https://openid.net/specs/openid-caep-interoperability-profile-1_0.html"
      },
      {
        "label": "OpenID announcement: SSF, CAEP, and RISC Final Specifications",
        "url": "https://openid.net/three-shared-signals-final-specifications-approved/"
      },
      {
        "label": "RFC 8417 — Security Event Token",
        "url": "https://www.rfc-editor.org/rfc/rfc8417"
      }
    ],
    "checkpoint": {
      "id": "intermediate/05-dynamic-authorization-cae/q-1",
      "text": "A receiver authenticates a valid SSF SET and is about to return HTTP 202. What must happen first?",
      "options": [
        "The receiver must replace sub_id with sub",
        "The business side effect must finish",
        "The SET must be durably persisted for idempotent asynchronous processing"
      ],
      "answer": 2,
      "explanation": "Push delivery acknowledgement follows validation and durable acceptance; business projection may happen asynchronously and duplicate jti values must remain idempotent."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/05-dynamic-authorization-cae/lab.py",
    "run": "python3 curriculum/intermediate/05-dynamic-authorization-cae/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/05-dynamic-authorization-cae/dynamic_authorization.ipynb"
  },
  {
    "id": "intermediate/06-mcp-tool-authorization",
    "module": "06-mcp-tool-authorization",
    "level": "intermediate",
    "step": 12,
    "levelStep": 6,
    "title": "Authorization for MCP and Tool Servers",
    "summary": "build and attack-test an HTTP MCP protected resource that authenticates an audience-bound access token, preserves human, agent, client, workload, and task identities, independently authorizes tool discovery, invocation, exact arguments, target resources, approvals, and downstream delegation, and executes consequential effects exactly once under current policy",
    "detail": "build and attack-test an HTTP MCP protected resource that authenticates an audience-bound access token, preserves human, agent, client, workload, and task identities, independently authorizes tool discovery, invocation, exact arguments, target resources, approvals, and downstream delegation, and executes consequential effects exactly once under current policy",
    "outcomes": [
      "separate the MCP client, protected resource, authorization server, tool, target resource, and downstream API",
      "explain why MCP authorization applies to HTTP transport and why stdio has a different credential boundary",
      "publish OAuth Protected Resource Metadata and return useful WWW-Authenticate challenges",
      "validate token signature, profile, issuer, audience/resource, time bounds, client, scopes, and identity bindings",
      "keep requester, subject, logical agent, OAuth client, workload, task, and downstream actor identities distinct",
      "authorize discovery, invocation, strict arguments, target objects, and effects as separate decisions"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/06-mcp-tool-authorization/README.md",
    "references": [
      {
        "label": "MCP Authorization specification, 2026-07-28",
        "url": "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization"
      },
      {
        "label": "MCP Security Best Practices, 2026-07-28",
        "url": "https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices"
      },
      {
        "label": "MCP Tools specification, 2026-07-28",
        "url": "https://modelcontextprotocol.io/specification/2026-07-28/server/tools"
      },
      {
        "label": "MCP 2026-07-28 release overview",
        "url": "https://blog.modelcontextprotocol.io/posts/2026-07-28/"
      },
      {
        "label": "Official MCP Python SDK authorization guide",
        "url": "https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/run/authorization.md"
      }
    ],
    "checkpoint": {
      "id": "intermediate/06-mcp-tool-authorization/q-1",
      "text": "A payment tool was visible in a cached tools/list response, but the task was revoked before tools/call. What should the MCP server do?",
      "options": [
        "Execute because discovery already granted access",
        "Deny by re-authorizing the invocation and current state",
        "Ask the model whether the revocation is relevant"
      ],
      "answer": 1,
      "explanation": "Discovery is an information boundary, not a durable grant. Every invocation and consequential commit must be authorized against current state."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/06-mcp-tool-authorization/lab.py",
    "run": "python3 curriculum/intermediate/06-mcp-tool-authorization/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/06-mcp-tool-authorization/mcp_authorization.ipynb"
  },
  {
    "id": "intermediate/07-risk-assurance-stepup",
    "module": "07-risk-assurance-stepup",
    "level": "intermediate",
    "step": 13,
    "levelStep": 7,
    "title": "Risk, Assurance, and Step-Up Authorization for Agents",
    "summary": "make agent authority proportional to the risk of an exact transaction and the current, independently verified strength of human, workload, task, resource, and approval evidence—without allowing step-up to repair an ineligible action",
    "detail": "make agent authority proportional to the risk of an exact transaction and the current, independently verified strength of human, workload, task, resource, and approval evidence—without allowing step-up to repair an ineligible action",
    "outcomes": [
      "distinguish identity proofing, authentication, federation, workload, task, approval, and transaction assurance",
      "describe NIST IAL, AAL, and FAL without turning them into a generic trust score",
      "map only explicitly trusted acr values to local assurance properties",
      "evaluate authtime independently of token issuance and expiry",
      "emit and consume a correct RFC 9470 WWW-Authenticate challenge",
      "separate user step-up, missing OAuth scope, workload re-attestation, and business approval"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/07-risk-assurance-stepup/README.md",
    "references": [
      {
        "label": "NIST SP 800-63-4 — Digital Identity Guidelines",
        "url": "https://pages.nist.gov/800-63-4/sp800-63.html"
      },
      {
        "label": "NIST SP 800-63A-4 — Identity Proofing and Enrollment",
        "url": "https://pages.nist.gov/800-63-4/sp800-63a.html"
      },
      {
        "label": "NIST SP 800-63B-4 — Authentication and Authenticator Management",
        "url": "https://pages.nist.gov/800-63-4/sp800-63b.html"
      },
      {
        "label": "NIST SP 800-63C-4 — Federation and Assertions",
        "url": "https://pages.nist.gov/800-63-4/sp800-63c.html"
      },
      {
        "label": "RFC 9470 — OAuth 2.0 Step Up Authentication Challenge Protocol",
        "url": "https://www.rfc-editor.org/rfc/rfc9470"
      }
    ],
    "checkpoint": {
      "id": "intermediate/07-risk-assurance-stepup/q-1",
      "text": "An agent requests the wrong tenant's payment resource and its user authentication is stale. What should happen first?",
      "options": [
        "Deny because resource eligibility failed; stronger authentication cannot make the target permissible",
        "Ask for a broader OAuth scope",
        "Offer user step-up so the stale authentication can be repaired"
      ],
      "answer": 0,
      "explanation": "Eligibility precedes remediation. Tenant or resource-boundary failures are hard denials, not reasons to solicit more assurance or privilege."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/07-risk-assurance-stepup/lab.py",
    "run": "python3 curriculum/intermediate/07-risk-assurance-stepup/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/07-risk-assurance-stepup/risk_stepup_authorization.ipynb"
  },
  {
    "id": "intermediate/08-workload-assurance-runtime-attestation",
    "module": "08-workload-assurance-runtime-attestation",
    "level": "intermediate",
    "step": 14,
    "levelStep": 8,
    "title": "Workload Assurance & Runtime Attestation for Agents",
    "summary": "bind logical agent identity to a cryptographically identifiable, attested workload and make runtime/supply-chain evidence part of authorization",
    "detail": "bind logical agent identity to a cryptographically identifiable, attested workload and make runtime/supply-chain evidence part of authorization",
    "outcomes": [
      "distinguish logical agent identity from workload/process identity",
      "design SPIFFE IDs and trust domains",
      "understand SPIFFE SVIDs and the Workload API",
      "compare X.509-SVID, JWT-SVID and emerging WIT-SVID concepts",
      "understand SPIRE Server, SPIRE Agent and registration entries",
      "distinguish node attestation from workload attestation"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/08-workload-assurance-runtime-attestation/README.md",
    "references": [
      {
        "label": "SPIFFE standards",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/"
      },
      {
        "label": "SPIFFE Identity and SVID",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/"
      },
      {
        "label": "SPIFFE Workload API",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/"
      },
      {
        "label": "X.509-SVID",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/x509-svid/"
      },
      {
        "label": "SPIFFE Trust Domain and Bundle",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/spiffe_trust_domain_and_bundle/"
      }
    ],
    "checkpoint": {
      "id": "intermediate/08-workload-assurance-runtime-attestation/q-1",
      "text": "A namespace selector matches the intended claims agent and several unrelated pods. What should the SPIRE operator do?",
      "options": [
        "Make the SVID lifetime longer",
        "Issue the same identity to every matching pod",
        "Add independent selectors such as service account, parent node, and approved image identity"
      ],
      "answer": 2,
      "explanation": "Selectors are identity-issuance policy. A broad selector lets an unrelated workload obtain the privileged SPIFFE ID."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/08-workload-assurance-runtime-attestation/lab.py",
    "run": "python3 curriculum/intermediate/08-workload-assurance-runtime-attestation/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/08-workload-assurance-runtime-attestation/workload_attestation.ipynb"
  },
  {
    "id": "intermediate/09-authorization-governance",
    "module": "09-authorization-governance",
    "level": "intermediate",
    "step": 15,
    "levelStep": 9,
    "title": "Authorization Governance, Delegation & Least Privilege at Scale",
    "summary": "govern authorization as a continuously managed enterprise system—not a collection of static roles and policies",
    "detail": "govern authorization as a continuously managed enterprise system—not a collection of static roles and policies",
    "outcomes": [
      "build an agent authorization inventory",
      "create an entitlement catalog",
      "model delegation as a graph",
      "distinguish direct, inherited and delegated authority",
      "calculate effective permissions",
      "detect delegation-depth and transitive-authority risks"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/09-authorization-governance/README.md",
    "references": [
      {
        "label": "OpenFGA authorization concepts",
        "url": "https://openfga.dev/docs/learn"
      },
      {
        "label": "modeling",
        "url": "https://openfga.dev/docs/modeling"
      },
      {
        "label": "ReBAC",
        "url": "https://openfga.dev/docs/learn/rebac"
      },
      {
        "label": "OpenFGA immutable authorization models",
        "url": "https://openfga.dev/docs/getting-started/immutable-models"
      },
      {
        "label": "conditions",
        "url": "https://openfga.dev/docs/modeling/conditions"
      }
    ],
    "checkpoint": {
      "id": "intermediate/09-authorization-governance/q-1",
      "text": "A critical break-glass entitlement has zero uses in 90 days. What should governance automation do?",
      "options": [
        "Delete it immediately because zero usage proves it is unnecessary",
        "Route it to a risk-aware review with owner, justification, expiry, and emergency-use context",
        "Convert it to a permanent wildcard so it remains available"
      ],
      "answer": 1,
      "explanation": "Usage is evidence for a controlled review, not sufficient authority for an automatic mutation—especially for rare emergency access."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/09-authorization-governance/lab.py",
    "run": "python3 curriculum/intermediate/09-authorization-governance/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/09-authorization-governance/governance_delegation.ipynb"
  },
  {
    "id": "intermediate/10-authorization-observability-audit-analytics",
    "module": "10-authorization-observability-audit-analytics",
    "level": "intermediate",
    "step": 16,
    "levelStep": 10,
    "title": "Authorization Observability & Audit Analytics for Agents",
    "summary": "make every important agent authorization decision explainable, traceable, privacy-aware, analyzable and reconstructable",
    "detail": "make every important agent authorization decision explainable, traceable, privacy-aware, analyzable and reconstructable",
    "outcomes": [
      "design a canonical authorization decision event",
      "correlate identity, delegation, policy, workload and tool evidence",
      "distinguish logs, traces, metrics and audit records",
      "capture decision provenance and reason codes",
      "understand OPA decision logs and masking",
      "use Cedar authorization diagnostics correctly"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/10-authorization-observability-audit-analytics/README.md",
    "references": [
      {
        "label": "OpenTelemetry Logs Data Model",
        "url": "https://opentelemetry.io/docs/specs/otel/logs/data-model/"
      },
      {
        "label": "OpenTelemetry Semantic Conventions",
        "url": "https://opentelemetry.io/docs/specs/semconv/"
      },
      {
        "label": "OpenTelemetry GenAI conventions repository transition",
        "url": "https://opentelemetry.io/docs/specs/semconv/gen-ai/"
      },
      {
        "label": "OpenTelemetry GenAI attribute registry",
        "url": "https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/"
      },
      {
        "label": "W3C Trace Context",
        "url": "https://www.w3.org/TR/trace-context/"
      }
    ],
    "checkpoint": {
      "id": "intermediate/10-authorization-observability-audit-analytics/q-1",
      "text": "A valid trace ID on a tool receipt matches an authorization span. What does that prove?",
      "options": [
        "Only that the records carry matching correlation context; producer trust and exact decision/effect binding still require verification",
        "The receipt cannot contain sensitive data",
        "The tool caller had authority"
      ],
      "answer": 0,
      "explanation": "W3C trace context is correlation input, not identity, a capability, a producer signature, or proof that the authorized request was the one executed."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/10-authorization-observability-audit-analytics/lab.py",
    "run": "python3 curriculum/intermediate/10-authorization-observability-audit-analytics/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/10-authorization-observability-audit-analytics/observability_audit_analytics.ipynb"
  },
  {
    "id": "intermediate/11-adversarial-authorization-testing",
    "module": "11-adversarial-authorization-testing",
    "level": "intermediate",
    "step": 17,
    "levelStep": 11,
    "title": "Adversarial Authorization Testing for Agents",
    "summary": "stop asking whether an authorization design looks secure and start proving that it resists realistic adversarial behavior",
    "detail": "stop asking whether an authorization design looks secure and start proving that it resists realistic adversarial behavior",
    "outcomes": [
      "threat-model authorization boundaries in agent systems",
      "distinguish authentication failures from authorization failures",
      "test confused-deputy vulnerabilities",
      "test token substitution, replay, downgrade, and audience confusion",
      "attack delegation scope, depth, expiry, and re-delegation",
      "test identity/workload binding"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/11-adversarial-authorization-testing/README.md",
    "references": [
      {
        "label": "Open Policy Agent: policy testing, fail-on-empty and coverage",
        "url": "https://www.openpolicyagent.org/docs/policy-testing"
      },
      {
        "label": "Cedar policy validation and validation soundness",
        "url": "https://docs.cedarpolicy.com/policies/validation.html"
      },
      {
        "label": "Cedar authorization semantics and diagnostics",
        "url": "https://docs.cedarpolicy.com/auth/authorization.html"
      },
      {
        "label": "OpenFGA model testing",
        "url": "https://openfga.dev/docs/modeling/testing"
      },
      {
        "label": "OpenFGA store file format",
        "url": "https://openfga.dev/docs/modeling/store-file-format"
      }
    ],
    "checkpoint": {
      "id": "intermediate/11-adversarial-authorization-testing/q-1",
      "text": "A red-team case expected CROSS_TENANT_RESOURCE but the request crashed with a JSON parse error. Should the case pass?",
      "options": [
        "Yes, if the HTTP status was not 200",
        "Yes, any failure means the resource was protected",
        "No; the oracle must deny for the expected security invariant so unrelated failures cannot hide a bypass"
      ],
      "answer": 2,
      "explanation": "Stable expected reason codes prove the intended control made the decision. An unrelated parser failure may disappear later and says nothing about tenant enforcement."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/11-adversarial-authorization-testing/lab.py",
    "run": "python3 curriculum/intermediate/11-adversarial-authorization-testing/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/11-adversarial-authorization-testing/adversarial_authorization_testing.ipynb"
  },
  {
    "id": "intermediate/12-integrating-authorization-agents-guardrails",
    "module": "12-integrating-authorization-agents-guardrails",
    "level": "intermediate",
    "step": 18,
    "levelStep": 12,
    "title": "Integrating Authorization with LLMs, Agents & Guardrails",
    "summary": "make authorization a mandatory execution boundary around agent actions—not a suggestion embedded in a prompt",
    "detail": "make authorization a mandatory execution boundary around agent actions—not a suggestion embedded in a prompt",
    "outcomes": [
      "treat model-generated actions as untrusted intents",
      "build a structured authorization intent between planning and execution",
      "place PDP/PEP checks around tools, APIs, resources, MCP servers, and sub-agents",
      "distinguish authorization from input/output/tool guardrails",
      "implement least-privilege tool exposure",
      "perform per-tool and per-resource authorization"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/12-integrating-authorization-agents-guardrails/README.md",
    "references": [
      {
        "label": "OpenAI — Guardrails and approvals",
        "url": "https://developers.openai.com/api/docs/guides/agents/guardrails-approvals"
      },
      {
        "label": "OpenAI Agents SDK — Python",
        "url": "https://openai.github.io/openai-agents-python/"
      },
      {
        "label": "OpenAI Agents SDK — Guardrails",
        "url": "https://openai.github.io/openai-agents-python/guardrails/"
      },
      {
        "label": "OpenAI Agents SDK — Human in the loop",
        "url": "https://openai.github.io/openai-agents-python/human_in_the_loop/"
      },
      {
        "label": "OpenAI Agents SDK — MCP",
        "url": "https://openai.github.io/openai-agents-python/mcp/"
      }
    ],
    "checkpoint": {
      "id": "intermediate/12-integrating-authorization-agents-guardrails/q-1",
      "text": "A tool input guardrail says a CAD 750 payment is well formed, and the Agents SDK pauses for human approval. What must still happen before commit?",
      "options": [
        "Execute because guardrail plus approval equals authorization",
        "Re-authorize trusted principal, workload, delegation, tenant, resource, exact arguments, and current state at the effect boundary",
        "Ask the model to confirm the approver's role"
      ],
      "answer": 1,
      "explanation": "Guardrails validate behavior and SDK approval controls run state; neither replaces application authorization or commit-time revalidation."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/12-integrating-authorization-agents-guardrails/lab.py",
    "run": "python3 curriculum/intermediate/12-integrating-authorization-agents-guardrails/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/12-integrating-authorization-agents-guardrails/integrating_authorization_with_agents.ipynb"
  },
  {
    "id": "intermediate/13-capstone-secure-agent-identity",
    "module": "13-capstone-secure-agent-identity",
    "level": "intermediate",
    "step": 19,
    "levelStep": 13,
    "title": "Capstone: Secure Agent Identity & Authorization Architecture",
    "summary": "integrate human identity, logical agent identity, workload identity, delegation, OAuth/OIDC, MCP, policy engines, resource authorization, HITL, guardrails, observability, adversarial testing, and governance into one production-style enterprise architecture",
    "detail": "integrate human identity, logical agent identity, workload identity, delegation, OAuth/OIDC, MCP, policy engines, resource authorization, HITL, guardrails, observability, adversarial testing, and governance into one production-style enterprise architecture",
    "outcomes": [
      "authenticated human, logical agent, workload, artifact, task, delegation, and sender identities remain distinct and bound",
      "OAuth scope, OpenFGA relationships, contextual policy, and resource-side constraints all agree before an effect",
      "RAG and memory are filtered before sensitive content reaches the model",
      "sub-agent authority is a strict subset of the parent delegation",
      "MCP server and audience substitution and token passthrough fail closed",
      "approval binds one exact proposal and commit-time state"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/13-capstone-secure-agent-identity/README.md",
    "references": [
      {
        "label": "NIST NCCoE — Accelerating the Adoption of Software and AI Agent Identity and Authorization",
        "url": "https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd"
      },
      {
        "label": "SPIFFE — Workload identity overview",
        "url": "https://spiffe.io/docs/latest/spiffe-about/overview/"
      },
      {
        "label": "SPIFFE — Workload API",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/"
      },
      {
        "label": "OpenAI — Guardrails and approvals",
        "url": "https://developers.openai.com/api/docs/guides/agents/guardrails-approvals"
      },
      {
        "label": "OpenAI Agents SDK — Python",
        "url": "https://openai.github.io/openai-agents-python/"
      }
    ],
    "checkpoint": {
      "id": "intermediate/13-capstone-secure-agent-identity/q-1",
      "text": "A request has a valid user token and OpenFGA confirms the agent is assigned to the claim, but the executing artifact is not an approved registry release. What should the PEP do?",
      "options": [
        "Deny because human identity, relationship authority, workload, artifact, and contextual policy must all agree",
        "Ask the model whether the artifact is probably safe",
        "Allow because relationship authorization passed"
      ],
      "answer": 0,
      "explanation": "No single plane is sufficient. The logical agent must be bound to an approved workload and artifact before resource authority can be exercised."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/13-capstone-secure-agent-identity/lab.py",
    "run": "python3 curriculum/intermediate/13-capstone-secure-agent-identity/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/intermediate/13-capstone-secure-agent-identity/capstone_secure_agent_identity.ipynb"
  },
  {
    "id": "advanced/01-advanced-authorization-models",
    "module": "01-advanced-authorization-models",
    "level": "advanced",
    "step": 20,
    "levelStep": 1,
    "title": "Advanced Authorization Models for Autonomous Agents",
    "summary": "design, implement, and evaluate a hybrid authorization control plane that composes roles, relationships, trusted attributes, task bounds, risk, approvals, versions, and deterministic enforcement for autonomous agents",
    "detail": "design, implement, and evaluate a hybrid authorization control plane that composes roles, relationships, trusted attributes, task bounds, risk, approvals, versions, and deterministic enforcement for autonomous agents",
    "outcomes": [
      "distinguish RBAC, ReBAC, ABAC, policy-based, purpose-based, and task/time-bound authorization",
      "assign each authorization fact to an authoritative source rather than trusting agent text",
      "model the intersection of human, agent, task, tenant, resource, and tool relationships",
      "compose current attributes, relationships, versions, and lifecycle state deterministically",
      "return allow, deny, stepup, and retryableerror without conflating them",
      "bind constraints, obligations, approvals, cache entries, and receipts to exact decisions"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/01-advanced-authorization-models/README.md",
    "references": [
      {
        "label": "NIST SP 800-162",
        "url": "https://csrc.nist.gov/pubs/sp/800/162/upd2/final"
      },
      {
        "label": "authorization algorithm",
        "url": "https://docs.cedarpolicy.com/auth/authorization.html"
      },
      {
        "label": "validation guidance",
        "url": "https://docs.cedarpolicy.com/policies/validation.html"
      },
      {
        "label": "immutable model guidance",
        "url": "https://openfga.dev/docs/getting-started/immutable-models"
      },
      {
        "label": "conditions",
        "url": "https://openfga.dev/docs/modeling/conditions"
      }
    ],
    "checkpoint": {
      "id": "advanced/01-advanced-authorization-models/q-1",
      "text": "A claims agent has the correct role and OpenFGA confirms its task relationship, but its risk attributes are stale. What should the hybrid PDP do?",
      "options": [
        "Ask the model to estimate current risk",
        "Allow because two authorization models agree",
        "Deny or return a distinct unavailable/stale outcome according to policy; never treat stale context as current"
      ],
      "answer": 2,
      "explanation": "Role and relationship eligibility do not compensate for missing current ABAC evidence. The application must preserve explicit failure semantics and create no effect."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/01-advanced-authorization-models/lab.py",
    "run": "python3 curriculum/advanced/01-advanced-authorization-models/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/01-advanced-authorization-models/advanced_authorization_models.ipynb"
  },
  {
    "id": "advanced/02-cryptographic-delegation-capabilities",
    "module": "02-cryptographic-delegation-capabilities",
    "level": "advanced",
    "step": 21,
    "levelStep": 2,
    "title": "Cryptographic Delegation, Capabilities & Verifiable Provenance for Agents",
    "summary": "design, implement, and evaluate attenuated, sender-constrained agent delegation that combines verifiable capability chains with current policy and signed provenance",
    "detail": "design, implement, and evaluate attenuated, sender-constrained agent delegation that combines verifiable capability chains with current policy and signed provenance",
    "outcomes": [
      "distinguish identity, authentication, delegation, impersonation, and capability-based authority",
      "define and test monotonic attenuation across subject, tenant, task, audience, action, resource, tool, purpose, time, budget, depth, and parent",
      "verify every signature and every link in a delegation chain",
      "bind use of authority to a client key with DPoP and explain when mTLS is a better fit",
      "combine portable proof with revocation, risk, workload, and relationship state in OPA or Cedar",
      "use Macaroons and assess Biscuit without overstating library maturity"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/02-cryptographic-delegation-capabilities/README.md",
    "references": [
      {
        "label": "RFC 8693",
        "url": "https://www.rfc-editor.org/rfc/rfc8693"
      },
      {
        "label": "RFC 9449",
        "url": "https://www.rfc-editor.org/rfc/rfc9449"
      },
      {
        "label": "RFC 8705",
        "url": "https://www.rfc-editor.org/rfc/rfc8705"
      },
      {
        "label": "RFC 8707",
        "url": "https://www.rfc-editor.org/rfc/rfc8707"
      },
      {
        "label": "PyMacaroons",
        "url": "https://github.com/ecordell/pymacaroons"
      }
    ],
    "checkpoint": {
      "id": "advanced/02-cryptographic-delegation-capabilities/q-1",
      "text": "A child capability is correctly signed by its issuer but adds claim.delete to the parent's knowledge.search grant. What should the verifier do?",
      "options": [
        "Allow because the signature is valid",
        "Deny because the child action set is not a subset of the parent",
        "Allow if the child expires sooner"
      ],
      "answer": 1,
      "explanation": "Signature validity proves who signed the child; attenuation independently proves that the issuer did not widen delegated authority."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/02-cryptographic-delegation-capabilities/lab.py",
    "run": "python3 curriculum/advanced/02-cryptographic-delegation-capabilities/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/02-cryptographic-delegation-capabilities/advanced_02_cryptographic_delegation.ipynb"
  },
  {
    "id": "advanced/03-cross-domain-identity-federation",
    "module": "03-cross-domain-identity-federation",
    "level": "advanced",
    "step": 22,
    "levelStep": 3,
    "title": "Cross-Domain Identity Federation & Interoperability for Agents",
    "summary": "design, implement, and evaluate cross-domain agent access that verifies a foreign trust chain and workload identity, resists OAuth/MCP mix-up, preserves namespaces, and keeps authorization local and revocable",
    "detail": "design, implement, and evaluate cross-domain agent access that verifies a foreign trust chain and workload identity, resists OAuth/MCP mix-up, preserves namespaces, and keeps authorization local and revocable",
    "outcomes": [
      "separate discovery, trust establishment, authentication, identity mapping, delegation, and local authorization",
      "construct and verify signed OpenID Federation-style entity statements that terminate at a locally configured trust anchor",
      "explain deterministic hierarchical metadata-policy resolution and why a conflicting policy invalidates a chain",
      "verify a real X.509-SVID against an exact <trust domain, bundle> binding",
      "validate an access token against its verified federation subject, audience, lifetime, sender key, agent class, and local partner agreement",
      "preserve (issuer, subject) as a compound identity without importing foreign roles"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/03-cross-domain-identity-federation/README.md",
    "references": [
      {
        "label": "OpenID Federation 1.0",
        "url": "https://openid.net/specs/openid-federation-1_0.html"
      },
      {
        "label": "SPIFFE Trust Domain and Bundle specification",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/spiffe_trust_domain_and_bundle/"
      },
      {
        "label": "SPIFFE Federation",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/"
      },
      {
        "label": "RFC 9728",
        "url": "https://www.rfc-editor.org/rfc/rfc9728"
      },
      {
        "label": "OAuth 2.0 Security Best Current Practice, RFC 9700",
        "url": "https://www.rfc-editor.org/rfc/rfc9700"
      }
    ],
    "checkpoint": {
      "id": "advanced/03-cross-domain-identity-federation/q-1",
      "text": "In a leaf → intermediate → trust-anchor entity-statement chain, which identifier must match the locally accepted anchor?",
      "options": [
        "The issuer of the final statement",
        "The leaf's human-readable organization name",
        "The subject of the final statement"
      ],
      "answer": 0,
      "explanation": "The final subordinate statement is issued by the trust anchor about the top intermediate. Its issuer must match a locally configured anchor and key."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/03-cross-domain-identity-federation/lab.py",
    "run": "python3 curriculum/advanced/03-cross-domain-identity-federation/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/03-cross-domain-identity-federation/advanced_03_cross_domain_federation.ipynb"
  },
  {
    "id": "advanced/04-agent-attestations-verifiable-credentials",
    "module": "04-agent-attestations-verifiable-credentials",
    "level": "advanced",
    "step": 23,
    "levelStep": 4,
    "title": "Agent Attestations, Verifiable Credentials & Trust Evidence",
    "summary": "turn claims about an agent into independently verifiable, freshness-aware, revocable, and correctly bound evidence—then use local policy, not the credential itself, to decide whether an action is allowed",
    "detail": "turn claims about an agent into independently verifiable, freshness-aware, revocable, and correctly bound evidence—then use local policy, not the credential itself, to decide whether an action is allowed",
    "outcomes": [
      "distinguish a claim, credential, verifiable credential, presentation, attestation evidence, attestation result, and authorization decision",
      "explain why signature validity proves authorship and integrity—not truth, issuer authority, fitness for purpose, or permission",
      "verify credential type, issuer policy, proof, schema, subject, audience, lifetime, status, and allowed claim vocabulary",
      "bind a presentation to its holder, verifier, challenge, subject, and a single-use replay record",
      "use W3C VC 2.0, OpenID4VCI, OpenID4VP/DCQL, RFC 9901 SD-JWT, and status-list concepts without confusing their distinct roles",
      "model RATS evidence and EAT measurements separately from the verifier's attestation result and the relying party's policy"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/04-agent-attestations-verifiable-credentials/README.md",
    "references": [
      {
        "label": "VC Data Model 2.0",
        "url": "https://www.w3.org/TR/vc-data-model-2.0/"
      },
      {
        "label": "VC Data Integrity 1.0",
        "url": "https://www.w3.org/TR/vc-data-integrity/"
      },
      {
        "label": "Securing VCs using JOSE and COSE",
        "url": "https://www.w3.org/TR/vc-jose-cose/"
      },
      {
        "label": "Bitstring Status List v1.0",
        "url": "https://www.w3.org/TR/vc-bitstring-status-list/"
      },
      {
        "label": "RFC 9901",
        "url": "https://www.rfc-editor.org/rfc/rfc9901"
      }
    ],
    "checkpoint": {
      "id": "advanced/04-agent-attestations-verifiable-credentials/q-1",
      "text": "A registration credential has a valid signature from the approved registry, but it contains evaluation-result claims. Should the verifier accept those claims?",
      "options": [
        "Yes, if the credential has not expired",
        "Yes, because the signature is valid",
        "No, because issuer authority is scoped by credential type, schema, and allowed claims"
      ],
      "answer": 2,
      "explanation": "A proof establishes authorship and integrity. Local issuer policy still limits which credential types and claims that issuer is authoritative for."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/04-agent-attestations-verifiable-credentials/lab.py",
    "run": "python3 curriculum/advanced/04-agent-attestations-verifiable-credentials/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/04-agent-attestations-verifiable-credentials/advanced_04_agent_attestations_credentials.ipynb"
  },
  {
    "id": "advanced/05-continuous-adaptive-trust",
    "module": "05-continuous-adaptive-trust",
    "level": "advanced",
    "step": 24,
    "levelStep": 5,
    "title": "Continuous and Adaptive Trust for Autonomous Agents",
    "summary": "keep an agent's authority synchronized with current identity, workload, behavior, threat, transaction, and governance state—including while a long-running operation is already in progress",
    "detail": "keep an agent's authority synchronized with current identity, workload, behavior, threat, transaction, and governance state—including while a long-running operation is already in progress",
    "outcomes": [
      "distinguish continuous authentication, continuous authorization, risk adaptation, and token revocation",
      "explain the roles of SSF, CAEP, RISC, SET, subject identifiers, and push or poll delivery",
      "validate a signed SET before acknowledging it and separate durable receipt from asynchronous projection",
      "correlate a signal to the exact tenant, agent, workload, and session without accepting ambiguous identifiers",
      "handle duplicates, late delivery, stale relaxation, backlog, stream outage, and recovery without reopening access unsafely",
      "combine identity, workload, behavior, threat, transaction, and governance state without treating a scalar score as authority"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/05-continuous-adaptive-trust/README.md",
    "references": [
      {
        "label": "RFC 8417",
        "url": "https://www.rfc-editor.org/rfc/rfc8417"
      },
      {
        "label": "SSF 1.0 Final",
        "url": "https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html"
      },
      {
        "label": "RFC 8935 push delivery",
        "url": "https://www.rfc-editor.org/rfc/rfc8935"
      },
      {
        "label": "RFC 8936 poll delivery",
        "url": "https://www.rfc-editor.org/rfc/rfc8936"
      },
      {
        "label": "RFC 9493 subject identifiers",
        "url": "https://www.rfc-editor.org/rfc/rfc9493"
      }
    ],
    "checkpoint": {
      "id": "advanced/05-continuous-adaptive-trust/q-1",
      "text": "A push receiver has authenticated and validated a SET but has not durably persisted it. May it return HTTP 202?",
      "options": [
        "Yes, because signature validation completed",
        "No, because 202 should follow durable acceptance so a crash cannot silently lose acknowledged work",
        "Yes, if projection normally finishes quickly"
      ],
      "answer": 1,
      "explanation": "Validation and business processing are separate. Persist before acknowledgement so retries and restart recovery remain safe."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/05-continuous-adaptive-trust/lab.py",
    "run": "python3 curriculum/advanced/05-continuous-adaptive-trust/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/05-continuous-adaptive-trust/advanced_05_continuous_adaptive_trust.ipynb"
  },
  {
    "id": "advanced/06-decentralized-identity-multi-agent-trust",
    "module": "06-decentralized-identity-multi-agent-trust",
    "level": "advanced",
    "step": 25,
    "levelStep": 6,
    "title": "Decentralized Identity and Trust for Multi-Agent Ecosystems",
    "summary": "authenticate an agent controlled outside your identity domain, establish exactly which external claims your organization accepts, and authorize one bounded action without assuming that a DID, credential, reputation score, or trust path is permission",
    "detail": "authenticate an agent controlled outside your identity domain, establish exactly which external claims your organization accepts, and authorize one bounded action without assuming that a DID, credential, reputation score, or trust path is permission",
    "outcomes": [
      "distinguish identifiers, controllers, credentials, trust anchors, reputation, and authorization",
      "parse DIDs and enforce a local DID-method policy",
      "derive an Ed25519 did:key using multicodec and multibase",
      "map did:web identifiers to HTTPS URLs without path confusion or unrestricted network access",
      "validate DID documents, metadata, key material, verification relationships, and services",
      "handle deactivation, key rotation, resolver caching, and high-assurance resolver disagreement"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/06-decentralized-identity-multi-agent-trust/README.md",
    "references": [
      {
        "label": "Decentralized Identifiers (DIDs) v1.0",
        "url": "https://www.w3.org/TR/did-core/"
      },
      {
        "label": "Decentralized Identifiers (DIDs) v1.1",
        "url": "https://www.w3.org/TR/did-1.1/"
      },
      {
        "label": "DID Resolution",
        "url": "https://www.w3.org/TR/did-resolution/"
      },
      {
        "label": "DID Method Rubric 2.0",
        "url": "https://www.w3.org/TR/did-rubric/"
      },
      {
        "label": "did:web Method Specification",
        "url": "https://w3c-ccg.github.io/did-method-web/"
      }
    ],
    "checkpoint": {
      "id": "advanced/06-decentralized-identity-multi-agent-trust/q-1",
      "text": "A caller proves control of a valid DID. What has the verifier established?",
      "options": [
        "The caller controls an authentication key for that DID in this transaction",
        "The caller belongs to an approved organization and may use every tool",
        "Every claim in the DID document is locally trusted"
      ],
      "answer": 0,
      "explanation": "DID control is authentication evidence. Organization membership, delegation, current state, and authorization require separate checks."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/06-decentralized-identity-multi-agent-trust/lab.py",
    "run": "python3 curriculum/advanced/06-decentralized-identity-multi-agent-trust/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/06-decentralized-identity-multi-agent-trust/advanced_06_decentralized_identity.ipynb"
  },
  {
    "id": "advanced/07-non-human-identity-security-key-management",
    "module": "07-non-human-identity-security-key-management",
    "level": "advanced",
    "step": 26,
    "levelStep": 7,
    "title": "Non-Human Identity Security & Key Management for Agents",
    "summary": "secure the operational identity substrate underneath autonomous agents: workload identity, machine credentials, keys, certificates, tokens, secretless federation, rotation, isolation, monitoring, and incident response",
    "detail": "secure the operational identity substrate underneath autonomous agents: workload identity, machine credentials, keys, certificates, tokens, secretless federation, rotation, isolation, monitoring, and incident response",
    "outcomes": [
      "distinguish logical agent identity from workload, service, application, and credential identities",
      "inventory and classify non-human identities",
      "design secure onboarding and decommissioning",
      "apply Zero Trust to machine identities",
      "prefer short-lived credentials and federation over static secrets",
      "use SPIFFE IDs and X.509/JWT SVIDs"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/07-non-human-identity-security-key-management/README.md",
    "references": [
      {
        "label": "csrc.nist.gov",
        "url": "https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd"
      },
      {
        "label": "csrc.nist.gov",
        "url": "https://csrc.nist.gov/pubs/sp/800/207/final"
      },
      {
        "label": "spiffe.io",
        "url": "https://spiffe.io/"
      },
      {
        "label": "spiffe.io",
        "url": "https://spiffe.io/docs/latest/spire-about/"
      },
      {
        "label": "spiffe.io",
        "url": "https://spiffe.io/docs/latest/deploying/svids/"
      }
    ],
    "checkpoint": {
      "id": "advanced/07-non-human-identity-security-key-management/q-1",
      "text": "A valid five-minute access token is stolen from an agent log. Which control most directly prevents its use by the thief?",
      "options": [
        "Base64-encoding the log",
        "A longer token identifier",
        "Sender constraint that requires proof of the bound private key"
      ],
      "answer": 2,
      "explanation": "mTLS certificate binding or DPoP makes token possession alone insufficient; short lifetime only reduces the remaining window."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/07-non-human-identity-security-key-management/lab.py",
    "run": "python3 curriculum/advanced/07-non-human-identity-security-key-management/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/07-non-human-identity-security-key-management/advanced_07_non_human_identity_security.ipynb"
  },
  {
    "id": "advanced/08-agent-identity-lifecycle-governance",
    "module": "08-agent-identity-lifecycle-governance",
    "level": "advanced",
    "step": 27,
    "levelStep": 8,
    "title": "Agent Identity Lifecycle, Governance & Operational Excellence",
    "summary": "operate agent identity as an enterprise product: inventoried, owned, risk-tiered, approved, continuously monitored, periodically recertified, rapidly revocable, auditable, measurable, and automated",
    "detail": "operate agent identity as an enterprise product: inventoried, owned, risk-tiered, approved, continuously monitored, periodically recertified, rapidly revocable, auditable, measurable, and automated",
    "outcomes": [
      "design an enterprise agent identity inventory",
      "classify agents, workloads, tools, sub-agents, and external agents",
      "establish accountable ownership",
      "risk-tier identities and authority",
      "design registration and onboarding",
      "implement approval workflows"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/08-agent-identity-lifecycle-governance/README.md",
    "references": [
      {
        "label": "nccoe.nist.gov",
        "url": "https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization"
      },
      {
        "label": "csrc.nist.gov",
        "url": "https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd"
      },
      {
        "label": "nvlpubs.nist.gov",
        "url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"
      },
      {
        "label": "nvlpubs.nist.gov",
        "url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf"
      },
      {
        "label": "csrc.nist.gov",
        "url": "https://csrc.nist.gov/pubs/sp/800/207/final"
      }
    ],
    "checkpoint": {
      "id": "advanced/08-agent-identity-lifecycle-governance/q-1",
      "text": "A high-risk agent proposal was approved, then its workload, tool authority, and model version changed before activation. What should the controller do?",
      "options": [
        "Activate because the agent ID is unchanged",
        "Reject activation because the signed approvals are bound to the original proposal digest",
        "Ask the model whether the changes are material"
      ],
      "answer": 1,
      "explanation": "Approval must bind the exact tenant, workload, artifact/model, authority, policy version, and other decision-relevant proposal fields."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/08-agent-identity-lifecycle-governance/lab.py",
    "run": "python3 curriculum/advanced/08-agent-identity-lifecycle-governance/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/08-agent-identity-lifecycle-governance/advanced_08_identity_lifecycle_governance.ipynb"
  },
  {
    "id": "advanced/09-agent-identity-security-posture-threat-defense",
    "module": "09-agent-identity-security-posture-threat-defense",
    "level": "advanced",
    "step": 28,
    "levelStep": 9,
    "title": "Agent Identity Security Posture Management & Threat Defense",
    "summary": "turn agent identity from a static access-control configuration into a continuously observed, graph-analyzed, attack-tested and rapidly defensible security system",
    "detail": "turn agent identity from a static access-control configuration into a continuously observed, graph-analyzed, attack-tested and rapidly defensible security system",
    "outcomes": [
      "build identity graphs",
      "discover attack paths",
      "toxic privilege combinations",
      "quantify blast radius",
      "detect stolen credentials, anomalous delegation",
      "lateral movement"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/09-agent-identity-security-posture-threat-defense/README.md",
    "references": [
      {
        "label": "csrc.nist.gov",
        "url": "https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd"
      },
      {
        "label": "csrc.nist.gov",
        "url": "https://csrc.nist.gov/pubs/sp/800/61/r3/final"
      },
      {
        "label": "owasp.org",
        "url": "https://owasp.org/projects/non-human-identities-top-10"
      },
      {
        "label": "spiffe.io",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/"
      },
      {
        "label": "openid.net",
        "url": "https://openid.net/three-shared-signals-final-specifications-approved/"
      }
    ],
    "checkpoint": {
      "id": "advanced/09-agent-identity-security-posture-threat-defense/q-1",
      "text": "A telemetry envelope has a valid signature, but the KMS source asserts a governance delegation event. Should the event enter detection?",
      "options": [
        "No, the receiver must also enforce source authority for the event type",
        "Yes, if the event has a high risk score",
        "Yes, because any trusted key may assert any event"
      ],
      "answer": 0,
      "explanation": "A signature establishes origin and integrity, not unlimited event authority. The lab allowlists event types per source."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/09-agent-identity-security-posture-threat-defense/lab.py",
    "run": "python3 curriculum/advanced/09-agent-identity-security-posture-threat-defense/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/09-agent-identity-security-posture-threat-defense/advanced_09_identity_posture_threat_defense.ipynb"
  },
  {
    "id": "advanced/10-identity-observability-telemetry-forensics",
    "module": "10-identity-observability-telemetry-forensics",
    "level": "advanced",
    "step": 29,
    "levelStep": 10,
    "title": "Identity Observability, Telemetry & Forensics for Agents",
    "summary": "make an agent's identity, authority, delegation, credentials, tool use, policy decisions and runtime actions reconstructable from trustworthy telemetry",
    "detail": "make an agent's identity, authority, delegation, credentials, tool use, policy decisions and runtime actions reconstructable from trustworthy telemetry",
    "outcomes": [
      "design an identity observability architecture for agents",
      "distinguish logs, metrics, traces, events and evidence",
      "use OpenTelemetry concepts for agent/tool traces",
      "correlate human, agent, workload and service identities",
      "model authentication, authorization, delegation and credential events",
      "instrument policy decisions"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/10-identity-observability-telemetry-forensics/README.md",
    "references": [
      {
        "label": "github.com",
        "url": "https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md"
      },
      {
        "label": "github.com",
        "url": "https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md"
      },
      {
        "label": "opentelemetry.io",
        "url": "https://opentelemetry.io/docs/collector/"
      },
      {
        "label": "github.com",
        "url": "https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/redactionprocessor"
      },
      {
        "label": "opentelemetry.io",
        "url": "https://opentelemetry.io/docs/specs/otel/logs/data-model/"
      }
    ],
    "checkpoint": {
      "id": "advanced/10-identity-observability-telemetry-forensics/q-1",
      "text": "A claims API signs an event labelled as an authorization decision. Is the signature sufficient to admit it?",
      "options": [
        "Yes, if the trace ID already exists",
        "Yes, every trusted producer may assert every event type",
        "No, the collector must also enforce producer authority for that event type"
      ],
      "answer": 2,
      "explanation": "A signature proves origin and integrity; it does not grant a producer authority to assert another component's evidence."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/10-identity-observability-telemetry-forensics/lab.py",
    "run": "python3 curriculum/advanced/10-identity-observability-telemetry-forensics/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/10-identity-observability-telemetry-forensics/advanced_10_identity_observability_telemetry_forensics.ipynb"
  },
  {
    "id": "advanced/11-compliance-audit-forensic-readiness",
    "module": "11-compliance-audit-forensic-readiness",
    "level": "advanced",
    "step": 30,
    "levelStep": 11,
    "title": "Compliance, Audit & Forensic Readiness for Agent Identity",
    "summary": "turn agent identity controls and telemetry into continuous, defensible assurance: control objectives, machine-evaluated compliance, audit-ready evidence, traceable exceptions, and forensic readiness",
    "detail": "turn agent identity controls and telemetry into continuous, defensible assurance: control objectives, machine-evaluated compliance, audit-ready evidence, traceable exceptions, and forensic readiness",
    "outcomes": [
      "create an agent-identity control catalog",
      "translate requirements into control objectives and evidence",
      "map controls to NIST, ISO, SOC 2, CIS, PCI DSS, privacy and AI obligations",
      "distinguish design effectiveness from operating effectiveness",
      "continuously evaluate identity controls",
      "build machine-verifiable control evidence"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/11-compliance-audit-forensic-readiness/README.md",
    "references": [
      {
        "label": "nccoe.nist.gov",
        "url": "https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization"
      },
      {
        "label": "csrc.nist.gov",
        "url": "https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls"
      },
      {
        "label": "csrc.nist.gov",
        "url": "https://csrc.nist.gov/pubs/sp/800/53/a/r5/final"
      },
      {
        "label": "pages.nist.gov",
        "url": "https://pages.nist.gov/OSCAL/about/news/"
      },
      {
        "label": "csrc.nist.gov",
        "url": "https://csrc.nist.gov/pubs/sp/800/61/r3/final"
      }
    ],
    "checkpoint": {
      "id": "advanced/11-compliance-audit-forensic-readiness/q-1",
      "text": "A required artifact is missing but the inventory says the control is configured. What status is defensible?",
      "options": [
        "Pass",
        "Indeterminate and review",
        "Not applicable"
      ],
      "answer": 1,
      "explanation": "Configuration claims do not replace required evidence; missing proof must remain visible."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/11-compliance-audit-forensic-readiness/lab.py",
    "run": "python3 curriculum/advanced/11-compliance-audit-forensic-readiness/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/11-compliance-audit-forensic-readiness/advanced_11_compliance_audit_forensic_readiness.ipynb"
  },
  {
    "id": "advanced/12-secure-compliant-resilient-agent-identity-platform",
    "module": "12-secure-compliant-resilient-agent-identity-platform",
    "level": "advanced",
    "step": 31,
    "levelStep": 12,
    "title": "Capstone: Secure, Compliant & Resilient Enterprise Agent Identity Platform",
    "summary": "integrate the entire Agent Identity curriculum into a production-style enterprise platform that can identify, authenticate, authorize, delegate, federate, observe, govern, detect, recover, and prove the actions of autonomous agents",
    "detail": "integrate the entire Agent Identity curriculum into a production-style enterprise platform that can identify, authenticate, authorize, delegate, federate, observe, govern, detect, recover, and prove the actions of autonomous agents",
    "outcomes": [
      "separate human, logical-agent, workload, task, delegation, credential, and tool identity",
      "exchange audience- and sender-bound authority without widening scope or lifetime",
      "compose lifecycle, workload, relationship, delegation, risk, and federation evidence into a deterministic decision",
      "bind a signed, single-use human approval to one exact request and policy version",
      "enforce constraints, idempotency, and unknown-outcome reconciliation at the PEP",
      "emit privacy-minimized telemetry, respond to authoritative alerts, and prove evidence completeness; and"
    ],
    "material": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/12-secure-compliant-resilient-agent-identity-platform/README.md",
    "references": [
      {
        "label": "nccoe.nist.gov",
        "url": "https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization"
      },
      {
        "label": "nist.gov",
        "url": "https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative"
      },
      {
        "label": "nist.gov",
        "url": "https://www.nist.gov/news-events/news/2026/09/comments-software-and-agentic-ai-identity-concept-paper"
      },
      {
        "label": "csrc.nist.gov",
        "url": "https://csrc.nist.gov/pubs/sp/800/207/final"
      },
      {
        "label": "spiffe.io",
        "url": "https://spiffe.io/docs/latest/spiffe-specs/"
      }
    ],
    "checkpoint": {
      "id": "advanced/12-secure-compliant-resilient-agent-identity-platform/q-1",
      "text": "A payment decision returns approval_required. A supervisor approves the exact request. What should happen next?",
      "options": [
        "Submit the approval evidence and have the PDP evaluate again, producing a new receipt-bound decision",
        "Let the agent execute because the approval UI succeeded",
        "Mutate the original decision to allow"
      ],
      "answer": 0,
      "explanation": "Approval is new evidence, not a retroactive change to a denial or step-up result. Exact intent and policy binding must be verified before a new allow is issued."
    },
    "lab": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/12-secure-compliant-resilient-agent-identity-platform/lab.py",
    "run": "python3 curriculum/advanced/12-secure-compliant-resilient-agent-identity-platform/lab.py",
    "notebook": "https://github.com/mahsa-teimourikia/agent-identity/blob/main/curriculum/advanced/12-secure-compliant-resilient-agent-identity-platform/advanced_12_capstone_agent_identity_platform.ipynb"
  }
];
