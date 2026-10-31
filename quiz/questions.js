const QUESTIONS = [
  {
    "text": "A schema-valid purchase request claims to be from the procurement agent, but verified workload evidence identifies an unapproved development runtime. What should the purchasing API do?",
    "options": [
      "Deny it because the verified workload is not bound to that production agent",
      "Ask the language model whether the request looks safe",
      "Allow it because the declared agent name is correct"
    ],
    "answer": 0,
    "explanation": "The enforcement point must bind verified workload evidence to the governed logical agent and fail closed on a mismatch.",
    "id": "beginner/01-agent-identity-foundations/q-1",
    "courseId": "beginner/01-agent-identity-foundations",
    "courseTitle": "Agent Identity Foundations",
    "courseStep": 1,
    "level": "beginner"
  },
  {
    "text": "Why should human, workload, and agent identities remain distinct?",
    "options": [
      "They should not remain distinct",
      "To prevent a development deployment from silently receiving production authority",
      "To confuse attackers"
    ],
    "answer": 1,
    "explanation": "Separating them allows distinct enforcement and boundaries.",
    "id": "beginner/01-agent-identity-foundations/q-2",
    "courseId": "beginner/01-agent-identity-foundations",
    "courseTitle": "Agent Identity Foundations",
    "courseStep": 1,
    "level": "beginner"
  },
  {
    "text": "What does delegation mean in the context of agent identity?",
    "options": [
      "Writing the code for an agent",
      "Giving an agent full permanent access to everything",
      "Intentionally giving another principal bounded authority"
    ],
    "answer": 2,
    "explanation": "Delegation passes bounded authority intentionally.",
    "id": "beginner/01-agent-identity-foundations/q-3",
    "courseId": "beginner/01-agent-identity-foundations",
    "courseTitle": "Agent Identity Foundations",
    "courseStep": 1,
    "level": "beginner"
  },
  {
    "text": "The booking API authenticates the corporate research workload, but the request envelope claims the booking-specialist agent and names a valid employee. What should it do?",
    "options": [
      "Deny because the workload is not the approved deployment for the claimed agent and application",
      "Allow because the employee is valid",
      "Allow because both workloads use the corporate trust domain"
    ],
    "answer": 0,
    "explanation": "A corporate workload credential does not prove a different logical agent, application binding, or delegation path.",
    "id": "beginner/02-humans-workloads-agents/q-1",
    "courseId": "beginner/02-humans-workloads-agents",
    "courseTitle": "Humans, Workloads and Agents",
    "courseStep": 2,
    "level": "beginner"
  },
  {
    "text": "In an agent request context, what does the 'requester' represent?",
    "options": [
      "The tool being called",
      "The principal that initiated the business intent",
      "The IP address of the server"
    ],
    "answer": 1,
    "explanation": "Requester maps to who originally asked for the action.",
    "id": "beginner/02-humans-workloads-agents/q-2",
    "courseId": "beginner/02-humans-workloads-agents",
    "courseTitle": "Humans, Workloads and Agents",
    "courseStep": 2,
    "level": "beginner"
  },
  {
    "text": "Why is it dangerous to simply forward a user's token directly to an agent?",
    "options": [
      "Because tokens expire too quickly",
      "Because tokens are heavy",
      "It hides the agent as an actor and gives it all of the user's permissions"
    ],
    "answer": 2,
    "explanation": "Forwarding a bearer token is impersonation, masking the true actor and bypassing least privilege.",
    "id": "beginner/02-humans-workloads-agents/q-3",
    "courseId": "beginner/02-humans-workloads-agents",
    "courseTitle": "Humans, Workloads and Agents",
    "courseStep": 2,
    "level": "beginner"
  },
  {
    "text": "A signed token contains an unknown kid and a jku URL controlled by the caller. What should the purchasing API do?",
    "options": [
      "Deny because key discovery must be configured for a trusted issuer, not redirected by token headers",
      "Fetch the URL to discover the verification key",
      "Decode the claims and accept if the issuer string looks familiar"
    ],
    "answer": 0,
    "explanation": "A key ID selects among issuer-bound trusted keys; received jku or x5u values must not create a trust anchor or SSRF path.",
    "id": "beginner/03-authentication-credentials-tokens/q-1",
    "courseId": "beginner/03-authentication-credentials-tokens",
    "courseTitle": "Authentication, Credentials and Tokens",
    "courseStep": 3,
    "level": "beginner"
  },
  {
    "text": "Which of the following is a type of credential providing evidence of identity?",
    "options": [
      "A username",
      "A signed JWT",
      "A plain text JSON file"
    ],
    "answer": 1,
    "explanation": "Signed JWTs provide cryptographic evidence that can be verified.",
    "id": "beginner/03-authentication-credentials-tokens/q-2",
    "courseId": "beginner/03-authentication-credentials-tokens",
    "courseTitle": "Authentication, Credentials and Tokens",
    "courseStep": 3,
    "level": "beginner"
  },
  {
    "text": "What happens if a bearer token is leaked?",
    "options": [
      "The token automatically self-destructs",
      "Nothing, they are secure by default",
      "It can lead to impersonation because possession is usually enough to use it"
    ],
    "answer": 2,
    "explanation": "Bearer tokens are susceptible to theft and replay.",
    "id": "beginner/03-authentication-credentials-tokens/q-3",
    "courseId": "beginner/03-authentication-credentials-tokens",
    "courseTitle": "Authentication, Credentials and Tokens",
    "courseStep": 3,
    "level": "beginner"
  },
  {
    "text": "A refund agent has the broad `refund_agent` role and proposes a refund for another tenant's order. What should the tool gateway do?",
    "options": [
      "Deny because role eligibility does not satisfy tenant, resource, task, and delegation constraints",
      "Execute because the role permits refunds",
      "Ask the model whether the tenant mismatch is intentional"
    ],
    "answer": 0,
    "explanation": "The PEP must enforce a resource-level, default-deny decision using trusted tenant and delegation data; a broad role alone is insufficient.",
    "id": "beginner/04-authorization-for-agents/q-1",
    "courseId": "beginner/04-authorization-for-agents",
    "courseTitle": "Authorization for Agents",
    "courseStep": 4,
    "level": "beginner"
  },
  {
    "text": "What is the primary difference between authentication and authorization?",
    "options": [
      "They are the exact same concept.",
      "Authentication proves who you are; authorization decides what you can do.",
      "Authorization checks passwords; authentication checks permissions."
    ],
    "answer": 1,
    "explanation": "Authentication verifies identity, authorization checks permissions.",
    "id": "beginner/04-authorization-for-agents/q-2",
    "courseId": "beginner/04-authorization-for-agents",
    "courseTitle": "Authorization for Agents",
    "courseStep": 4,
    "level": "beginner"
  },
  {
    "text": "A manager approved a CAD 450 refund, but the agent changes it to CAD 460 before execution. What is required?",
    "options": [
      "Allow if the model explains the change",
      "Reuse the approval because the order is unchanged",
      "Deny and require a new approval bound to the changed proposal digest"
    ],
    "answer": 2,
    "explanation": "Consequential approval must bind the exact action, resource, amount, tenant, policy version, and lifetime; changing the proposal invalidates it.",
    "id": "beginner/04-authorization-for-agents/q-3",
    "courseId": "beginner/04-authorization-for-agents",
    "courseTitle": "Authorization for Agents",
    "courseStep": 4,
    "level": "beginner"
  },
  {
    "text": "The PDP times out while the agent is about to create a refund. What should this write path do?",
    "options": [
      "Fail closed, record the dependency failure, and create no execution receipt",
      "Fail open to preserve availability",
      "Let the agent apply its cached judgment"
    ],
    "answer": 0,
    "explanation": "A policy outage must not become an authorization bypass for a consequential side effect.",
    "id": "beginner/04-authorization-for-agents/q-4",
    "courseId": "beginner/04-authorization-for-agents",
    "courseTitle": "Authorization for Agents",
    "courseStep": 4,
    "level": "beginner"
  },
  {
    "text": "An MCP server marks a tool as read-only, but the server is not trusted and the tool accepts an arbitrary URL. What should the client gateway do?",
    "options": [
      "Grant automatic access because the annotation says read-only",
      "Treat the annotation as a hint and independently enforce authorization, strict arguments, and egress policy",
      "Ask the language model whether the URL looks safe"
    ],
    "answer": 1,
    "explanation": "MCP annotations are not enforcement guarantees; the trusted gateway must validate and authorize the call and network destination.",
    "id": "beginner/05-least-privilege-tool-access/q-1",
    "courseId": "beginner/05-least-privilege-tool-access",
    "courseTitle": "Least-Privilege Tool Access for Agents",
    "courseStep": 5,
    "level": "beginner"
  },
  {
    "text": "A booking response is lost after the airline may have committed the purchase. What is the safe next step?",
    "options": [
      "Assume the booking failed and issue another approval",
      "Retry with a new operation ID",
      "Reconcile the original stable operation ID and request digest before any retry"
    ],
    "answer": 2,
    "explanation": "Unknown outcomes require reconciliation. Reusing the stable operation ID prevents a transport retry from becoming a duplicate effect.",
    "id": "beginner/05-least-privilege-tool-access/q-2",
    "courseId": "beginner/05-least-privilege-tool-access",
    "courseTitle": "Least-Privilege Tool Access for Agents",
    "courseStep": 5,
    "level": "beginner"
  },
  {
    "text": "A tool argument is schema-valid but targets another tenant's trip. What should happen?",
    "options": [
      "Deny using authoritative resource ownership and tenant policy",
      "Let the tool credential decide after execution",
      "Execute because schema validation passed"
    ],
    "answer": 0,
    "explanation": "Schema validity proves shape, not authority. Resource authorization must run before the downstream call.",
    "id": "beginner/05-least-privilege-tool-access/q-3",
    "courseId": "beginner/05-least-privilege-tool-access",
    "courseTitle": "Least-Privilege Tool Access for Agents",
    "courseStep": 5,
    "level": "beginner"
  },
  {
    "text": "A provisioning workflow requests one capability that is absent from the independently approved agent manifest. What should the lifecycle controller do?",
    "options": [
      "Provision it because the workflow has the provisioner role",
      "Deny it because provisioning must not widen the approved manifest and blueprint",
      "Ask the model whether the new capability is useful"
    ],
    "answer": 1,
    "explanation": "A provisioner may materialize approved intent but cannot expand it. The controller must bind exact manifest capabilities to the approved blueprint.",
    "id": "beginner/06-agent-identity-lifecycle/q-1",
    "courseId": "beginner/06-agent-identity-lifecycle",
    "courseTitle": "Agent Identity Lifecycle",
    "courseStep": 6,
    "level": "beginner"
  },
  {
    "text": "A retirement workflow removed the workload binding and grants, but credential cleanup timed out. What is the correct lifecycle state?",
    "options": [
      "Retired, because most cleanup finished",
      "Active, so the agent can retry itself",
      "Retiring with a visible partial outcome, then resume the same idempotent operation"
    ],
    "answer": 2,
    "explanation": "Retirement is terminal only after every downstream category is verified. Partial cleanup must remain visible and retry under the same stable operation ID.",
    "id": "beginner/06-agent-identity-lifecycle/q-2",
    "courseId": "beginner/06-agent-identity-lifecycle",
    "courseTitle": "Agent Identity Lifecycle",
    "courseStep": 6,
    "level": "beginner"
  },
  {
    "text": "Two sponsor reviews read record version 7 and submit different decisions. The first commits version 8. What should happen to the second?",
    "options": [
      "Reject it as stale and require the reviewer to reload current state",
      "Merge the decisions using a language model",
      "Overwrite version 8 because the sponsor role is valid"
    ],
    "answer": 0,
    "explanation": "Role eligibility does not make stale state current. Optimistic concurrency prevents a last-writer-wins lifecycle decision.",
    "id": "beginner/06-agent-identity-lifecycle/q-3",
    "courseId": "beginner/06-agent-identity-lifecycle",
    "courseTitle": "Agent Identity Lifecycle",
    "courseStep": 6,
    "level": "beginner"
  },
  {
    "text": "Security suspended an agent after suspected credential theft. What is required before reactivation?",
    "options": [
      "A new prompt instructing the agent to be careful",
      "Independent request-bound approval, rotated credential generation, and revalidation of activation invariants",
      "A status toggle by the technical owner"
    ],
    "answer": 1,
    "explanation": "Reactivation is a new authorization decision; it must not restore compromised authority through a simple reversible flag.",
    "id": "beginner/06-agent-identity-lifecycle/q-4",
    "courseId": "beginner/06-agent-identity-lifecycle",
    "courseTitle": "Agent Identity Lifecycle",
    "courseStep": 6,
    "level": "beginner"
  },
  {
    "text": "A pod's attested selectors match two active SPIRE registration entries with different SPIFFE IDs. What should issuance do?",
    "options": [
      "Choose the entry with the longest path",
      "Issue both identities so the pod can choose",
      "Deny issuance and repair the registration collision"
    ],
    "answer": 2,
    "explanation": "Multiple matches make the observed runtime-to-identity mapping ambiguous. The control plane must fail closed and repair the selector policy.",
    "id": "intermediate/01-workload-identity-spiffe-spire/q-1",
    "courseId": "intermediate/01-workload-identity-spiffe-spire",
    "courseTitle": "Workload Identity with SPIFFE and SPIRE",
    "courseStep": 7,
    "level": "intermediate"
  },
  {
    "text": "A partner workload presents a valid X.509-SVID chaining to its configured federated bundle. May it charge a Northstar booking?",
    "options": [
      "Only if local authorization permits that exact authenticated SPIFFE ID, action, and resource",
      "Yes, if both trust domains use SPIRE",
      "Yes, federation grants reciprocal access"
    ],
    "answer": 0,
    "explanation": "Federation makes a partner identity verifiable; it does not create application authority. Local resource authorization remains mandatory.",
    "id": "intermediate/01-workload-identity-spiffe-spire/q-2",
    "courseId": "intermediate/01-workload-identity-spiffe-spire",
    "courseTitle": "Workload Identity with SPIFFE and SPIRE",
    "courseStep": 7,
    "level": "intermediate"
  },
  {
    "text": "A later full-state Workload API response omits an SVID that was present before. What must the client do?",
    "options": [
      "Keep using it until the process restarts",
      "Stop using and remove the omitted SVID from its cache",
      "Merge the response and retain every credential ever observed"
    ],
    "answer": 1,
    "explanation": "Fetch responses represent complete current state. Omission or redaction means the prior SVID is no longer available for use.",
    "id": "intermediate/01-workload-identity-spiffe-spire/q-3",
    "courseId": "intermediate/01-workload-identity-spiffe-spire",
    "courseTitle": "Workload Identity with SPIFFE and SPIRE",
    "courseStep": 7,
    "level": "intermediate"
  },
  {
    "text": "During root rotation, generation-2 SVIDs are issued before verifiers receive the generation-2 root. What is the likely result and correction?",
    "options": [
      "Automatic trust because the SPIFFE ID is unchanged",
      "Authorization bypass; add broader resource roles",
      "Authentication outages; distribute an old-plus-new overlap bundle before new issuance"
    ],
    "answer": 2,
    "explanation": "Identity stability does not bypass cryptographic trust. Ordered bundle overlap lets verifiers trust both generations during the transition.",
    "id": "intermediate/01-workload-identity-spiffe-spire/q-4",
    "courseId": "intermediate/01-workload-identity-spiffe-spire",
    "courseTitle": "Workload Identity with SPIFFE and SPIRE",
    "courseStep": 7,
    "level": "intermediate"
  },
  {
    "text": "A travel agent has a correctly signed access token for the travel API and tries to use it at the payment API. What should the payment API do?",
    "options": [
      "Deny it because the token is not audience/resource-bound to the payment API",
      "Ask the model whether payment is part of the trip",
      "Accept it because the issuer and signature are valid"
    ],
    "answer": 0,
    "explanation": "Signature validity does not override audience. Every resource server must accept only tokens issued for its own canonical resource.",
    "id": "intermediate/02-oauth-oidc-for-agents/q-1",
    "courseId": "intermediate/02-oauth-oidc-for-agents",
    "courseTitle": "OAuth and OpenID Connect for Agents",
    "courseStep": 8,
    "level": "intermediate"
  },
  {
    "text": "A DPoP proof has a valid signature from the public key embedded in that proof, but the access token's cnf.jkt names a different key. What is the correct result?",
    "options": [
      "Allow because either valid key proves possession",
      "Deny because the proof key is not the sender key bound into the token",
      "Remove cnf and treat it as a bearer token"
    ],
    "answer": 1,
    "explanation": "The embedded proof key is not authority. Its RFC 7638 thumbprint must match the access token confirmation claim.",
    "id": "intermediate/02-oauth-oidc-for-agents/q-2",
    "courseId": "intermediate/02-oauth-oidc-for-agents",
    "courseTitle": "OAuth and OpenID Connect for Agents",
    "courseStep": 8,
    "level": "intermediate"
  },
  {
    "text": "An Authorization Code callback contains the correct state and code but an issuer different from the issuer stored with the transaction. What should the client do?",
    "options": [
      "Ignore issuer when PKCE is present",
      "Redeem the code at the new issuer",
      "Deny before token redemption to prevent authorization-server mix-up"
    ],
    "answer": 2,
    "explanation": "PKCE does not replace issuer validation. The response must remain bound to the authorization server selected for that transaction.",
    "id": "intermediate/02-oauth-oidc-for-agents/q-3",
    "courseId": "intermediate/02-oauth-oidc-for-agents",
    "courseTitle": "OAuth and OpenID Connect for Agents",
    "courseStep": 8,
    "level": "intermediate"
  },
  {
    "text": "A Client Credentials token is issued to an agent workload. Which user should the resource server infer?",
    "options": [
      "No user; the client is acting on its own behalf",
      "The most recent interactive user",
      "The agent's owner"
    ],
    "answer": 0,
    "explanation": "Client Credentials represents machine/client authority. A human subject requires an independently validated delegated flow.",
    "id": "intermediate/02-oauth-oidc-for-agents/q-4",
    "courseId": "intermediate/02-oauth-oidc-for-agents",
    "courseTitle": "OAuth and OpenID Connect for Agents",
    "courseStep": 8,
    "level": "intermediate"
  },
  {
    "text": "A child token contains Alice as sub and an outer act for the Flight Specialist with a nested Travel Supervisor. Which actor may drive current actor-based authorization?",
    "options": [
      "Both actors receive the union of their permissions",
      "The Flight Specialist, because the outermost act is current",
      "The Travel Supervisor, because it appeared first in time"
    ],
    "answer": 1,
    "explanation": "RFC 8693 makes the outermost act the current actor. Nested actors are history and must not resurrect prior privilege.",
    "id": "intermediate/03-token-exchange-delegation-impersonation/q-1",
    "courseId": "intermediate/03-token-exchange-delegation-impersonation",
    "courseTitle": "Token Exchange, Delegation, and Impersonation",
    "courseStep": 9,
    "level": "intermediate"
  },
  {
    "text": "An exchange requests an allowed scope but widens the resource from trip:483 to tenant:all. What should the broker do?",
    "options": [
      "Issue the token because scope did not widen",
      "Silently remove the resource and continue",
      "Deny because attenuation applies independently to resource as well as scope"
    ],
    "answer": 2,
    "explanation": "A child must remain within every authority dimension. A valid scope cannot compensate for a widened resource.",
    "id": "intermediate/03-token-exchange-delegation-impersonation/q-2",
    "courseId": "intermediate/03-token-exchange-delegation-impersonation",
    "courseTitle": "Token Exchange, Delegation, and Impersonation",
    "courseStep": 9,
    "level": "intermediate"
  },
  {
    "text": "A legacy impersonation token omits act, so the API sees only Alice as subject. Which compensating control is most important?",
    "options": [
      "Exceptional audience-limited policy with exact single-use approval and broker-side actor evidence",
      "Let the language model record who it believes acted",
      "A longer lifetime so fewer exchanges are needed"
    ],
    "answer": 0,
    "explanation": "Impersonation loses downstream actor attribution. It should be exceptional, tightly bounded, exactly approved, and independently evidenced.",
    "id": "intermediate/03-token-exchange-delegation-impersonation/q-3",
    "courseId": "intermediate/03-token-exchange-delegation-impersonation",
    "courseTitle": "Token Exchange, Delegation, and Impersonation",
    "courseStep": 9,
    "level": "intermediate"
  },
  {
    "text": "A broker times out after issuing a token and receives the same operation ID with one changed scope. What is the safe response?",
    "options": [
      "Return the prior token because operation IDs ignore request contents",
      "Reject an operation-ID conflict; only an exact request may reconcile to the prior result",
      "Issue another token with the new scope"
    ],
    "answer": 1,
    "explanation": "Idempotency binds the stable operation ID to a canonical request digest. Changed retries must not mint different authority.",
    "id": "intermediate/03-token-exchange-delegation-impersonation/q-4",
    "courseId": "intermediate/03-token-exchange-delegation-impersonation",
    "courseTitle": "Token Exchange, Delegation, and Impersonation",
    "courseStep": 9,
    "level": "intermediate"
  },
  {
    "text": "An OpenFGA check confirms the claims agent is assigned and delegated to a task linked to the claim. May the PEP create a payment?",
    "options": [
      "Yes, if the model says the payment is urgent",
      "Yes; the relationship allow is sufficient",
      "Only after the attribute policy also validates workload, tenant, state, risk, amount, exact approval, and obligations"
    ],
    "answer": 2,
    "explanation": "Relationship authority is one required plane. The PEP must also enforce trusted contextual policy and every mandatory obligation before the effect.",
    "id": "intermediate/04-fine-grained-authorization/q-1",
    "courseId": "intermediate/04-fine-grained-authorization",
    "courseTitle": "Fine-Grained Authorization for AI Agents",
    "courseStep": 10,
    "level": "intermediate"
  },
  {
    "text": "A PDP returns allow with an audit obligation that the service does not support. What should the PEP do?",
    "options": [
      "Deny the execution because every mandatory obligation must be fulfilled",
      "Ask the agent to reinterpret the response",
      "Execute and ignore the obligation"
    ],
    "answer": 0,
    "explanation": "An allow response is conditional on the PEP satisfying all mandatory obligations; unsupported obligations fail closed.",
    "id": "intermediate/04-fine-grained-authorization/q-2",
    "courseId": "intermediate/04-fine-grained-authorization",
    "courseTitle": "Fine-Grained Authorization for AI Agents",
    "courseStep": 10,
    "level": "intermediate"
  },
  {
    "text": "A payment proposal changes from $250 to $300 after a supervisor approved its earlier digest. Which result is correct?",
    "options": [
      "Reuse the approval because the task and claim are unchanged",
      "Deny because the approval is not bound to the changed proposal",
      "Allow if the OAuth scope still includes payments:create"
    ],
    "answer": 1,
    "explanation": "Consequential approval must bind the exact proposal, including its parameters and policy version; any material change requires a new approval.",
    "id": "intermediate/04-fine-grained-authorization/q-3",
    "courseId": "intermediate/04-fine-grained-authorization",
    "courseTitle": "Fine-Grained Authorization for AI Agents",
    "courseStep": 10,
    "level": "intermediate"
  },
  {
    "text": "A receiver authenticates a valid SSF SET and is about to return HTTP 202. What must happen first?",
    "options": [
      "The receiver must replace sub_id with sub",
      "The business side effect must finish",
      "The SET must be durably persisted for idempotent asynchronous processing"
    ],
    "answer": 2,
    "explanation": "Push delivery acknowledgement follows validation and durable acceptance; business projection may happen asynchronously and duplicate jti values must remain idempotent.",
    "id": "intermediate/05-dynamic-authorization-cae/q-1",
    "courseId": "intermediate/05-dynamic-authorization-cae",
    "courseTitle": "Dynamic Authorization & Continuous Access Evaluation",
    "courseStep": 11,
    "level": "intermediate"
  },
  {
    "text": "Risk sequence 9 reports low, then the receiver gets previously unseen session sequence 1 saying revoked. What is the safe outcome?",
    "options": [
      "Apply the revocation because ordering is maintained independently per signal domain",
      "Reset every domain to sequence 1",
      "Ignore the revocation because its sequence is lower"
    ],
    "answer": 0,
    "explanation": "One global cursor lets unrelated benign signals suppress critical events. Per-domain ordering preserves the late session restriction.",
    "id": "intermediate/05-dynamic-authorization-cae/q-2",
    "courseId": "intermediate/05-dynamic-authorization-cae",
    "courseTitle": "Dynamic Authorization & Continuous Access Evaluation",
    "courseStep": 11,
    "level": "intermediate"
  },
  {
    "text": "A payment decision was cached for CAD 300 and the agent changes the amount to CAD 900. What should the PEP do?",
    "options": [
      "Reuse the cache because action and resource are unchanged",
      "Miss the cache, invalidate the exact approval, and authorize the changed proposal again",
      "Execute if the token has not expired"
    ],
    "answer": 1,
    "explanation": "A safe decision lease binds the canonical proposal—including amount and purpose—and current trusted state versions.",
    "id": "intermediate/05-dynamic-authorization-cae/q-3",
    "courseId": "intermediate/05-dynamic-authorization-cae",
    "courseTitle": "Dynamic Authorization & Continuous Access Evaluation",
    "courseStep": 11,
    "level": "intermediate"
  },
  {
    "text": "An update is allowed, but a session-revoked event is projected before database commit. What should happen?",
    "options": [
      "Wait until token expiry",
      "Commit because the first decision was valid",
      "Re-authorize at the side-effect boundary and deny"
    ],
    "answer": 2,
    "explanation": "Continuous authorization closes the TOCTOU window by checking current state immediately before a consequential effect.",
    "id": "intermediate/05-dynamic-authorization-cae/q-4",
    "courseId": "intermediate/05-dynamic-authorization-cae",
    "courseTitle": "Dynamic Authorization & Continuous Access Evaluation",
    "courseStep": 11,
    "level": "intermediate"
  },
  {
    "text": "A signal stream has an unrepaired sequence gap. Which policy is defensible?",
    "options": [
      "Use an explicit degraded-mode matrix and fail closed for sensitive writes",
      "Let the model decide whether the missing event matters",
      "Treat the stream as fresh because the last event was signed"
    ],
    "answer": 0,
    "explanation": "Authenticated events can still be incomplete. Gap state must affect authorization until replay or a trusted snapshot repairs freshness.",
    "id": "intermediate/05-dynamic-authorization-cae/q-5",
    "courseId": "intermediate/05-dynamic-authorization-cae",
    "courseTitle": "Dynamic Authorization & Continuous Access Evaluation",
    "courseStep": 11,
    "level": "intermediate"
  },
  {
    "text": "A payment tool was visible in a cached tools/list response, but the task was revoked before tools/call. What should the MCP server do?",
    "options": [
      "Execute because discovery already granted access",
      "Deny by re-authorizing the invocation and current state",
      "Ask the model whether the revocation is relevant"
    ],
    "answer": 1,
    "explanation": "Discovery is an information boundary, not a durable grant. Every invocation and consequential commit must be authorized against current state.",
    "id": "intermediate/06-mcp-tool-authorization/q-1",
    "courseId": "intermediate/06-mcp-tool-authorization",
    "courseTitle": "Authorization for MCP and Tool Servers",
    "courseStep": 12,
    "level": "intermediate"
  },
  {
    "text": "A valid MCP access token has the right payment scope, but its audience names a different API. What should the MCP server do?",
    "options": [
      "Accept it because scope is sufficient",
      "Forward it to the payment API",
      "Reject it because the token is not resource-bound to this MCP server"
    ],
    "answer": 2,
    "explanation": "Issuer and scope do not override audience. The resource server must accept only tokens issued for its canonical resource.",
    "id": "intermediate/06-mcp-tool-authorization/q-2",
    "courseId": "intermediate/06-mcp-tool-authorization",
    "courseTitle": "Authorization for MCP and Tool Servers",
    "courseStep": 12,
    "level": "intermediate"
  },
  {
    "text": "A supervisor approved a CAD 125.00 payment, and the agent changes it to CAD 125.01 before execution. What is required?",
    "options": [
      "Deny and require a new approval bound to the changed proposal digest",
      "Allow if the tool annotation says destructive",
      "Reuse the approval because the payee is unchanged"
    ],
    "answer": 0,
    "explanation": "Consequential approval binds the exact action, arguments, identities, versions, expiry, and operation ID; a one-cent mutation changes the proposal.",
    "id": "intermediate/06-mcp-tool-authorization/q-3",
    "courseId": "intermediate/06-mcp-tool-authorization",
    "courseTitle": "Authorization for MCP and Tool Servers",
    "courseStep": 12,
    "level": "intermediate"
  },
  {
    "text": "The payment API may have committed, but the MCP response was lost. What is the safe retry behavior?",
    "options": [
      "Issue a new operation ID and submit again",
      "Reconcile the same operation ID and exact request digest before another effect",
      "Assume the timeout means failure"
    ],
    "answer": 1,
    "explanation": "An unknown transport outcome is not proof of failure. Exact idempotency and a durable receipt prevent duplicate effects.",
    "id": "intermediate/06-mcp-tool-authorization/q-4",
    "courseId": "intermediate/06-mcp-tool-authorization",
    "courseTitle": "Authorization for MCP and Tool Servers",
    "courseStep": 12,
    "level": "intermediate"
  },
  {
    "text": "A token has every required OAuth scope, but current risk policy denies the payment. Should the 403 request broader scopes?",
    "options": [
      "Only if the client retries three times",
      "Yes, broader scope overrides risk",
      "No; this is a business-policy denial, not OAuth scope insufficiency"
    ],
    "answer": 2,
    "explanation": "Scope step-up is appropriate only when an obtainable missing scope can satisfy access. Risk, tenant, resource, and approval denials must not become privilege growth prompts.",
    "id": "intermediate/06-mcp-tool-authorization/q-5",
    "courseId": "intermediate/06-mcp-tool-authorization",
    "courseTitle": "Authorization for MCP and Tool Servers",
    "courseStep": 12,
    "level": "intermediate"
  },
  {
    "text": "An agent requests the wrong tenant's payment resource and its user authentication is stale. What should happen first?",
    "options": [
      "Deny because resource eligibility failed; stronger authentication cannot make the target permissible",
      "Ask for a broader OAuth scope",
      "Offer user step-up so the stale authentication can be repaired"
    ],
    "answer": 0,
    "explanation": "Eligibility precedes remediation. Tenant or resource-boundary failures are hard denials, not reasons to solicit more assurance or privilege.",
    "id": "intermediate/07-risk-assurance-stepup/q-1",
    "courseId": "intermediate/07-risk-assurance-stepup",
    "courseTitle": "Risk, Assurance, and Step-Up Authorization for Agents",
    "courseStep": 13,
    "level": "intermediate"
  },
  {
    "text": "How does an API correctly request stronger user authentication under RFC 9470?",
    "options": [
      "Silently reinterpret the current token as a higher AAL",
      "Return a 401 Bearer challenge with insufficient_user_authentication and acr_values and/or max_age",
      "Return a JSON body containing the user's password policy"
    ],
    "answer": 1,
    "explanation": "RFC 9470 uses the WWW-Authenticate Bearer challenge. The client then starts a new authorization request using the requested ACR values or maximum authentication age.",
    "id": "intermediate/07-risk-assurance-stepup/q-2",
    "courseId": "intermediate/07-risk-assurance-stepup",
    "courseTitle": "Risk, Assurance, and Step-Up Authorization for Agents",
    "courseStep": 13,
    "level": "intermediate"
  },
  {
    "text": "A signed session names an ACR value the verifier has never configured. How should the authorization service treat it?",
    "options": [
      "Infer AAL3 because the token is signed",
      "Map it to the nearest known assurance level",
      "Fail closed because an unknown ACR has no trusted local semantics"
    ],
    "answer": 2,
    "explanation": "A signature proves who issued the claim, not what an unknown ACR means. The verifier must use an explicit, trusted ACR-to-properties mapping.",
    "id": "intermediate/07-risk-assurance-stepup/q-3",
    "courseId": "intermediate/07-risk-assurance-stepup",
    "courseTitle": "Risk, Assurance, and Step-Up Authorization for Agents",
    "courseStep": 13,
    "level": "intermediate"
  },
  {
    "text": "Two reviewers approve a CAD 25,000 payment, but the agent changes the destination account before commit. Can the approval be reused?",
    "options": [
      "No; the changed proposal digest invalidates the exact approval binding",
      "Yes, if the user's authentication is still fresh",
      "Yes, because the amount and reviewer count are unchanged"
    ],
    "answer": 0,
    "explanation": "Approval must bind the exact action, arguments, identities, risk, policy and signal versions, resource version, expiry, and operation. Any consequential mutation requires a new decision and approval.",
    "id": "intermediate/07-risk-assurance-stepup/q-4",
    "courseId": "intermediate/07-risk-assurance-stepup",
    "courseTitle": "Risk, Assurance, and Step-Up Authorization for Agents",
    "courseStep": 13,
    "level": "intermediate"
  },
  {
    "text": "A user presents a fresh phishing-resistant AAL3 session for an action that policy prohibits. What is the result?",
    "options": [
      "Constrain the action but let it commit",
      "Deny; assurance can satisfy an assurance requirement but cannot override a hard policy boundary",
      "Allow because AAL3 overrides policy"
    ],
    "answer": 1,
    "explanation": "Assurance is evidence used by policy, not a privilege multiplier. Stronger proof of identity does not make a forbidden action eligible.",
    "id": "intermediate/07-risk-assurance-stepup/q-5",
    "courseId": "intermediate/07-risk-assurance-stepup",
    "courseTitle": "Risk, Assurance, and Step-Up Authorization for Agents",
    "courseStep": 13,
    "level": "intermediate"
  },
  {
    "text": "A namespace selector matches the intended claims agent and several unrelated pods. What should the SPIRE operator do?",
    "options": [
      "Make the SVID lifetime longer",
      "Issue the same identity to every matching pod",
      "Add independent selectors such as service account, parent node, and approved image identity"
    ],
    "answer": 2,
    "explanation": "Selectors are identity-issuance policy. A broad selector lets an unrelated workload obtain the privileged SPIFFE ID.",
    "id": "intermediate/08-workload-assurance-runtime-attestation/q-1",
    "courseId": "intermediate/08-workload-assurance-runtime-attestation",
    "courseTitle": "Workload Assurance & Runtime Attestation for Agents",
    "courseStep": 14,
    "level": "intermediate"
  },
  {
    "text": "A JWT workload identity is valid for the claims API. May the payments API accept it because the SPIFFE ID is trusted?",
    "options": [
      "No; the payments API must require and verify its own intended audience",
      "Yes, trust domain membership is sufficient",
      "Only when both APIs share a database"
    ],
    "answer": 0,
    "explanation": "JWT workload credentials are bearer tokens. Signature and subject validity do not replace exact audience validation.",
    "id": "intermediate/08-workload-assurance-runtime-attestation/q-2",
    "courseId": "intermediate/08-workload-assurance-runtime-attestation",
    "courseTitle": "Workload Assurance & Runtime Attestation for Agents",
    "courseStep": 14,
    "level": "intermediate"
  },
  {
    "text": "Which statement correctly follows the IETF RATS model?",
    "options": [
      "The relying party should directly interpret every vendor measurement",
      "A verifier appraises Evidence and issues Attestation Results that the relying party evaluates under policy",
      "Any signed Evidence is automatically an authorization grant"
    ],
    "answer": 1,
    "explanation": "RATS separates attestation evidence, appraisal, attestation results, and relying-party policy so vendor-specific measurements do not become self-asserted authorization facts.",
    "id": "intermediate/08-workload-assurance-runtime-attestation/q-3",
    "courseId": "intermediate/08-workload-assurance-runtime-attestation",
    "courseTitle": "Workload Assurance & Runtime Attestation for Agents",
    "courseStep": 14,
    "level": "intermediate"
  },
  {
    "text": "Cosign verifies a provenance signature, but the statement names an unapproved builder. What should admission policy do?",
    "options": [
      "Replace the builder field after verification",
      "Allow because the signature is cryptographically valid",
      "Deny because provenance content must also satisfy builder, source, build-type, signer, and subject-digest expectations"
    ],
    "answer": 2,
    "explanation": "A valid signature authenticates the statement; policy must still decide whether the signer and every consequential provenance claim are acceptable.",
    "id": "intermediate/08-workload-assurance-runtime-attestation/q-4",
    "courseId": "intermediate/08-workload-assurance-runtime-attestation",
    "courseTitle": "Workload Assurance & Runtime Attestation for Agents",
    "courseStep": 14,
    "level": "intermediate"
  },
  {
    "text": "A workload keeps a valid X.509 identity after runtime monitoring quarantines it. Can it continue an assigned claim update?",
    "options": [
      "No; current quarantine and business authorization are evaluated in addition to workload authentication",
      "Yes, certificate validity overrides runtime state",
      "Only if it uses AAL3"
    ],
    "answer": 0,
    "explanation": "SVID validity proves an identity document is current, not that runtime posture or business authority remains acceptable.",
    "id": "intermediate/08-workload-assurance-runtime-attestation/q-5",
    "courseId": "intermediate/08-workload-assurance-runtime-attestation",
    "courseTitle": "Workload Assurance & Runtime Attestation for Agents",
    "courseStep": 14,
    "level": "intermediate"
  },
  {
    "text": "A critical break-glass entitlement has zero uses in 90 days. What should governance automation do?",
    "options": [
      "Delete it immediately because zero usage proves it is unnecessary",
      "Route it to a risk-aware review with owner, justification, expiry, and emergency-use context",
      "Convert it to a permanent wildcard so it remains available"
    ],
    "answer": 1,
    "explanation": "Usage is evidence for a controlled review, not sufficient authority for an automatic mutation—especially for rare emergency access.",
    "id": "intermediate/09-authorization-governance/q-1",
    "courseId": "intermediate/09-authorization-governance",
    "courseTitle": "Authorization Governance, Delegation & Least Privilege at Scale",
    "courseStep": 15,
    "level": "intermediate"
  },
  {
    "text": "A delegated child grant adds claim.delete even though its parent contains only claim.read. What is the safe result?",
    "options": [
      "Allow if the delegatee has an owner",
      "Allow because the child is more specific",
      "Deny the child because delegated authority must attenuate within the parent's permissions"
    ],
    "answer": 2,
    "explanation": "Every delegation hop must remain within its parent across permissions, resource, time, tenant, task, redelegation, and depth.",
    "id": "intermediate/09-authorization-governance/q-2",
    "courseId": "intermediate/09-authorization-governance",
    "courseTitle": "Authorization Governance, Delegation & Least Privilege at Scale",
    "courseStep": 15,
    "level": "intermediate"
  },
  {
    "text": "An OpenFGA client omits authorization_model_id and therefore evaluates against the latest model. Why is this unsafe during rollout?",
    "options": [
      "It can silently change request semantics; consumers should pin an immutable reviewed model ID",
      "It makes tuples encrypted",
      "It prevents all relationship checks"
    ],
    "answer": 0,
    "explanation": "OpenFGA models are immutable, but using the latest model implicitly can expose a consumer to an unreviewed semantic change. Pin model IDs and stage rollout.",
    "id": "intermediate/09-authorization-governance/q-3",
    "courseId": "intermediate/09-authorization-governance",
    "courseTitle": "Authorization Governance, Delegation & Least Privilege at Scale",
    "courseStep": 15,
    "level": "intermediate"
  },
  {
    "text": "A recertification packet was generated, then the entitlement changed without the reviewer reloading it. What should apply do?",
    "options": [
      "Merge the old and new entitlements",
      "Reject the stale snapshot/version and issue a fresh review packet",
      "Apply the old decision because the reviewer is authorized"
    ],
    "answer": 1,
    "explanation": "Reviewer eligibility does not make stale evidence current. Snapshot digests and optimistic versions close the review time-of-check/time-of-use gap.",
    "id": "intermediate/09-authorization-governance/q-4",
    "courseId": "intermediate/09-authorization-governance",
    "courseTitle": "Authorization Governance, Delegation & Least Privilege at Scale",
    "courseStep": 15,
    "level": "intermediate"
  },
  {
    "text": "An offboarding request times out after revoking some downstream authority. What is the safe retry?",
    "options": [
      "Mark the agent retired because the identity record changed",
      "Create a new operation ID and start over",
      "Reconcile the same operation ID and target, continuing until every entitlement, delegation, exception, workload, tool, MCP, and job surface is verified"
    ],
    "answer": 2,
    "explanation": "Offboarding is a multi-surface idempotent workflow. A stable operation ID prevents duplicate or conflicting cleanup while partial outcomes remain visible.",
    "id": "intermediate/09-authorization-governance/q-5",
    "courseId": "intermediate/09-authorization-governance",
    "courseTitle": "Authorization Governance, Delegation & Least Privilege at Scale",
    "courseStep": 15,
    "level": "intermediate"
  },
  {
    "text": "A valid trace ID on a tool receipt matches an authorization span. What does that prove?",
    "options": [
      "Only that the records carry matching correlation context; producer trust and exact decision/effect binding still require verification",
      "The receipt cannot contain sensitive data",
      "The tool caller had authority"
    ],
    "answer": 0,
    "explanation": "W3C trace context is correlation input, not identity, a capability, a producer signature, or proof that the authorized request was the one executed.",
    "id": "intermediate/10-authorization-observability-audit-analytics/q-1",
    "courseId": "intermediate/10-authorization-observability-audit-analytics",
    "courseTitle": "Authorization Observability & Audit Analytics for Agents",
    "courseStep": 16,
    "level": "intermediate"
  },
  {
    "text": "A denied claim deletion has no execution receipt, while another denied deletion has a signed receipt saying it executed. Which is an actual violation?",
    "options": [
      "Only the first because it lacks a receipt",
      "The executed denied operation; the blocked deny is evidence that enforcement worked",
      "Both denials are equally violations"
    ],
    "answer": 1,
    "explanation": "A deny is a decision outcome, not proof of harm. A trusted enforcement receipt showing the denied effect executed is evidence of an actual forbidden outcome.",
    "id": "intermediate/10-authorization-observability-audit-analytics/q-2",
    "courseId": "intermediate/10-authorization-observability-audit-analytics",
    "courseTitle": "Authorization Observability & Audit Analytics for Agents",
    "courseStep": 16,
    "level": "intermediate"
  },
  {
    "text": "OPA rate limiting drops some decision-log events during an exporter outage. Which metric is most defensible?",
    "options": [
      "Allow rate calculated after removing all errors",
      "A 100% audit-completeness claim based only on received rows",
      "Coverage against an independent protected-operation denominator plus sequence/delivery-gap alerts"
    ],
    "answer": 2,
    "explanation": "Received logs cannot define their own completeness. Use an independent operation population and monitor source sequences and delivery status.",
    "id": "intermediate/10-authorization-observability-audit-analytics/q-3",
    "courseId": "intermediate/10-authorization-observability-audit-analytics",
    "courseTitle": "Authorization Observability & Audit Analytics for Agents",
    "courseStep": 16,
    "level": "intermediate"
  },
  {
    "text": "Cedar reports an evaluation error for one policy but returns Allow because another permit policy matched. What should the application do?",
    "options": [
      "Inspect and record diagnostics, then apply a risk-appropriate policy because Cedar skips erroring policies during evaluation",
      "Ignore diagnostics because Allow always means error-free",
      "Treat the error as an automatic deny in every context"
    ],
    "answer": 0,
    "explanation": "Cedar errors are distinct diagnostic evidence. Applications must decide whether a given error is tolerable or requires fail-closed handling.",
    "id": "intermediate/10-authorization-observability-audit-analytics/q-4",
    "courseId": "intermediate/10-authorization-observability-audit-analytics",
    "courseTitle": "Authorization Observability & Audit Analytics for Agents",
    "courseStep": 16,
    "level": "intermediate"
  },
  {
    "text": "An attacker can rewrite an entire local hash-chained audit store and create a new local chain root. What improves detection?",
    "options": [
      "Longer trace IDs",
      "Signed checkpoints published to an independently controlled system with record count, time window, schema, and policy versions",
      "Removing producer sequence numbers"
    ],
    "answer": 1,
    "explanation": "A hash chain detects changes relative to a trusted root. An independently held signed checkpoint makes rewriting both records and the accepted root harder and visible.",
    "id": "intermediate/10-authorization-observability-audit-analytics/q-5",
    "courseId": "intermediate/10-authorization-observability-audit-analytics",
    "courseTitle": "Authorization Observability & Audit Analytics for Agents",
    "courseStep": 16,
    "level": "intermediate"
  },
  {
    "text": "A red-team case expected CROSS_TENANT_RESOURCE but the request crashed with a JSON parse error. Should the case pass?",
    "options": [
      "Yes, if the HTTP status was not 200",
      "Yes, any failure means the resource was protected",
      "No; the oracle must deny for the expected security invariant so unrelated failures cannot hide a bypass"
    ],
    "answer": 2,
    "explanation": "Stable expected reason codes prove the intended control made the decision. An unrelated parser failure may disappear later and says nothing about tenant enforcement.",
    "id": "intermediate/11-adversarial-authorization-testing/q-1",
    "courseId": "intermediate/11-adversarial-authorization-testing",
    "courseTitle": "Adversarial Authorization Testing for Agents",
    "courseStep": 17,
    "level": "intermediate"
  },
  {
    "text": "A valid token for the analytics API contains claim.read and names the same user. May the claims MCP server accept it?",
    "options": [
      "No; the resource server must verify exact audience/resource binding in addition to signature, issuer, time and scope",
      "Yes, matching subject and scope are sufficient",
      "Only if the model says the request is safe"
    ],
    "answer": 0,
    "explanation": "A valid token can still be substituted into the wrong service. Exact audience validation prevents token confusion and passthrough.",
    "id": "intermediate/11-adversarial-authorization-testing/q-2",
    "courseId": "intermediate/11-adversarial-authorization-testing",
    "courseTitle": "Adversarial Authorization Testing for Agents",
    "courseStep": 17,
    "level": "intermediate"
  },
  {
    "text": "The PDP allowed claim.update at resource version 7, but the claim changed to version 8 before commit. What should the PEP do?",
    "options": [
      "Change the decision record to version 8",
      "Re-authorize or deny because the decision was bound to stale state",
      "Commit because the PDP already returned Allow"
    ],
    "answer": 1,
    "explanation": "Rechecking the bound resource version at the effect boundary closes the authorization TOCTOU window.",
    "id": "intermediate/11-adversarial-authorization-testing/q-3",
    "courseId": "intermediate/11-adversarial-authorization-testing",
    "courseTitle": "Adversarial Authorization Testing for Agents",
    "courseStep": 17,
    "level": "intermediate"
  },
  {
    "text": "An exact retry arrives after an update committed but the response was lost. What is the safe behavior?",
    "options": [
      "Use a new operation ID for every retry",
      "Execute again to ensure success",
      "Reconcile the durable receipt for the same operation ID and exact request digest; reject a changed proposal"
    ],
    "answer": 2,
    "explanation": "Idempotency must bind a stable operation ID to the exact authorized proposal and recorded outcome so unknown transport results do not become duplicate effects.",
    "id": "intermediate/11-adversarial-authorization-testing/q-4",
    "courseId": "intermediate/11-adversarial-authorization-testing",
    "courseTitle": "Adversarial Authorization Testing for Agents",
    "courseStep": 17,
    "level": "intermediate"
  },
  {
    "text": "OPA policy tests report 100% line coverage. What important question remains?",
    "options": [
      "Whether the suite kills security-weakening mutants and covers every PEP/backend path",
      "Whether comments were executed",
      "Whether every request is allowed at least once"
    ],
    "answer": 0,
    "explanation": "Line coverage shows evaluation, not assertion strength or enforcement reach. Mutation tests and path-level PEP tests expose those gaps.",
    "id": "intermediate/11-adversarial-authorization-testing/q-5",
    "courseId": "intermediate/11-adversarial-authorization-testing",
    "courseTitle": "Adversarial Authorization Testing for Agents",
    "courseStep": 17,
    "level": "intermediate"
  },
  {
    "text": "A tool input guardrail says a CAD 750 payment is well formed, and the Agents SDK pauses for human approval. What must still happen before commit?",
    "options": [
      "Execute because guardrail plus approval equals authorization",
      "Re-authorize trusted principal, workload, delegation, tenant, resource, exact arguments, and current state at the effect boundary",
      "Ask the model to confirm the approver's role"
    ],
    "answer": 1,
    "explanation": "Guardrails validate behavior and SDK approval controls run state; neither replaces application authorization or commit-time revalidation.",
    "id": "intermediate/12-integrating-authorization-agents-guardrails/q-1",
    "courseId": "intermediate/12-integrating-authorization-agents-guardrails",
    "courseTitle": "Integrating Authorization with LLMs, Agents & Guardrails",
    "courseStep": 18,
    "level": "intermediate"
  },
  {
    "text": "A supervisor approved payment.create for CAD 750, but the agent changes the amount to CAD 900 before execution. What is the safe outcome?",
    "options": [
      "Allow if the SDK still reports the run as approved",
      "Reuse approval because tool and payee are unchanged",
      "Deny because the changed canonical proposal no longer matches the signed approval"
    ],
    "answer": 2,
    "explanation": "Approval must bind the exact operation, arguments, identities, resource version, decision, policy version, and expiry.",
    "id": "intermediate/12-integrating-authorization-agents-guardrails/q-2",
    "courseId": "intermediate/12-integrating-authorization-agents-guardrails",
    "courseTitle": "Integrating Authorization with LLMs, Agents & Guardrails",
    "courseStep": 18,
    "level": "intermediate"
  },
  {
    "text": "A LangGraph node may have committed an update, but the transport response was lost and the node resumes. What should the node do?",
    "options": [
      "Reconcile the same operation ID and exact proposal digest before any retry",
      "Create a new operation ID so the graph can progress",
      "Repeat the effect immediately"
    ],
    "answer": 0,
    "explanation": "Checkpointing preserves workflow state but does not make external effects exactly-once. Durable receipts and exact idempotency prevent duplicates.",
    "id": "intermediate/12-integrating-authorization-agents-guardrails/q-3",
    "courseId": "intermediate/12-integrating-authorization-agents-guardrails",
    "courseTitle": "Integrating Authorization with LLMs, Agents & Guardrails",
    "courseStep": 18,
    "level": "intermediate"
  },
  {
    "text": "An MCP server receives a valid access token intended for a different MCP server and could forward it to an upstream API. What should it do?",
    "options": [
      "Accept and forward because the signature is valid",
      "Reject the audience mismatch and obtain a separate upstream token instead of token passthrough",
      "Accept if the requested tool was visible in tools/list"
    ],
    "answer": 1,
    "explanation": "Resource/audience binding prevents token substitution, and token passthrough creates confused-deputy risk.",
    "id": "intermediate/12-integrating-authorization-agents-guardrails/q-4",
    "courseId": "intermediate/12-integrating-authorization-agents-guardrails",
    "courseTitle": "Integrating Authorization with LLMs, Agents & Guardrails",
    "courseStep": 18,
    "level": "intermediate"
  },
  {
    "text": "The agent saw payments.create during tool discovery, but its delegation was revoked before tools/call. Which rule applies?",
    "options": [
      "The model may choose whether revocation is relevant",
      "Discovery is a durable authorization grant",
      "Invocation and commit must be independently authorized against current trusted state"
    ],
    "answer": 2,
    "explanation": "Tool filtering reduces exposure; it never replaces per-invocation and pre-effect authorization.",
    "id": "intermediate/12-integrating-authorization-agents-guardrails/q-5",
    "courseId": "intermediate/12-integrating-authorization-agents-guardrails",
    "courseTitle": "Integrating Authorization with LLMs, Agents & Guardrails",
    "courseStep": 18,
    "level": "intermediate"
  },
  {
    "text": "A request has a valid user token and OpenFGA confirms the agent is assigned to the claim, but the executing artifact is not an approved registry release. What should the PEP do?",
    "options": [
      "Deny because human identity, relationship authority, workload, artifact, and contextual policy must all agree",
      "Ask the model whether the artifact is probably safe",
      "Allow because relationship authorization passed"
    ],
    "answer": 0,
    "explanation": "No single plane is sufficient. The logical agent must be bound to an approved workload and artifact before resource authority can be exercised.",
    "id": "intermediate/13-capstone-secure-agent-identity/q-1",
    "courseId": "intermediate/13-capstone-secure-agent-identity",
    "courseTitle": "Capstone: Secure Agent Identity & Authorization Architecture",
    "courseStep": 19,
    "level": "intermediate"
  },
  {
    "text": "A research sub-agent needs knowledge.search for one claim task. Which authority should the orchestrator delegate?",
    "options": [
      "All parent scopes so the child can adapt",
      "Only knowledge.search over the approved knowledge resource, with a shorter lifetime and bounded depth",
      "The user's original bearer token unchanged"
    ],
    "answer": 1,
    "explanation": "Child authority must be a strict subset across action, resource, lifetime, tenant, task, and redelegation dimensions.",
    "id": "intermediate/13-capstone-secure-agent-identity/q-2",
    "courseId": "intermediate/13-capstone-secure-agent-identity",
    "courseTitle": "Capstone: Secure Agent Identity & Authorization Architecture",
    "courseStep": 19,
    "level": "intermediate"
  },
  {
    "text": "The MCP payment tool is visible and the access token has payments:create, but its audience names the claims MCP server. What should happen?",
    "options": [
      "Forward the token to the payment API and let it decide",
      "Execute because discovery and scope both passed",
      "Reject the request because the token is not resource-bound to the payment server"
    ],
    "answer": 2,
    "explanation": "Tool discovery is not a grant, scope does not override audience, and token passthrough creates confused-deputy risk.",
    "id": "intermediate/13-capstone-secure-agent-identity/q-3",
    "courseId": "intermediate/13-capstone-secure-agent-identity",
    "courseTitle": "Capstone: Secure Agent Identity & Authorization Architecture",
    "courseStep": 19,
    "level": "intermediate"
  },
  {
    "text": "An update may have committed, but a workflow checkpoint resumes after the response was lost. What is the safe recovery?",
    "options": [
      "Reconcile the same operation ID and exact proposal digest to a durable receipt before any new effect",
      "Generate a new operation ID so the workflow can continue",
      "Repeat the update immediately"
    ],
    "answer": 0,
    "explanation": "Workflow durability does not make external effects exactly-once. Exact idempotency plus outcome reconciliation prevents duplicates.",
    "id": "intermediate/13-capstone-secure-agent-identity/q-4",
    "courseId": "intermediate/13-capstone-secure-agent-identity",
    "courseTitle": "Capstone: Secure Agent Identity & Authorization Architecture",
    "courseStep": 19,
    "level": "intermediate"
  },
  {
    "text": "Which evidence best supports the claim that a denied payment produced no side effect?",
    "options": [
      "A model trace saying the agent stopped",
      "A correlated signed decision plus an independent protected-operation/receipt ledger showing no execution receipt",
      "The absence of an application error"
    ],
    "answer": 1,
    "explanation": "Decision evidence and effect evidence must be correlated and independently trustworthy; a deny alone is not proof that the backend did nothing.",
    "id": "intermediate/13-capstone-secure-agent-identity/q-5",
    "courseId": "intermediate/13-capstone-secure-agent-identity",
    "courseTitle": "Capstone: Secure Agent Identity & Authorization Architecture",
    "courseStep": 19,
    "level": "intermediate"
  },
  {
    "text": "A claims agent has the correct role and OpenFGA confirms its task relationship, but its risk attributes are stale. What should the hybrid PDP do?",
    "options": [
      "Ask the model to estimate current risk",
      "Allow because two authorization models agree",
      "Deny or return a distinct unavailable/stale outcome according to policy; never treat stale context as current"
    ],
    "answer": 2,
    "explanation": "Role and relationship eligibility do not compensate for missing current ABAC evidence. The application must preserve explicit failure semantics and create no effect.",
    "id": "advanced/01-advanced-authorization-models/q-1",
    "courseId": "advanced/01-advanced-authorization-models",
    "courseTitle": "Advanced Authorization Models for Autonomous Agents",
    "courseStep": 20,
    "level": "advanced"
  },
  {
    "text": "A PDP returns Allow with an optimistic-lock obligation, but the PEP cannot verify the current resource version. What should happen?",
    "options": [
      "Fail closed because the PEP cannot fulfill the decision contract",
      "Reuse the version from the agent proposal",
      "Execute and log the missing check later"
    ],
    "answer": 0,
    "explanation": "An allow is conditional on enforceable constraints and obligations. The PEP remains responsible for the effect boundary.",
    "id": "advanced/01-advanced-authorization-models/q-2",
    "courseId": "advanced/01-advanced-authorization-models",
    "courseTitle": "Advanced Authorization Models for Autonomous Agents",
    "courseStep": 20,
    "level": "advanced"
  },
  {
    "text": "Which change must produce a different authorization cache key?",
    "options": [
      "Only a different subject",
      "A changed purpose, tool, task, risk state, resource version, relationship version, policy version, or approval",
      "Only a different HTTP route"
    ],
    "answer": 1,
    "explanation": "A safe key binds every decision-relevant fact and version so one request cannot inherit another request's authority.",
    "id": "advanced/01-advanced-authorization-models/q-3",
    "courseId": "advanced/01-advanced-authorization-models",
    "courseTitle": "Advanced Authorization Models for Autonomous Agents",
    "courseStep": 20,
    "level": "advanced"
  },
  {
    "text": "A child delegation adds claim.delete while retaining the same tenant, expiry, and call budget. Is it valid?",
    "options": [
      "Yes, if the sub-agent has a stronger model",
      "Yes, because most dimensions remain equal",
      "No, because child actions must be a subset of parent actions"
    ],
    "answer": 2,
    "explanation": "Delegation attenuation applies independently to actions, resources, tools, purposes, tenant, lifetime, budget, depth, and parent binding.",
    "id": "advanced/01-advanced-authorization-models/q-4",
    "courseId": "advanced/01-advanced-authorization-models",
    "courseTitle": "Advanced Authorization Models for Autonomous Agents",
    "courseStep": 20,
    "level": "advanced"
  },
  {
    "text": "Cedar returns Allow from one permit while another policy produced an evaluation error. What should a safety-sensitive application do?",
    "options": [
      "Inspect diagnostics and apply its documented error posture; this course treats diagnostics as denial",
      "Retry until Cedar omits the diagnostic",
      "Assume Allow proves every policy evaluated successfully"
    ],
    "answer": 0,
    "explanation": "Cedar uses skip-on-error semantics. Schema validation reduces runtime errors, but the application must still inspect diagnostics and choose a risk-appropriate response.",
    "id": "advanced/01-advanced-authorization-models/q-5",
    "courseId": "advanced/01-advanced-authorization-models",
    "courseTitle": "Advanced Authorization Models for Autonomous Agents",
    "courseStep": 20,
    "level": "advanced"
  },
  {
    "text": "A child capability is correctly signed by its issuer but adds claim.delete to the parent's knowledge.search grant. What should the verifier do?",
    "options": [
      "Allow because the signature is valid",
      "Deny because the child action set is not a subset of the parent",
      "Allow if the child expires sooner"
    ],
    "answer": 1,
    "explanation": "Signature validity proves who signed the child; attenuation independently proves that the issuer did not widen delegated authority.",
    "id": "advanced/02-cryptographic-delegation-capabilities/q-1",
    "courseId": "advanced/02-cryptographic-delegation-capabilities",
    "courseTitle": "Cryptographic Delegation, Capabilities & Verifiable Provenance for Agents",
    "courseStep": 21,
    "level": "advanced"
  },
  {
    "text": "A DPoP proof has a valid signature and key thumbprint, but its htu names a different API path. What is the correct result?",
    "options": [
      "Replace htu with the requested URI at the gateway",
      "Allow because the key is correct",
      "Deny because sender constraint also binds the proof to the normalized request URI"
    ],
    "answer": 2,
    "explanation": "RFC 9449 verification binds the proof to its key, method, URI, access-token hash, freshness, nonce, and replay identifier.",
    "id": "advanced/02-cryptographic-delegation-capabilities/q-2",
    "courseId": "advanced/02-cryptographic-delegation-capabilities",
    "courseTitle": "Cryptographic Delegation, Capabilities & Verifiable Provenance for Agents",
    "courseStep": 21,
    "level": "advanced"
  },
  {
    "text": "The root capability is revoked while a short-lived child remains unexpired. May the child still be used?",
    "options": [
      "No, because every ancestor is part of the authority chain and parent revocation cascades",
      "Only when the policy engine is unavailable",
      "Yes, because the child has its own signature"
    ],
    "answer": 0,
    "explanation": "A verifier must check revocation and validity for every link; otherwise derived authority can outlive a compromised or withdrawn parent.",
    "id": "advanced/02-cryptographic-delegation-capabilities/q-3",
    "courseId": "advanced/02-cryptographic-delegation-capabilities",
    "courseTitle": "Cryptographic Delegation, Capabilities & Verifiable Provenance for Agents",
    "courseStep": 21,
    "level": "advanced"
  },
  {
    "text": "Why does the resource gateway evaluate current workload, relationship, risk, and policy-version facts after verifying the capability?",
    "options": [
      "Current policy is needed only to format logs",
      "Cryptographic proof preserves issued claims but cannot prove that changing operational facts remain current",
      "The signature becomes invalid whenever risk changes"
    ],
    "answer": 1,
    "explanation": "Portable proof and current policy answer different questions and must be composed at the effect boundary.",
    "id": "advanced/02-cryptographic-delegation-capabilities/q-4",
    "courseId": "advanced/02-cryptographic-delegation-capabilities",
    "courseTitle": "Cryptographic Delegation, Capabilities & Verifiable Provenance for Agents",
    "courseStep": 21,
    "level": "advanced"
  },
  {
    "text": "An evidence log hash-links every event but stores no producer signatures or external checkpoint. What attack remains possible?",
    "options": [
      "No attack remains because hash chains are immutable",
      "Only accidental duplicate IDs can occur",
      "An attacker with write access can replace the entire log and recompute every hash"
    ],
    "answer": 2,
    "explanation": "Hash links reveal local modification only relative to a trusted head. Signed events and an independent checkpoint make a full rewrite detectable.",
    "id": "advanced/02-cryptographic-delegation-capabilities/q-5",
    "courseId": "advanced/02-cryptographic-delegation-capabilities",
    "courseTitle": "Cryptographic Delegation, Capabilities & Verifiable Provenance for Agents",
    "courseStep": 21,
    "level": "advanced"
  },
  {
    "text": "In a leaf → intermediate → trust-anchor entity-statement chain, which identifier must match the locally accepted anchor?",
    "options": [
      "The issuer of the final statement",
      "The leaf's human-readable organization name",
      "The subject of the final statement"
    ],
    "answer": 0,
    "explanation": "The final subordinate statement is issued by the trust anchor about the top intermediate. Its issuer must match a locally configured anchor and key.",
    "id": "advanced/03-cross-domain-identity-federation/q-1",
    "courseId": "advanced/03-cross-domain-identity-federation",
    "courseTitle": "Cross-Domain Identity Federation & Interoperability for Agents",
    "courseStep": 22,
    "level": "advanced"
  },
  {
    "text": "A partner publishes a correctly signed authorization-server configuration, but its metadata violates a superior entity's algorithm policy. What should happen?",
    "options": [
      "Accept it because the leaf signature is valid",
      "Invalidate the chain because resolved metadata policy is integral to trust resolution",
      "Silently replace the algorithm after token issuance"
    ],
    "answer": 1,
    "explanation": "OpenID Federation policy is resolved hierarchically. A subordinate cannot widen a superior constraint, and a conflicting/noncompliant chain is invalid.",
    "id": "advanced/03-cross-domain-identity-federation/q-2",
    "courseId": "advanced/03-cross-domain-identity-federation",
    "courseTitle": "Cross-Domain Identity Federation & Interoperability for Agents",
    "courseStep": 22,
    "level": "advanced"
  },
  {
    "text": "Two approved partners both issue subject agent:research. How should the local system map them?",
    "options": [
      "Use the first token received as the canonical identity",
      "Map both to one local agent because the subject text matches",
      "Preserve issuer and subject as a compound identity so the namespaces remain distinct"
    ],
    "answer": 2,
    "explanation": "Subject identifiers are scoped by their issuer. Dropping the issuer creates namespace collision and cross-partner privilege risk.",
    "id": "advanced/03-cross-domain-identity-federation/q-3",
    "courseId": "advanced/03-cross-domain-identity-federation",
    "courseTitle": "Cross-Domain Identity Federation & Interoperability for Agents",
    "courseStep": 22,
    "level": "advanced"
  },
  {
    "text": "RFC 9728 metadata advertises two authorization servers, but local policy approves only one. What should an MCP client do?",
    "options": [
      "Intersect the advertisement with local policy and use only the uniquely approved issuer",
      "Trust both because the protected resource listed them",
      "Select the first advertised server"
    ],
    "answer": 0,
    "explanation": "Protected Resource Metadata supports discovery, not automatic trust. Secure authorization-server selection remains application policy.",
    "id": "advanced/03-cross-domain-identity-federation/q-4",
    "courseId": "advanced/03-cross-domain-identity-federation",
    "courseTitle": "Cross-Domain Identity Federation & Interoperability for Agents",
    "courseStep": 22,
    "level": "advanced"
  },
  {
    "text": "A partner's X.509-SVID verifies under a newly supplied bundle, but the configured trust-domain-to-bundle fingerprint has not been updated. Is the workload trusted?",
    "options": [
      "Yes, because any valid certificate chain is sufficient",
      "No, because bundle substitution breaks the independently governed trust-domain binding",
      "Yes, if the SPIFFE path contains the word production"
    ],
    "answer": 1,
    "explanation": "SPIFFE federation depends on the protected <trust domain, bundle> association. Rotation requires an explicit, audited local update.",
    "id": "advanced/03-cross-domain-identity-federation/q-5",
    "courseId": "advanced/03-cross-domain-identity-federation",
    "courseTitle": "Cross-Domain Identity Federation & Interoperability for Agents",
    "courseStep": 22,
    "level": "advanced"
  },
  {
    "text": "A registration credential has a valid signature from the approved registry, but it contains evaluation-result claims. Should the verifier accept those claims?",
    "options": [
      "Yes, if the credential has not expired",
      "Yes, because the signature is valid",
      "No, because issuer authority is scoped by credential type, schema, and allowed claims"
    ],
    "answer": 2,
    "explanation": "A proof establishes authorship and integrity. Local issuer policy still limits which credential types and claims that issuer is authoritative for.",
    "id": "advanced/04-agent-attestations-verifiable-credentials/q-1",
    "courseId": "advanced/04-agent-attestations-verifiable-credentials",
    "courseTitle": "Agent Attestations, Verifiable Credentials & Trust Evidence",
    "courseStep": 23,
    "level": "advanced"
  },
  {
    "text": "A holder presents a valid evaluation for release A while the workload attestation measures release B. What should happen?",
    "options": [
      "Deny because evidence for different subjects or releases cannot be composed",
      "Average the assurance levels",
      "Allow because both pieces of evidence are independently valid"
    ],
    "answer": 0,
    "explanation": "Composite assurance requires exact cross-evidence bindings. Valid evidence about another release is not evidence about the running release.",
    "id": "advanced/04-agent-attestations-verifiable-credentials/q-2",
    "courseId": "advanced/04-agent-attestations-verifiable-credentials",
    "courseTitle": "Agent Attestations, Verifiable Credentials & Trust Evidence",
    "courseStep": 23,
    "level": "advanced"
  },
  {
    "text": "An SD-JWT presentation does not disclose the approved claim. Which policy state is correct?",
    "options": [
      "Verified true because the issuer is trusted",
      "Unknown/not disclosed, which grants no privilege",
      "Verified false"
    ],
    "answer": 1,
    "explanation": "Selective disclosure requires tri-state semantics. Absence is neither a verified true nor a verified false value.",
    "id": "advanced/04-agent-attestations-verifiable-credentials/q-3",
    "courseId": "advanced/04-agent-attestations-verifiable-credentials",
    "courseTitle": "Agent Attestations, Verifiable Credentials & Trust Evidence",
    "courseStep": 23,
    "level": "advanced"
  },
  {
    "text": "A credential is unexpired, but a fresh signed status list marks its index revoked. Which state wins?",
    "options": [
      "Whichever response arrived first",
      "The credential expiry because it is embedded in the signed credential",
      "Revocation because current negative status overrides the original validity window"
    ],
    "answer": 2,
    "explanation": "Expiry is only an upper time bound. A credential can be revoked or suspended before it expires.",
    "id": "advanced/04-agent-attestations-verifiable-credentials/q-4",
    "courseId": "advanced/04-agent-attestations-verifiable-credentials",
    "courseTitle": "Agent Attestations, Verifiable Credentials & Trust Evidence",
    "courseStep": 23,
    "level": "advanced"
  },
  {
    "text": "What is the correct relationship between RATS Evidence, an Attestation Result, and authorization?",
    "options": [
      "An attester produces Evidence, a verifier appraises it into a result, and the relying party applies local policy",
      "The model converts Evidence directly into permission",
      "They are three names for the same signed token"
    ],
    "answer": 0,
    "explanation": "RATS separates evidence production, verifier appraisal, and the relying party's trust or authorization decision.",
    "id": "advanced/04-agent-attestations-verifiable-credentials/q-5",
    "courseId": "advanced/04-agent-attestations-verifiable-credentials",
    "courseTitle": "Agent Attestations, Verifiable Credentials & Trust Evidence",
    "courseStep": 23,
    "level": "advanced"
  },
  {
    "text": "A push receiver has authenticated and validated a SET but has not durably persisted it. May it return HTTP 202?",
    "options": [
      "Yes, because signature validation completed",
      "No, because 202 should follow durable acceptance so a crash cannot silently lose acknowledged work",
      "Yes, if projection normally finishes quickly"
    ],
    "answer": 1,
    "explanation": "Validation and business processing are separate. Persist before acknowledgement so retries and restart recovery remain safe.",
    "id": "advanced/05-continuous-adaptive-trust/q-1",
    "courseId": "advanced/05-continuous-adaptive-trust",
    "courseTitle": "Continuous and Adaptive Trust for Autonomous Agents",
    "courseStep": 24,
    "level": "advanced"
  },
  {
    "text": "A SET has a valid identity-provider signature but contains a task-change event. Should the task state change?",
    "options": [
      "Yes, if the task identifier exists",
      "Yes, any trusted signer may update any signal",
      "No, event authority must be scoped by transmitter and event type"
    ],
    "answer": 2,
    "explanation": "A signature proves authorship and integrity, not unlimited authority. The governed task source owns task lifecycle events.",
    "id": "advanced/05-continuous-adaptive-trust/q-2",
    "courseId": "advanced/05-continuous-adaptive-trust",
    "courseTitle": "Continuous and Adaptive Trust for Autonomous Agents",
    "courseStep": 24,
    "level": "advanced"
  },
  {
    "text": "A newer low-risk event is projected before an older high-risk event arrives. Which ordering rule is safest?",
    "options": [
      "Apply the late restriction but do not let stale relaxation erase newer state",
      "Average both events",
      "Ignore every older event"
    ],
    "answer": 0,
    "explanation": "Asymmetric convergence prevents delays from reopening access while preserving late negative evidence.",
    "id": "advanced/05-continuous-adaptive-trust/q-3",
    "courseId": "advanced/05-continuous-adaptive-trust",
    "courseTitle": "Continuous and Adaptive Trust for Autonomous Agents",
    "courseStep": 24,
    "level": "advanced"
  },
  {
    "text": "An agent was allowed at planning time, then its session was revoked while it waited for human review. What protects the final write?",
    "options": [
      "The original allow remains valid",
      "Commit-time reauthorization against current projected state",
      "A longer token lifetime"
    ],
    "answer": 1,
    "explanation": "Long-running work crosses state changes. Reevaluate immediately before the irreversible effect.",
    "id": "advanced/05-continuous-adaptive-trust/q-4",
    "courseId": "advanced/05-continuous-adaptive-trust",
    "courseTitle": "Continuous and Adaptive Trust for Autonomous Agents",
    "courseStep": 24,
    "level": "advanced"
  },
  {
    "text": "What is required before leaving quarantine?",
    "options": [
      "Deletion of the original incident event",
      "One low-risk signal from any source",
      "Governed recovery evidence, fresh attestation, incident clearance, human approval, and elapsed cooldown"
    ],
    "answer": 2,
    "explanation": "Recovery is a new governed decision. It should not be an untrusted score decrease or erasure of evidence.",
    "id": "advanced/05-continuous-adaptive-trust/q-5",
    "courseId": "advanced/05-continuous-adaptive-trust",
    "courseTitle": "Continuous and Adaptive Trust for Autonomous Agents",
    "courseStep": 24,
    "level": "advanced"
  },
  {
    "text": "A caller proves control of a valid DID. What has the verifier established?",
    "options": [
      "The caller controls an authentication key for that DID in this transaction",
      "The caller belongs to an approved organization and may use every tool",
      "Every claim in the DID document is locally trusted"
    ],
    "answer": 0,
    "explanation": "DID control is authentication evidence. Organization membership, delegation, current state, and authorization require separate checks.",
    "id": "advanced/06-decentralized-identity-multi-agent-trust/q-1",
    "courseId": "advanced/06-decentralized-identity-multi-agent-trust",
    "courseTitle": "Decentralized Identity and Trust for Multi-Agent Ecosystems",
    "courseStep": 25,
    "level": "advanced"
  },
  {
    "text": "A DID document contains a valid signing key, but that key appears only in assertionMethod. May it sign a capability invocation?",
    "options": [
      "Yes, because every verification method is interchangeable",
      "No, the verifier must require the key in the relationship for the operation",
      "Yes, if the DID uses did:web"
    ],
    "answer": 1,
    "explanation": "Verification relationships purpose-bind keys. Mere presence in a DID document is insufficient.",
    "id": "advanced/06-decentralized-identity-multi-agent-trust/q-2",
    "courseId": "advanced/06-decentralized-identity-multi-agent-trust",
    "courseTitle": "Decentralized Identity and Trust for Multi-Agent Ecosystems",
    "courseStep": 25,
    "level": "advanced"
  },
  {
    "text": "A signed did:web document advertises a service at a link-local IP address. What should the verifier do?",
    "options": [
      "Convert it to HTTP and retry",
      "Fetch it because the document signature makes the endpoint safe",
      "Treat it as an untrusted hint and enforce independent URL and egress policy"
    ],
    "answer": 2,
    "explanation": "DID services do not authorize network access. Strict SSRF controls still apply.",
    "id": "advanced/06-decentralized-identity-multi-agent-trust/q-3",
    "courseId": "advanced/06-decentralized-identity-multi-agent-trust",
    "courseTitle": "Decentralized Identity and Trust for Multi-Agent Ecosystems",
    "courseStep": 25,
    "level": "advanced"
  },
  {
    "text": "A child capability is signed correctly but expires after its parent. Is the chain valid?",
    "options": [
      "No, delegation must attenuate authority and lifetime",
      "Yes, if both use the same audience",
      "Yes, because the child signature is valid"
    ],
    "answer": 0,
    "explanation": "A delegate cannot create authority beyond the parent's action, resource, context, or validity bounds.",
    "id": "advanced/06-decentralized-identity-multi-agent-trust/q-4",
    "courseId": "advanced/06-decentralized-identity-multi-agent-trust",
    "courseTitle": "Decentralized Identity and Trust for Multi-Agent Ecosystems",
    "courseStep": 25,
    "level": "advanced"
  },
  {
    "text": "Two high-assurance resolvers return different current document digests for the same DID. What is the safest immediate decision?",
    "options": [
      "Choose the result with more keys",
      "Deny and investigate the disagreement under the configured resolver policy",
      "Average the documents"
    ],
    "answer": 1,
    "explanation": "Resolver disagreement is an assurance failure; arbitrary selection can accept substituted or stale key material.",
    "id": "advanced/06-decentralized-identity-multi-agent-trust/q-5",
    "courseId": "advanced/06-decentralized-identity-multi-agent-trust",
    "courseTitle": "Decentralized Identity and Trust for Multi-Agent Ecosystems",
    "courseStep": 25,
    "level": "advanced"
  },
  {
    "text": "A valid five-minute access token is stolen from an agent log. Which control most directly prevents its use by the thief?",
    "options": [
      "Base64-encoding the log",
      "A longer token identifier",
      "Sender constraint that requires proof of the bound private key"
    ],
    "answer": 2,
    "explanation": "mTLS certificate binding or DPoP makes token possession alone insufficient; short lifetime only reduces the remaining window.",
    "id": "advanced/07-non-human-identity-security-key-management/q-1",
    "courseId": "advanced/07-non-human-identity-security-key-management",
    "courseTitle": "Non-Human Identity Security & Key Management for Agents",
    "courseStep": 26,
    "level": "advanced"
  },
  {
    "text": "What must an X.509-SVID verifier check beyond certificate parsing?",
    "options": [
      "Trust bundle signature, exact SPIFFE URI SAN, trust domain, validity, and profile constraints",
      "Only the Common Name",
      "The filename containing the certificate"
    ],
    "answer": 0,
    "explanation": "An SVID is authenticated through the configured bundle and SPIFFE profile, not merely because it is valid X.509 syntax.",
    "id": "advanced/07-non-human-identity-security-key-management/q-2",
    "courseId": "advanced/07-non-human-identity-security-key-management",
    "courseTitle": "Non-Human Identity Security & Key Management for Agents",
    "courseStep": 26,
    "level": "advanced"
  },
  {
    "text": "A signing key enters its rotation overlap period. What may the old key do after the overlap deadline?",
    "options": [
      "Continue signing until manually deleted",
      "Nothing; verification/signing policy must reject it after the governed deadline",
      "Gain access to the new key"
    ],
    "answer": 1,
    "explanation": "Bounded overlap supports rollout, but indefinite acceptance defeats rotation and extends compromise windows.",
    "id": "advanced/07-non-human-identity-security-key-management/q-3",
    "courseId": "advanced/07-non-human-identity-security-key-management",
    "courseTitle": "Non-Human Identity Security & Key Management for Agents",
    "courseStep": 26,
    "level": "advanced"
  },
  {
    "text": "Why should build, deployment, and runtime agents use different identities?",
    "options": [
      "Because OAuth requires three clients",
      "To create more logs",
      "To prevent one compromised phase from inheriting every supply-chain and production permission"
    ],
    "answer": 2,
    "explanation": "Purpose-separated identities constrain blast radius and make policy and evidence meaningful.",
    "id": "advanced/07-non-human-identity-security-key-management/q-4",
    "courseId": "advanced/07-non-human-identity-security-key-management",
    "courseTitle": "Non-Human Identity Security & Key Management for Agents",
    "courseStep": 26,
    "level": "advanced"
  },
  {
    "text": "The SPIFFE Workload API lists WIT-SVID support as incubating and optional. How should a course present it?",
    "options": [
      "As emerging work to evaluate separately from stable production profiles",
      "As an OAuth bearer token",
      "As the mandatory replacement for X.509-SVID"
    ],
    "answer": 0,
    "explanation": "Standards maturity is part of architecture judgment; incubating mechanisms should not be described as universally stable.",
    "id": "advanced/07-non-human-identity-security-key-management/q-5",
    "courseId": "advanced/07-non-human-identity-security-key-management",
    "courseTitle": "Non-Human Identity Security & Key Management for Agents",
    "courseStep": 26,
    "level": "advanced"
  },
  {
    "text": "A high-risk agent proposal was approved, then its workload, tool authority, and model version changed before activation. What should the controller do?",
    "options": [
      "Activate because the agent ID is unchanged",
      "Reject activation because the signed approvals are bound to the original proposal digest",
      "Ask the model whether the changes are material"
    ],
    "answer": 1,
    "explanation": "Approval must bind the exact tenant, workload, artifact/model, authority, policy version, and other decision-relevant proposal fields.",
    "id": "advanced/08-agent-identity-lifecycle-governance/q-1",
    "courseId": "advanced/08-agent-identity-lifecycle-governance",
    "courseTitle": "Agent Identity Lifecycle, Governance & Operational Excellence",
    "courseStep": 27,
    "level": "advanced"
  },
  {
    "text": "Two approval receipts contain the required owner and security role labels, but both were issued by the requester. Is activation valid?",
    "options": [
      "Yes, if the receipts have different identifiers",
      "Yes, because both required labels are present",
      "No, authoritative role verification and segregation of duties must both pass"
    ],
    "answer": 2,
    "explanation": "Role coverage does not replace identity verification or separation of duties; a requester cannot approve their own high-risk proposal.",
    "id": "advanced/08-agent-identity-lifecycle-governance/q-2",
    "courseId": "advanced/08-agent-identity-lifecycle-governance",
    "courseTitle": "Agent Identity Lifecycle, Governance & Operational Excellence",
    "courseStep": 27,
    "level": "advanced"
  },
  {
    "text": "An active agent's owner leaves the organization one day after recertification. Must runtime access wait for the next scheduled review?",
    "options": [
      "No, owner departure is current negative state and should suspend authority immediately",
      "Only if the model reports suspicious behavior",
      "Yes, because the review is still current"
    ],
    "answer": 0,
    "explanation": "Event-driven governance complements scheduled review. Loss of accountable ownership should remove authority before the next periodic cycle.",
    "id": "advanced/08-agent-identity-lifecycle-governance/q-3",
    "courseId": "advanced/08-agent-identity-lifecycle-governance",
    "courseTitle": "Agent Identity Lifecycle, Governance & Operational Excellence",
    "courseStep": 27,
    "level": "advanced"
  },
  {
    "text": "A local audit log has a valid hash chain. What claim is still unsafe?",
    "options": [
      "Changing one retained event without recomputing later hashes is detectable",
      "The chain alone prevents an administrator from deleting or replacing the entire log and root",
      "An independent signed checkpoint can strengthen rewrite detection"
    ],
    "answer": 1,
    "explanation": "A chain provides tamper evidence relative to a trusted anchor; append-only storage, external checkpoints, access separation, retention, and trusted time are still needed.",
    "id": "advanced/08-agent-identity-lifecycle-governance/q-4",
    "courseId": "advanced/08-agent-identity-lifecycle-governance",
    "courseTitle": "Agent Identity Lifecycle, Governance & Operational Excellence",
    "courseStep": 27,
    "level": "advanced"
  },
  {
    "text": "A retirement command disabled the registry row but downstream credentials and queued jobs were not reconciled. What lifecycle result is accurate?",
    "options": [
      "Active, so the agent can clean itself up",
      "Retired, because the primary row changed",
      "A visible partial retiring state until every authority surface is verified revoked"
    ],
    "answer": 2,
    "explanation": "Decommissioning is a multi-surface idempotent workflow. Terminal retirement should follow verified credential, grant, delegation, queue, and workload cleanup.",
    "id": "advanced/08-agent-identity-lifecycle-governance/q-5",
    "courseId": "advanced/08-agent-identity-lifecycle-governance",
    "courseTitle": "Agent Identity Lifecycle, Governance & Operational Excellence",
    "courseStep": 27,
    "level": "advanced"
  },
  {
    "text": "A telemetry envelope has a valid signature, but the KMS source asserts a governance delegation event. Should the event enter detection?",
    "options": [
      "No, the receiver must also enforce source authority for the event type",
      "Yes, if the event has a high risk score",
      "Yes, because any trusted key may assert any event"
    ],
    "answer": 0,
    "explanation": "A signature establishes origin and integrity, not unlimited event authority. The lab allowlists event types per source.",
    "id": "advanced/09-agent-identity-security-posture-threat-defense/q-1",
    "courseId": "advanced/09-agent-identity-security-posture-threat-defense",
    "courseTitle": "Agent Identity Security Posture Management & Threat Defense",
    "courseStep": 28,
    "level": "advanced"
  },
  {
    "text": "The graph-priority index for a path is 64. What does that number mean?",
    "options": [
      "A 64% probability of compromise",
      "A transparent ranking value for comparing paths under the documented formula",
      "The number of breached accounts"
    ],
    "answer": 1,
    "explanation": "The lab deliberately labels the value as an ordinal prioritization index, not calibrated breach probability.",
    "id": "advanced/09-agent-identity-security-posture-threat-defense/q-2",
    "courseId": "advanced/09-agent-identity-security-posture-threat-defense",
    "courseTitle": "Agent Identity Security Posture Management & Threat Defense",
    "courseStep": 28,
    "level": "advanced"
  },
  {
    "text": "A KMS-signing spike is the only signal observed. What is the safest default response?",
    "options": [
      "Ignore all behavioral signals",
      "Immediately disable every KMS key",
      "Queue human review and seek corroboration before a destructive action"
    ],
    "answer": 2,
    "explanation": "Behavioral anomalies are useful but noisy. The lab separates review-only signals from deterministic containment rules.",
    "id": "advanced/09-agent-identity-security-posture-threat-defense/q-3",
    "courseId": "advanced/09-agent-identity-security-posture-threat-defense",
    "courseTitle": "Agent Identity Security Posture Management & Threat Defense",
    "courseStep": 28,
    "level": "advanced"
  },
  {
    "text": "A response retry repeats the same finding and action, but changes the target credential. What should the orchestrator do?",
    "options": [
      "Reject the idempotency-key conflict because the requested effect changed",
      "Execute both targets under one evidence record",
      "Treat it as the same successful retry"
    ],
    "answer": 0,
    "explanation": "Idempotency must bind the exact intended effect; a reused key cannot authorize a different target.",
    "id": "advanced/09-agent-identity-security-posture-threat-defense/q-4",
    "courseId": "advanced/09-agent-identity-security-posture-threat-defense",
    "courseTitle": "Agent Identity Security Posture Management & Threat Defense",
    "courseStep": 28,
    "level": "advanced"
  },
  {
    "text": "A compromised agent has a rotated credential and healthy telemetry again, but an attacker-created OAuth client remains. Is recovery complete?",
    "options": [
      "Yes, because the main credential was rotated",
      "No, persistence removal and the other recovery gates must all be verified",
      "Yes, if posture averages above 80"
    ],
    "answer": 1,
    "explanation": "Recovery is conjunctive and current-state based; an aggregate score cannot hide unresolved persistence.",
    "id": "advanced/09-agent-identity-security-posture-threat-defense/q-5",
    "courseId": "advanced/09-agent-identity-security-posture-threat-defense",
    "courseTitle": "Agent Identity Security Posture Management & Threat Defense",
    "courseStep": 28,
    "level": "advanced"
  },
  {
    "text": "A claims API signs an event labelled as an authorization decision. Is the signature sufficient to admit it?",
    "options": [
      "Yes, if the trace ID already exists",
      "Yes, every trusted producer may assert every event type",
      "No, the collector must also enforce producer authority for that event type"
    ],
    "answer": 2,
    "explanation": "A signature proves origin and integrity; it does not grant a producer authority to assert another component's evidence.",
    "id": "advanced/10-identity-observability-telemetry-forensics/q-1",
    "courseId": "advanced/10-identity-observability-telemetry-forensics",
    "courseTitle": "Identity Observability, Telemetry & Forensics for Agents",
    "courseStep": 29,
    "level": "advanced"
  },
  {
    "text": "A PDP emits a permit event, but no matching PEP event exists. What may the investigator conclude?",
    "options": [
      "Enforcement is unproven and the missing record is an evidence gap",
      "The PEP definitely blocked it",
      "The request definitely reached the resource"
    ],
    "answer": 0,
    "explanation": "Absence of enforcement evidence is a completeness problem, not proof of either external effect.",
    "id": "advanced/10-identity-observability-telemetry-forensics/q-2",
    "courseId": "advanced/10-identity-observability-telemetry-forensics",
    "courseTitle": "Identity Observability, Telemetry & Forensics for Agents",
    "courseStep": 29,
    "level": "advanced"
  },
  {
    "text": "Why preserve both event Timestamp and ObservedTimestamp?",
    "options": [
      "To make every event appear twice",
      "To distinguish source time from collection delay and avoid silently rewriting forensic order",
      "To use one value as an authorization credential"
    ],
    "answer": 1,
    "explanation": "Source and collection clocks answer different questions; causal links and sequence evidence remain necessary.",
    "id": "advanced/10-identity-observability-telemetry-forensics/q-3",
    "courseId": "advanced/10-identity-observability-telemetry-forensics",
    "courseTitle": "Identity Observability, Telemetry & Forensics for Agents",
    "courseStep": 29,
    "level": "advanced"
  },
  {
    "text": "A retained hash chain verifies after the final two entries are deleted. What additional control detects the truncation?",
    "options": [
      "Sorting the remaining records again",
      "A longer trace ID",
      "An independently stored signed checkpoint binding the expected count and root"
    ],
    "answer": 2,
    "explanation": "A valid prefix can still verify locally. An external checkpoint binds completeness to an expected count and root.",
    "id": "advanced/10-identity-observability-telemetry-forensics/q-4",
    "courseId": "advanced/10-identity-observability-telemetry-forensics",
    "courseTitle": "Identity Observability, Telemetry & Forensics for Agents",
    "courseStep": 29,
    "level": "advanced"
  },
  {
    "text": "OpenTelemetry GenAI tool arguments may contain customer data and secrets. What is the safest default?",
    "options": [
      "Record low-cardinality metadata and make content capture explicit, minimized, and access-controlled",
      "Hash the whole prompt with an unkeyed hash",
      "Capture all content because traces are internal"
    ],
    "answer": 0,
    "explanation": "Current GenAI conventions flag content-bearing attributes as sensitive or opt-in; minimization should precede export.",
    "id": "advanced/10-identity-observability-telemetry-forensics/q-5",
    "courseId": "advanced/10-identity-observability-telemetry-forensics",
    "courseTitle": "Identity Observability, Telemetry & Forensics for Agents",
    "courseStep": 29,
    "level": "advanced"
  },
  {
    "text": "A required artifact is missing but the inventory says the control is configured. What status is defensible?",
    "options": [
      "Pass",
      "Indeterminate and review",
      "Not applicable"
    ],
    "answer": 1,
    "explanation": "Configuration claims do not replace required evidence; missing proof must remain visible.",
    "id": "advanced/11-compliance-audit-forensic-readiness/q-1",
    "courseId": "advanced/11-compliance-audit-forensic-readiness",
    "courseTitle": "Compliance, Audit & Forensic Readiness for Agent Identity",
    "courseStep": 30,
    "level": "advanced"
  },
  {
    "text": "Why does a valid control exception remain an exception rather than become a pass?",
    "options": [
      "Because exceptions cannot have compensating controls",
      "To avoid recording an approver",
      "To preserve the underlying deviation, approval scope, expiry, and residual risk"
    ],
    "answer": 2,
    "explanation": "An exception is accepted risk around a failed requirement, not evidence that the requirement operated normally.",
    "id": "advanced/11-compliance-audit-forensic-readiness/q-2",
    "courseId": "advanced/11-compliance-audit-forensic-readiness",
    "courseTitle": "Compliance, Audit & Forensic Readiness for Agent Identity",
    "courseStep": 30,
    "level": "advanced"
  },
  {
    "text": "What does a custody hash chain fail to prove by itself?",
    "options": [
      "That no valid suffix was truncated unless an expected terminal root or count is independently bound",
      "That an edited early entry breaks later links",
      "That each retained entry links to its predecessor"
    ],
    "answer": 0,
    "explanation": "A shortened prefix can still be internally valid; the signed pack binds the expected root and artifact set.",
    "id": "advanced/11-compliance-audit-forensic-readiness/q-3",
    "courseId": "advanced/11-compliance-audit-forensic-readiness",
    "courseTitle": "Compliance, Audit & Forensic Readiness for Agent Identity",
    "courseStep": 30,
    "level": "advanced"
  },
  {
    "text": "Why version framework mappings independently from control tests?",
    "options": [
      "To eliminate auditor judgment",
      "To detect mapping drift when standards or assessment procedures change",
      "To make every control automatically satisfy every framework"
    ],
    "answer": 1,
    "explanation": "Mappings are traceability aids whose sources and versions change independently from local implementations.",
    "id": "advanced/11-compliance-audit-forensic-readiness/q-4",
    "courseId": "advanced/11-compliance-audit-forensic-readiness",
    "courseTitle": "Compliance, Audit & Forensic Readiness for Agent Identity",
    "courseStep": 30,
    "level": "advanced"
  },
  {
    "text": "Which sampling report is most defensible?",
    "options": [
      "The dashboard is green",
      "Ten agents passed",
      "A 12-of-40 risk-weighted sample with population lineage, risk distribution, exclusions, and critical coverage"
    ],
    "answer": 2,
    "explanation": "Sampling conclusions require a known population, selection method, denominator, and coverage by relevant risk slices.",
    "id": "advanced/11-compliance-audit-forensic-readiness/q-5",
    "courseId": "advanced/11-compliance-audit-forensic-readiness",
    "courseTitle": "Compliance, Audit & Forensic Readiness for Agent Identity",
    "courseStep": 30,
    "level": "advanced"
  },
  {
    "text": "A payment decision returns approval_required. A supervisor approves the exact request. What should happen next?",
    "options": [
      "Submit the approval evidence and have the PDP evaluate again, producing a new receipt-bound decision",
      "Let the agent execute because the approval UI succeeded",
      "Mutate the original decision to allow"
    ],
    "answer": 0,
    "explanation": "Approval is new evidence, not a retroactive change to a denial or step-up result. Exact intent and policy binding must be verified before a new allow is issued.",
    "id": "advanced/12-secure-compliant-resilient-agent-identity-platform/q-1",
    "courseId": "advanced/12-secure-compliant-resilient-agent-identity-platform",
    "courseTitle": "Capstone: Secure, Compliant & Resilient Enterprise Agent Identity Platform",
    "courseStep": 31,
    "level": "advanced"
  },
  {
    "text": "A claim update may have committed, but the PEP lost the response. What is the safe retry behavior?",
    "options": [
      "Generate a new operation ID and repeat the update",
      "Reconcile the original operation ID and request digest against the protected effect ledger before any new write",
      "Ask the model whether the update probably succeeded"
    ],
    "answer": 1,
    "explanation": "Idempotency prevents duplicate execution only when the logical operation and exact request remain bound; ambiguous outcomes require reconciliation.",
    "id": "advanced/12-secure-compliant-resilient-agent-identity-platform/q-2",
    "courseId": "advanced/12-secure-compliant-resilient-agent-identity-platform",
    "courseTitle": "Capstone: Secure, Compliant & Resilient Enterprise Agent Identity Platform",
    "courseStep": 31,
    "level": "advanced"
  },
  {
    "text": "A partner workload presents a valid SVID. What additional checks are required before it may search Northstar knowledge?",
    "options": [
      "Only compare the partner organization name",
      "None; a valid foreign identity is an authorization grant",
      "Verify the governed trust-domain bundle and freshness, then intersect partner identity with local action, resource, delegation, and relationship policy"
    ],
    "answer": 2,
    "explanation": "Federation authenticates a scoped foreign identity. Local authorization and the protected trust-domain-to-bundle binding still apply.",
    "id": "advanced/12-secure-compliant-resilient-agent-identity-platform/q-3",
    "courseId": "advanced/12-secure-compliant-resilient-agent-identity-platform",
    "courseTitle": "Capstone: Secure, Compliant & Resilient Enterprise Agent Identity Platform",
    "courseStep": 31,
    "level": "advanced"
  },
  {
    "text": "A hash-linked audit log verifies after its last two records are removed. Which control detects that truncation?",
    "options": [
      "An independently stored signed checkpoint binding the expected record count and terminal root",
      "Re-sorting the remaining events",
      "A longer event name"
    ],
    "answer": 0,
    "explanation": "A valid prefix can remain internally consistent. An independent count-and-root checkpoint adds completeness evidence.",
    "id": "advanced/12-secure-compliant-resilient-agent-identity-platform/q-4",
    "courseId": "advanced/12-secure-compliant-resilient-agent-identity-platform",
    "courseTitle": "Capstone: Secure, Compliant & Resilient Enterprise Agent Identity Platform",
    "courseStep": 31,
    "level": "advanced"
  },
  {
    "text": "Which result is a defensible capstone release gate?",
    "options": [
      "The happy-path notebook ran once",
      "All labelled adversarial cases match expected terminal states, false allows and approval bypasses are zero, and required effect and evidence artifacts verify",
      "The LLM reports that the architecture is secure"
    ],
    "answer": 1,
    "explanation": "A release gate should combine negative testing with independently verifiable decision, effect, telemetry, and evidence artifacts.",
    "id": "advanced/12-secure-compliant-resilient-agent-identity-platform/q-5",
    "courseId": "advanced/12-secure-compliant-resilient-agent-identity-platform",
    "courseTitle": "Capstone: Secure, Compliant & Resilient Enterprise Agent Identity Platform",
    "courseStep": 31,
    "level": "advanced"
  }
];
