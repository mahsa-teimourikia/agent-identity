package agent.claims_test
import data.agent.claims

test_read_allowed if {
  claims.allow with input as {
    "user":{"id":"alice"},
    "agent":{"id":"claims-agent"},
    "action":"claim.read",
    "resource":{"claim_id":"483"},
    "task":{"active":true,"claim_id":"483"},
    "context":{}
  }
}

test_wrong_claim_denied if {
  not claims.allow with input as {
    "user":{"id":"alice"},
    "agent":{"id":"claims-agent"},
    "action":"claim.read",
    "resource":{"claim_id":"999"},
    "task":{"active":true,"claim_id":"483"},
    "context":{}
  }
}
