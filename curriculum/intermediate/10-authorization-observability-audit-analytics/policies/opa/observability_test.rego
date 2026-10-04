package system.log

import rego.v1

base := {
    "input": {
        "operation": "claim.read",
        "risk_tier": "R2",
        "request_digest": "safe-digest",
        "policy_version": "claims-authz/2026-10-04",
        "token": "bearer-secret",
        "authorization": "Bearer secret",
        "user": {"email": "caseworker@example.test"},
        "tool": {"arguments": {
            "customer_ssn": "000-00-0000",
            "raw_prompt": "private claim narrative",
        }},
    },
    "result": true,
}

test_masks_all_classified_fields if {
    patches := mask with input as base
    count(patches) == 5
}

test_masks_token if {
    patches := mask with input as base
    some patch in patches
    patch.path == "/input/token"
    patch.value == "**REDACTED**"
}

test_masks_authorization_header if {
    patches := mask with input as base
    some patch in patches
    patch.path == "/input/authorization"
}

test_removes_raw_prompt if {
    patches := mask with input as base
    some patch in patches
    patch.path == "/input/tool/arguments/raw_prompt"
    patch.op == "remove"
}

test_keeps_safe_request_digest if {
    patches := mask with input as base
    not {"op": "remove", "path": "/input/request_digest"} in patches
}

test_drops_only_successful_r0_health_check if {
    drop with input as {"input": {"operation": "health.check", "risk_tier": "R0"}, "result": true}
}

test_keeps_denied_health_check if {
    not drop with input as {"input": {"operation": "health.check", "risk_tier": "R0"}, "result": false}
}

test_keeps_high_risk_health_check if {
    not drop with input as {"input": {"operation": "health.check", "risk_tier": "R4"}, "result": true}
}

test_keeps_policy_evaluation_error if {
    not drop with input as {
        "input": {"operation": "health.check", "risk_tier": "R0"},
        "result": false,
        "error": {"message": "evaluation failed"},
    }
}

test_keeps_business_decisions if {
    not drop with input as base
}
