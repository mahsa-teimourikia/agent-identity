package system.log

import rego.v1

# Teaching policy for OPA's decision-log hook. Keep the safe correlation and
# policy-version fields; redact credentials and high-risk business content.
# Production deployments should generate this list from a data-classification
# contract and test it whenever request schemas change.

mask contains {"op": "upsert", "path": "/input/token", "value": "**REDACTED**"} if {
    input.input.token
}

mask contains {"op": "upsert", "path": "/input/authorization", "value": "**REDACTED**"} if {
    input.input.authorization
}

mask contains {"op": "upsert", "path": "/input/tool/arguments/customer_ssn", "value": "**REDACTED**"} if {
    input.input.tool.arguments.customer_ssn
}

mask contains {"op": "remove", "path": "/input/tool/arguments/raw_prompt"} if {
    input.input.tool.arguments.raw_prompt
}

mask contains {"op": "remove", "path": "/input/user/email"} if {
    input.input.user.email
}

# Only low-value health-check decisions may be dropped. Authorization denies,
# high-risk decisions, and evaluator errors remain mandatory audit evidence.
drop if {
    input.input.operation == "health.check"
    input.result == true
    input.input.risk_tier == "R0"
    not input.error
}
