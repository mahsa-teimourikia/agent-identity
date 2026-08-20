package system.log

# Example OPA decision-log privacy policy.
# Never treat this sample as a complete enterprise classification policy.

mask contains {"op": "upsert", "path": "/input/token", "value": "**REDACTED**"} if {
    input.input.token
}

mask contains {"op": "upsert", "path": "/input/tool/arguments/customer_ssn", "value": "**REDACTED**"} if {
    input.input.tool.arguments.customer_ssn
}

mask contains {"op": "remove", "path": "/input/user/email"} if {
    input.input.user.email
}
