package agent.identity.compliance
default compliant := false
compliant if {
  input.registered
  input.owner != ""
  input.environment == "prod"
  input.credential.type != "static_api_key"
  input.credential.lifetime_minutes <= 60
  input.last_review_age_days <= 90
  input.telemetry.authz_enabled
  input.telemetry.tool_enabled
}
violations contains "missing owner" if { input.owner == "" }
violations contains "static production credential" if {
  input.environment == "prod"
  input.credential.type == "static_api_key"
}
violations contains "overdue recertification" if { input.last_review_age_days > 90 }
