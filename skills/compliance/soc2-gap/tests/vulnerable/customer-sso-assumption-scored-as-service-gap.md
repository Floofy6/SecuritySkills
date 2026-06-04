# Vulnerable: customer-managed SSO assumption scored as a service-organization gap

## Input Context

```yaml
control_area: logical_access
service_organization_controls:
  - SSO support
  - MFA support
  - IP allowlisting
  - tenant audit logs
customer_user_entity_responsibilities:
  - configure SSO for their tenant
  - review tenant users quarterly
  - protect tenant-generated integration credentials
current_gap_output:
  criteria: CC6.1
  score: 1
  gap: Customers have not enabled SSO or MFA.
```

## Expected Result

Separate the finding into a user-entity assumption register. Score a service-organization gap only if the service organization failed to provide the promised capability, secure default, monitoring, or disclosure evidence.
