# Benign: scored criteria trace to selected commitments and requirements

## Input Context

```yaml
planned_soc2_report:
  categories:
    - Security
    - Availability
  management_assertion: draft-v3
  system_boundary:
    product: B2B admin SaaS
    environments:
      - paid production tenants
service_commitments:
  SC-001:
    text: 99.9 percent production availability for paid tenants
    source: MSA/SLA
    requirements:
      - monitored backups
      - recovery test evidence
      - capacity monitoring
gap_matrix_output:
  A1.2:
    scope_status: In Scope
    service_commitment: SC-001
    system_requirement: monitored backups and recovery objectives
    scope_source: MSA/SLA plus management assertion
    scope_confidence: Strong
    score: 3
```

## Expected Result

This is a valid in-scope score because Availability is selected, the row traces to a service commitment and system requirement, and the product/environment boundary is explicit.
