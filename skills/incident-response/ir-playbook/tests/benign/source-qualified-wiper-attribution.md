# Benign: Source-Qualified Wiper Attribution

```yaml
incident_id: IR-2026-062
category: destructive_wiper
observed_evidence:
  - Intune remote wipe commands observed in tenant audit logs
  - affected device count from MDM export
actor_claim:
  actor: Handala
  source_confidence: actor_claim
  attribution_status: claimed
trusted_ti:
  source: Palo Alto Unit 42 profile
  attribution_status: assessed
executive_update: destructive activity confirmed; attribution remains assessed, not confirmed
operational_action: preserve identity, MDM, cloud-admin, and endpoint evidence
```

This should not be flagged because operational response is tied to observed
evidence while actor identity and motive are clearly source-qualified.
