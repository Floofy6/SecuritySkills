# Vulnerable: Mobile Device Collection Without Lock-State Decision

```yaml
incident_id: IR-2026-055
evidence_source: employee_phone
requested_action: collect messages and authenticator evidence
device_platform: iOS
legal_authority: counsel-approved employee device collection
lock_state: unknown
network_state: online
remote_wipe_risk: unknown
acquisition_method: "use whatever tool is available"
tool_version: missing
output_hash: missing
```

This should be flagged because a mobile plan that does not record lock state,
network isolation, remote-wipe risk, acquisition method, tool provenance, and
output hashing can destroy or materially alter evidence.
