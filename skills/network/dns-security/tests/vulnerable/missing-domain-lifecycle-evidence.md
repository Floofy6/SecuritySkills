# Vulnerable: DNSSEC Review Missing Domain Lifecycle Evidence

## Scenario

A report gives a public domain a strong DNS posture because DNSSEC and protective DNS are present, but it never proves registrar control, registry lock status, CAA policy, parent/child delegation consistency, or provider hosted-zone ownership.

## Evidence

```yaml
domain: example.com
scope: public apex plus app.example.com delegation
dnssec:
  signed: true
  ds_in_parent: true
protective_dns:
  enabled: true
  logs_forwarded_to_siem: true
missing_evidence:
  registrar_identity: unknown
  registrar_mfa: unknown
  registrar_client_locks: unknown
  registry_server_locks: unknown
  nameserver_change_audit: missing
  caa_records: not_checked
  ct_monitoring: unknown
  ca_account_controls: unknown
delegation:
  parent_ns:
    - ns-111.awsdns-01.net
    - ns-222.awsdns-02.org
  child_provider_zone_id: missing
  child_authoritative_query: not_run
  provider_account_owner: unknown
records:
  - name: old.example.com
    type: CNAME
    value: old-customer.deleted-saas.example
    provider_ownership: unknown
```

## Expected Skill Behavior

- Do not report a strong overall public-DNS posture from DNSSEC and protective DNS alone.
- Mark registrar, registry, CAA, CT/CA, parent/child NS, provider-account, and takeover evidence as `Not Evaluable` with specific `DNS-NE-*` reason codes.
- Escalate stale public delegation or dangling CNAME/NS records only when live and provider evidence proves a reclaimable target; otherwise record partial evidence and required follow-up.
