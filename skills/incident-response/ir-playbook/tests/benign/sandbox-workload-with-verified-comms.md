# Benign: Sandbox Workload With Verified Communications

## Scenario

```yaml
incident_type: suspected_web_shell
affected_scope: single_dev_vm
cloud_account:
  tier: sandbox
  production_trust_path: none_found
  data_classification: synthetic_test_data
control_plane:
  organization_admin_activity: none
  iam_policy_changes: none
  audit_log_status: enabled
  federation_changes: none
communications:
  primary_chat: company_slack
  primary_chat_trust: trusted
  out_of_band_bridge: tested
  identity_provider_in_scope: false
preserve_before_mutate:
  vm_disk_snapshot: captured
  cloud_audit_log_export: captured
  iam_policy_snapshot: not_applicable
```

## Expected Handling

- Classify as workload-only unless new evidence shows production trust or control-plane activity.
- Keep severity calibrated to SEV-3 or SEV-4 when business impact and data impact remain low.
- Record the tested out-of-band bridge, but normal sanitized updates can continue over trusted chat.
- Preserve the workload and audit-log evidence before rebuild or deletion.

