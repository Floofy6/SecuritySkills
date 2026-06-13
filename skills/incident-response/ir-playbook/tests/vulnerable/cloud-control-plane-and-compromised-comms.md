# Vulnerable: Cloud Control Plane With Compromised Communications

## Scenario

```yaml
incident_type: suspicious_console_login
principal: OrganizationAccountAccessRole
cloud_account:
  tier: production
  production_trust_path: present
  affected_accounts:
    - prod
    - security-log-archive
control_plane_actions:
  - iam:CreateAccessKey
  - organizations:DetachPolicy
  - cloudtrail:StopLogging
communications:
  primary_chat: company_slack
  primary_email: corporate_email
  identity_provider_in_scope: true
  out_of_band_bridge: untested
proposed_containment:
  - delete_compromised_admin_user
  - detach_suspicious_policy
missing_preservation:
  - iam_policy_snapshot
  - active_session_export
  - access_key_inventory
  - federation_config_snapshot
  - cloudtrail_event_export
  - recovery_admin_path
```

## Expected Finding

- Escalate as cloud/SaaS control-plane suspected or confirmed compromise.
- Do not coordinate sensitive containment timing over SSO-backed chat or corporate email until channel trust is established.
- Establish and test an out-of-band communications path before executive/legal/containment coordination.
- Preserve IAM, session, key, federation, audit-log, policy, and recovery-admin evidence before destructive identity or policy changes.

