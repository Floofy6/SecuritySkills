# Vulnerable: privacy criteria scored as SOC 2 gaps when Privacy is out of scope

## Input Context

```yaml
planned_soc2_report:
  categories:
    - Security
    - Availability
  service_commitments:
    - protected admin access
    - change control
    - incident response
    - 99.9 percent production availability
privacy_obligations:
  privacy_notice: present
  gdpr_ccpa_intake: handled by legal program
gap_matrix_output:
  P1.1:
    scope_status: In Scope
    score: 1
    gap: No SOC 2-ready privacy notice evidence.
```

## Expected Result

Do not score P1.1-P1.8 as SOC 2 report-scope gaps when Privacy is not selected for the report. Record privacy obligations as `Out of scope but relevant` observations with a legal/privacy owner and separate follow-up.
