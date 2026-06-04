# CVSS / SSVC Boundary Fixtures

These fixtures calibrate `scanner-tuning` severity overrides so CVSS v4.0
Environmental vectors stay separate from non-CVSS prioritization decisions.

## Vulnerable Fixture 1: SSVC Label Used As CVSS Justification

```text
Severity Override Record:
- Scanner:             ExampleScanner
- Plugin/Check ID:     12345
- CVE ID:              CVE-2026-0001
- Asset:               dev-api.example.com
- Original Severity:   Critical, CVSS 9.8
- Overridden Severity: Medium, CVSS 5.4
- Override Direction:  Down
- Justification:       Mission Prevalence = Minimal (SSVC); non-production
- CVSS 4.0 Vector:     CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L/IR:L/AR:L
```

Expected outcome:

- Reject the severity downgrade unless the report also proves that `CR`, `IR`,
  and `AR` are lower for the vulnerable system.
- Flag `Mission Prevalence` as a non-CVSS prioritization label, not a valid CVSS
  Environmental metric.
- Require separate `Priority Context` if SSVC is used.

## Vulnerable Fixture 2: Business Urgency Inside The CVSS Field

```text
Severity Override Record:
- Scanner:             ExampleScanner
- Plugin/Check ID:     67890
- CVE ID:              CVE-2026-0002
- Asset:               reporting.internal
- Original Severity:   High, CVSS 8.1
- Overridden Severity: Low, CVSS 3.2
- Justification:       asset criticality low; owner accepted risk
- CVSS 4.0 Vector:     Business Priority: Low; SLA: next quarter
```

Expected outcome:

- Reject the vector because it is not a CVSS v4.0 vector string.
- Keep asset criticality and owner risk acceptance outside the CVSS score.
- Ask for valid Modified Base Metric or Security Requirement evidence before
  changing severity.

## Benign Fixture 1: Valid Environmental Downgrade With Metric Evidence

```text
Severity Override Record:
- Scanner:             ExampleScanner
- Plugin/Check ID:     24680
- CVE ID:              CVE-2026-0003
- Asset:               isolated-lab-host.local
- Original Severity:   High, CVSS 8.8
- Overridden Severity: Medium, CVSS-BE documented by calculator
- Override Direction:  Down
- Justification:       MAV:P because the service is reachable only through a locked lab console; CR:L/IR:L/AR:L because asset inventory shows no production data, customer traffic, secrets, or privileged integrations.
- CVSS 4.0 Vector:     CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:P/CR:L/IR:L/AR:L
- Priority Context:    SSVC Track due no exploitation and lab-only exposure
```

Expected outcome:

- Accept the CVSS severity override if the cited isolation and data-classification
  evidence is present.
- Keep the SSVC priority decision in `Priority Context`, not in the CVSS vector.

## Benign Fixture 2: Priority Change Without Severity Change

```text
Severity Override Record:
- Scanner:             ExampleScanner
- Plugin/Check ID:     13579
- CVE ID:              CVE-2026-0004
- Asset:               customer-facing-api
- Original Severity:   High, CVSS 8.2
- Overridden Severity: High, unchanged
- Override Direction:  None
- Justification:       No valid CVSS Environmental metric changes are proven.
- CVSS 4.0 Vector:     CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
- Priority Context:    SSVC Attend because exploitation is not observed but the asset is internet-facing and customer-impacting.
```

Expected outcome:

- Preserve the technical severity score.
- Use priority context only to drive remediation queue placement and due date.
