# ISO 27001 SoA Risk Treatment Traceability - Benign

## Scenario

An organization marks Annex A control A.8.15 Logging as implemented in the
Statement of Applicability and provides traceability to the risk treatment
decision that selected the control.

```text
Control: A.8.15 Logging
Applicable: Yes
Requirement Driver / Risk ID: R-042 privileged-access-monitoring / customer contract LOG-7
Treatment Option: mitigate
Control Owner: Security Operations Manager
Evidence Type / Source: operating evidence, SIEM alert test report SIEM-2026-04-22
Evidence Freshness: 2026-04-22
Residual Risk Approval: risk owner approved on 2026-04-29, review due 2026-10-29
Implementation Status: Implemented
Maturity Score: 4
Gap Description: None
```

## Expected Handling

- Mark the SoA row as evaluable because it identifies a risk or requirement
  driver, treatment option, owner, evidence source, evidence freshness, and
  residual-risk approval.
- Record no ISO-NE reason code for A.8.15 unless other evidence contradicts the
  stated operating evidence.
- Include the row in the Risk Treatment Traceability Matrix with no open
  traceability gap.
