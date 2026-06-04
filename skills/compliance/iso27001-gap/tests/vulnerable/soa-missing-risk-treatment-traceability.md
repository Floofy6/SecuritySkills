# ISO 27001 SoA Missing Risk Treatment Traceability - Vulnerable

## Scenario

An organization marks Annex A control A.8.15 Logging as implemented in the
Statement of Applicability, but the row only contains implementation status and
maturity. It does not show why the control was selected, who owns the evidence,
or whether residual risk was accepted.

```text
Control: A.8.15 Logging
Applicable: Yes
Implementation Status: Implemented
Maturity Score: 4
Gap Description: None
```

## Expected Handling

- Do not accept the SoA row as certification-ready solely because it is marked
  implemented.
- Mark the row Not Evaluable for missing traceability:
  - ISO-NE-01: missing risk or requirement driver for an included control
  - ISO-NE-02: missing treatment option or linked risk-treatment action
  - ISO-NE-03: missing control owner or evidence owner
  - ISO-NE-04: evidence is policy-only, stale, absent, or not tied to operating
    effectiveness
  - ISO-NE-05: residual-risk acceptance is missing or not approved by the risk
    owner
- Add A.8.15 to the SoA Traceability Gaps table with follow-up to link the row
  to the risk register, treatment plan, evidence owner, evidence date, and
  residual-risk approval.
