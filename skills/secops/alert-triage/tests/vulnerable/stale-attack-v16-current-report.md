## Alert Triage Report
**Date:** 2026-06-04 14:00 UTC
**Skill:** alert-triage v1.0.0
**Frameworks:** MITRE ATT&CK v16, NIST SP 800-61 Rev 2
**Analyst:** AI-assisted

### Alert Summary
| Field | Value |
|-------|-------|
| Alert ID | SIEM-44821 |
| Rule Name | Suspicious PowerShell Encoded Command |
| Source System | SIEM |
| Timestamp | 2026-06-04 13:43:10 UTC |
| ATT&CK Technique | T1059.001 -- PowerShell |
| ATT&CK Tactic | Execution (TA0002) |

### Triage Decision
| Field | Value |
|-------|-------|
| **Disposition** | **Benign True Positive** |
| **Priority** | **P4 Low** |
| **Confidence** | High |
| **Escalation Required** | No |

### Evidence Summary
1. Report claims current ATT&CK coverage while using an ATT&CK v16 label.
2. No ATT&CK version history, current technique URL, or reviewed-source date is recorded.
3. The old ATT&CK label is copied from the detection rule metadata without current-source verification.
