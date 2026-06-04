# Vulnerable: stale ATT&CK v16 source claim

## SIEM Detection Rule: Password Spray
**Date:** 2026-06-04
**Skill:** siem-rules v1.0.0
**Framework:** MITRE ATT&CK v16
**Platform:** Microsoft Sentinel (KQL)

### Rule Metadata
| Field | Value |
|-------|-------|
| ATT&CK Technique | T1110.003 -- Brute Force: Password Spraying |
| Data Source | SigninLogs |

### Source Notes
- Treats MITRE ATT&CK v16 as the current framework release.
- Uses https://attack.mitre.org/datasources/ as the active detection source of truth.
- Does not record the ATT&CK version history URL, technique URL, Detection Strategy, Analytics, or Data Component evidence used for the rule.
