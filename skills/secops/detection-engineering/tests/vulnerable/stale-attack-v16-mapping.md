# Vulnerable: stale ATT&CK v16 detection mapping

## Detection Engineering Report: T1059.001

**Frameworks:** MITRE ATT&CK v16, Sigma, Palantir ADS

### ATT&CK Technique Summary

| Field | Value |
|-------|-------|
| Technique ID | T1059.001 |
| Technique Name | Command and Scripting Interpreter: PowerShell |
| Tactic(s) | Execution |
| Data Sources | Process Creation, Command Execution |

### Coverage Assessment

Coverage is marked operational because process creation logs are collected and the rule maps to T1059.001.

## Expected Review Behavior

This should be treated as stale source evidence because it relies on the old ATT&CK v16 label and broad Data Sources only. A current report must record the reviewed ATT&CK version, technique URL, current defensive evidence such as Detection Strategy or Analytic when available, Data Components, required fields, and validation status.
