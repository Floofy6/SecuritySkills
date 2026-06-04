# Benign: current ATT&CK v19.1 detection evidence

## Detection Engineering Report: T1059.001

**Frameworks:** MITRE ATT&CK v19.1, Sigma, Palantir ADS

### ATT&CK Technique Summary

| Field | Value |
|-------|-------|
| Technique ID | T1059.001 |
| Technique Name | Command and Scripting Interpreter: PowerShell |
| ATT&CK Version | v19.1 |
| Source Reviewed | 2026-06-04, https://attack.mitre.org/techniques/T1059/001/ |
| Tactic(s) | Execution |
| Detection Strategy / Analytic | Current ATT&CK defensive object reviewed or custom analytic documented |
| Data Components | Process Creation, Command Execution, Script Execution |
| Required Fields | command line, process image, parent process, user, host, timestamp |
| Mapping Confidence | High: sub-technique, telemetry fields, and validation method are documented |

### Coverage Assessment

Coverage is marked tested only after the Sigma rule is validated against a known PowerShell encoded-command event and known-good administrative PowerShell activity. The report does not treat a broad legacy Data Source label as sufficient proof.
