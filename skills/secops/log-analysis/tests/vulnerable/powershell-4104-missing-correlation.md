# Vulnerable: PowerShell process without script block correlation

The analyst sees a suspicious PowerShell process but cannot prove what script content executed.

```text
Event ID: 4688
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Process Command Line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA...

Missing:
- Microsoft-Windows-PowerShell/Operational Event ID 4104
- ScriptBlockText / decoded script block content
- Sysmon Event ID 1 or EDR process tree fallback
```

Problematic assessment:

- Claims script behavior without decoding the payload or correlating to 4104 script block content.
- Does not identify whether Script Block Logging is disabled, unavailable, or outside retention.
- Does not document sensitive-data handling for command-line or script block evidence.
