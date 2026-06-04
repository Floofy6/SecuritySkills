# Vulnerable: 4688 process name treated as command evidence

Event ID 4688 is present, but command-line process auditing is not enabled.

```text
Event ID: 4688
New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Creator Process Name: C:\Windows\System32\svchost.exe
Process Command Line: <missing>
Host role: management jump box
```

Problematic assessment:

- Labels the event as malicious PowerShell execution based only on process name.
- Does not record whether `Audit Process Creation` is enabled.
- Does not record whether `Include command line in process creation events` is enabled.
- Does not downgrade confidence or list missing command-line capture as a visibility gap.
