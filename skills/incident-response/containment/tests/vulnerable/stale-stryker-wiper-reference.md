# Vulnerable: stale containment reference for Stryker wiper reporting

The containment skill cites the Stryker incident only through `krebsonsystems.com`, which no longer resolves, and labels the example as an Iran-backed wiper attack without a source-confidence caveat.

Problematic signals:

- Broken reference URL prevents responders from validating the example.
- Victim-confirmed incident scope is not linked.
- Reported Microsoft Intune remote-wipe abuse is not distinguished from confirmed malware behavior.
- Containment planning may overfit to unconfirmed device counts or attribution instead of treating them as hypotheses.
