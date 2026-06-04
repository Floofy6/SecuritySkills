# Benign Fixture: Source-Scoped Network Device Reference

## Scenario

A forensic collection checklist cites the current Cyber.gov.au page:

```markdown
ASD/ACSC-NCSC Digital Forensics and Protective Monitoring Specifications for Network Devices and Appliances -- https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/network-hardening/securing-edge-devices/guidance-on-digital-forensics-and-protective-monitoring-specifications-for-producers-of-network-devices-and-appliances
```

The checklist applies this reference only to routers, firewalls, VPN concentrators, NAS, edge devices, and virtual appliances. It records authentication logs, administrative access, service/process activity, DNS queries, firmware updates, configuration changes, NTP/UTC timestamp confidence, remote logging status, volatile running state, and non-volatile storage collection support.

## Expected Result

Do not flag this as stale or overbroad. The checklist preserves NIST SP 800-86 and RFC 3227 as the primary general forensic process references while using the 2025 Cyber.gov.au guidance only for network device/appliance forensic visibility and protective monitoring evidence.
