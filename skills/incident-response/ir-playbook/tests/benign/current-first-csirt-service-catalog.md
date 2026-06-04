## Benign: current FIRST CSIRT service catalogue evidence

This incident response plan records a current CSIRT service reference before using
FIRST terminology in service handoffs.

```yaml
incident_id: IR-2026-110
csirt_service_model:
  framework: FIRST CSIRT Services Framework
  version: "2.1"
  source_url: https://www.first.org/standards/frameworks/csirts/csirt_services_framework_v2.1
  retrieved: 2026-06-04
  mapped_services:
    - incident management
    - vulnerability response coordination
    - information sharing
handoff_boundaries:
  internal_soc: detection and triage
  csirt: incident coordination and stakeholder updates
  external_ir: forensic acquisition and eradication support
```

Expected result: the skill should treat this as current, traceable service
catalogue evidence and not flag the FIRST reference as stale.
