## Vulnerable: stale FIRST CSIRT framework reference

This incident response plan cites the retired FIRST education URL and does not
record a framework version or retrieval date before using CSIRT service terms.

```yaml
incident_id: IR-2026-111
csirt_service_model:
  framework: FIRST CSIRT Framework
  source_url: https://www.first.org/education/csirt
  version: unknown
  retrieved: missing
handoff_boundaries:
  csirt: "handles all services listed by FIRST"
  external_ir: "called if needed"
```

Expected result: the skill should require the responder to replace the stale URL
with the current FIRST Services Framework material and record version/retrieval
evidence before relying on CSIRT service catalogue assumptions.
