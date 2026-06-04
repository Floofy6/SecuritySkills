# Vulnerable: Stale EO 14028 Source Evidence

## Scenario

A dependency-supply-chain report maps SBOM/provenance recommendations to EO 14028 but cites only the stale White House briefing-room URL and does not record source status or reviewed date.

## Evidence

```yaml
report:
  claim: EO 14028 supports SBOM and provenance requirements
  source_url: https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
  source_type: not recorded
  status: not checked
  reviewed_date: missing
  replacement_sources:
    federal_register: missing
    govinfo_pdf: missing
```

## Expected Skill Behavior

- Do not treat the stale URL as strong compliance evidence.
- Require an Authoritative Source Register row with source type, status, reviewed date, and supported claim.
- Prefer the Federal Register page or GovInfo official PDF for EO 14028 context.
