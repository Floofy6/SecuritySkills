# Benign: Current EO 14028 Source Register

## Scenario

An SBOM analysis report uses EO 14028 only as policy context and records current official Federal Register and GovInfo sources with reviewed dates.

## Evidence

```yaml
authoritative_source_register:
  - source: NTIA SBOM Minimum Elements
    url: https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf
    source_type: official_report
    status: 200
    reviewed_date: 2026-06-04
    supports_claim: seven minimum SBOM elements
    confidence: Strong
  - source: EO 14028
    url: https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity
    source_type: official_federal_register
    status: 200
    reviewed_date: 2026-06-04
    supports_claim: SBOM policy and federal supplier context
    confidence: Strong
  - source: EO 14028 official PDF
    url: https://www.govinfo.gov/content/pkg/FR-2021-05-17/pdf/2021-10460.pdf
    source_type: official_pdf
    status: 200
    reviewed_date: 2026-06-04
    supports_claim: legal-grade citation for EO 14028
    confidence: Strong
```

## Expected Skill Behavior

- Treat EO 14028 as current policy context because official sources and reviewed dates are recorded.
- Keep NTIA minimum elements as the concrete SBOM completeness criteria.
- Do not require the stale White House briefing-room URL when Federal Register and GovInfo sources are present.
