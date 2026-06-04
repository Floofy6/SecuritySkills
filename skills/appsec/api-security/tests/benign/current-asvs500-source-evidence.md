# Benign: Current ASVS 5.0.0 Source Evidence

Scenario: An API security review report records current framework sources before classifying findings.

Report excerpt:

- Framework sources:
  - OWASP API Security Top 10:2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  - OWASP ASVS 5.0.0: https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release
- Finding: GraphQL query depth and cost controls are missing.
- OWASP API Risk: API4:2023 -- Unrestricted Resource Consumption
- ASVS Mapping: `v5.0.0-4.3.1`
- CWE: CWE-770 -- Allocation of Resources Without Limits or Throttling

Expected skill behavior:

- Do not flag this report as stale framework evidence.
- Accept ASVS 5.0.0 as the current default source version for new API reviews.
- Accept version-qualified ASVS requirement IDs, and allow `N/A` only when the report records why no ASVS control applies.
