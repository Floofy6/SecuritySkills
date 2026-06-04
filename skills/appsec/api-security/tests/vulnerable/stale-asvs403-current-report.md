# Vulnerable: Stale ASVS 4.0.3 Current-Baseline Report

Scenario: An API security review report is generated for a new 2026 engagement.

Report excerpt:

- Frameworks applied: OWASP API Security Top 10:2023, OWASP ASVS 4.0.3
- ASVS Reference: V13.2.3
- Source evidence: OWASP ASVS project page checked; current baseline is ASVS 4.0.3
- Finding: GraphQL depth limiting is missing, mapped to API4:2023 and ASVS V13

Expected skill behavior:

- Flag this as stale framework evidence because ASVS 4.0.3 must not be labeled current for new reports.
- Require OWASP ASVS 5.0.0 as the default baseline, or require the report to label ASVS 4.0.3 as an explicitly scoped legacy framework.
- Require version-qualified ASVS identifiers such as `v5.0.0-4.3.1` when exact ASVS requirements are cited.
