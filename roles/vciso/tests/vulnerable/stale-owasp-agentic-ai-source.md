# Vulnerable: stale OWASP Agentic AI source

This fixture documents the stale vCISO source-reference pattern.

## Finding

The vCISO role cites the retired OWASP Agentic AI project URL:

```text
https://owasp.org/www-project-agentic-ai-top-10/
```

As of 2026-06-04, that URL returns HTTP 404. A vCISO AI governance report that
uses it cannot prove which current OWASP agentic taxonomy was applied.

## Expected review result

- Mark the source as stale.
- Do not use the dead URL as the source of truth for agentic AI governance.
- Replace it with the current OWASP GenAI Agentic Applications source and record
  the taxonomy version/date in the engagement source register.
