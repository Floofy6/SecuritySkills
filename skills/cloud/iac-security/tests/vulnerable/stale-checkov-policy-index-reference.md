# Vulnerable Fixture: Stale Checkov Policy Index Reference

## Scenario

An IaC review cites this source as the proof for every Checkov rule mapping:

```markdown
Checkov Policy Index: https://www.checkov.io/5.Policy%20Index/
```

The review maps findings to `CKV_AWS_17`, `CKV_AWS_19`, `CKV_AWS_24`, and `CKV_TF_1`, but it does not record the Checkov version, framework/runner, current scanner `Guide:` URL, Prisma Cloud policy-reference source, or whether the rule came from a custom policy.

## Expected Finding

Flag this as stale and under-evidenced. The old Checkov policy-index path should not be used as the sole proof for Checkov rule mappings. The review should capture the scanner version, framework, rule ID/title, current guide URL when available, and whether the rule source is built-in, custom, stale, unavailable, or inferred.
