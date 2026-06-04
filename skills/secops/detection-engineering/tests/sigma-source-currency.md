# Detection Engineering Sigma Source Currency

These fixtures document how the `detection-engineering` skill should treat Sigma documentation source freshness.

## Vulnerable: Stale Sigma Rule Creation Link

```text
Sigma conformance source: https://sigmahq.io/docs/guide/rules.html
Reviewed date: not recorded
Claim supported: rule field requirements and repository conventions
Source status: not checked
```

**Expected result:** Not Evaluable. The source is stale and no reviewed date is recorded, so the reviewer cannot prove the rule was checked against current Sigma documentation or SigmaHQ conventions.

## Benign: Current Sigma Rules Documentation

```text
Sigma specification source: https://sigmahq.io/docs/basics/rules.html
SigmaHQ convention source: https://sigmahq.io/sigma-specification/sigmahq/sigmahq-rule-convention.html
Reviewed date: 2026-06-04
Claim supported: required fields, modifiers, false-positive guidance, and repository conventions
```

**Expected result:** Pass. The sources are current, official, reachable, and tied to the Sigma conformance claim.

## Benign: SigmaHQ Rule Creation Wiki

```text
SigmaHQ rule creation guide: https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide
Reviewed date: 2026-06-04
Claim supported: community rule-authoring expectations and metadata conventions
```

**Expected result:** Pass as repository-convention evidence when paired with the current Sigma rules documentation for syntax semantics.
