# Benign PIR Metric Case: Single Incident With Timestamp Ranges

Use this fixture to verify that `post-incident-review` preserves timestamp uncertainty and does not label one incident as an aggregate mean.

---

## Evidence

```text
Incident: IR-2026-0042
Last known clean: 2026-05-01 00:00 UTC
First confirmed malicious event: 2026-05-08 14:02 UTC
First external notification: 2026-05-10 09:40 UTC
First internal signal: none observed before external notification
Incident declaration: 2026-05-10 10:00 UTC
Containment: 2026-05-10 12:30 UTC
Customer traffic restored: 2026-05-10 18:00 UTC
Data integrity validation complete: 2026-05-11 08:00 UTC
Enhanced monitoring ended: 2026-05-17 18:00 UTC
```

## Expected Review Behavior

- Report `Metric Scope` as `Single incident`.
- Report per-incident `TTD`, `TTC`, and `TTR`; do not label these rows as `MTTD`, `MTTC`, or `MTTR`.
- Use a TTD range because initial compromise is interval-censored between last-known-clean and first malicious event.
- Record first external notification separately from first internal signal.
- Select one recovery anchor for TTR and keep the other recovery milestones visible.
- Mark aggregate mean metrics as `N/A` unless a separate incident population and reporting period are provided.
