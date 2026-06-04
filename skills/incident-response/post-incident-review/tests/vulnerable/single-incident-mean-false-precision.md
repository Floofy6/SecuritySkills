# Vulnerable PIR Metric Case: Single Incident Labeled as Mean Metrics

Use this fixture to verify that `post-incident-review` rejects false precision and aggregate labels when the evidence covers only one incident.

---

## Evidence

```markdown
### Metrics
| Metric | Value | Benchmark |
|---|---|---|
| MTTD (Initial Compromise to Detection) | 9d 10h | better than industry average |
| MTTC (Detection to Containment) | 2h 30m | met SLA |
| MTTR (Detection to Recovery) | 8h | met SLA |

Initial compromise: estimated between 2026-05-01 and 2026-05-08
Detection: customer reported suspicious activity on 2026-05-10 09:40 UTC
Recovery: service restored 2026-05-10 18:00 UTC; forensic monitoring ended 2026-05-17
```

## Expected Review Behavior

- Flag the report because one incident is labeled with mean metrics.
- Replace `MTTD`, `MTTC`, and `MTTR` with per-incident `TTD`, `TTC`, and `TTR`.
- Replace the exact TTD value with a range or `Unknown` because compromise time is estimated.
- Record that detection was external and that no internal detection timestamp is provided.
- Require a selected recovery milestone and preserve secondary milestones instead of silently choosing the shortest value.
