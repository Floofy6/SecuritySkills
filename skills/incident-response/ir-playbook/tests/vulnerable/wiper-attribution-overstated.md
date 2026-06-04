# Vulnerable: Wiper Attribution Treated as Confirmed

```yaml
incident_id: IR-2026-061
category: destructive_wiper
actor: Handala
attribution_status: confirmed
source: threat_actor_telegram_claim
impact_count: 200000 devices wiped
motive: retaliation
operational_action: notify customers that a confirmed nation-state actor caused the outage
```

This should be flagged because an actor claim alone is not confirmed
attribution or verified impact. The incident report should separate observed
evidence from claimed, assessed, and confirmed attribution.
