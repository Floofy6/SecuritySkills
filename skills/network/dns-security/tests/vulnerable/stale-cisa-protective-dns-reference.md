# Vulnerable Fixture: Stale CISA Protective DNS Reference

## Scenario

A DNS security review cites:

```markdown
CISA Protective DNS: https://www.cisa.gov/protective-dns
```

It recommends CISA Protective DNS as a generic protective resolver for any organization, but it does not verify service eligibility, routing coverage, upstream/internal-DNS architecture, block/redirect/sinkhole behavior, alert delivery, or SIEM/log forwarding.

## Expected Finding

Flag this as stale and overbroad. The current CISA service page uses the Protective Domain Name System Resolver page and describes service availability for FCEB agencies plus limited critical-infrastructure pilot participants. The review should record eligibility/scope, DNS routing coverage, provider response behavior, alert/log delivery, and the current source URL.
