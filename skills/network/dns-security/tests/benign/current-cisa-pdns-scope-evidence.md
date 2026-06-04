# Benign Fixture: Current CISA PDNS Scope Evidence

## Scenario

A DNS security review cites the current CISA service page:

```markdown
CISA Protective Domain Name System (DNS) Resolver -- https://www.cisa.gov/resources-tools/services/protective-domain-name-system-dns-resolver
```

The review records:

```yaml
service_scope: FCEB agency or limited critical-infrastructure pilot participant
deployment_model: upstream from agency networks, complementing internal DNS architecture
routing_coverage:
  - on-premises recursive resolvers
  - mobile assets
  - roaming assets
  - cloud assets
provider_response: block, redirect, or sinkhole matched threat-intelligence indicators
alerts_and_logs: origin agency and CISA receive alerts/logs; SIEM forwarding verified
```

## Expected Result

Do not flag this as stale or overbroad. The review uses the current CISA source and keeps CISA PDNS availability, deployment model, traffic routing, response behavior, and alert/log evidence scoped to what the service page describes.
