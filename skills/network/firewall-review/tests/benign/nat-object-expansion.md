# Benign NAT and Object Expansion Case

Use this case to validate that `firewall-review` does not report an any/any, missing NAT, or stale-object finding when the effective traffic set is fully documented.

## Partner CIDR and Fresh FQDN Evidence Are Fully Expanded

**Configuration excerpt:**

```text
address group partner-api-sources:
  198.51.100.0/24

fqdn object api-prod.example.com:
  resolved: 10.30.40.25
  resolver: firewall-dns-cache
  observed_at: 2026-06-04T18:15:00Z

nat rule api-no-dnat:
  original destination: api-prod.example.com
  translation: none

security rule partner-api:
  source: partner-api-sources
  destination: api-prod.example.com
  service: tcp/443
  action: allow
```

**Expected review behavior:**

- Do not flag any/any or missing NAT expansion.
- Record `Objects Expanded: Yes`, `Service Groups Expanded: Yes`, `NAT/VIP Joined: Yes`, and `Dynamic/FQDN Timestamp: 2026-06-04T18:15:00Z/firewall-dns-cache`.
- Confidence may be **High** because the effective source, destination, service, and freshness evidence are present.
