# Vulnerable: stale DAST tool references

## DAST CI/CD Reference Evidence

```yaml
steps:
  - uses: actions/checkout@v4
  - name: ZAP Baseline Scan
    uses: zaproxy/action-baseline@v0.12.0
  - name: ZAP Full Scan
    uses: zaproxy/action-full-scan@v0.10.0
```

## References

- ZAP GitHub Actions: https://www.zaproxy.org/docs/docker/github-actions/
- Burp Suite Enterprise Documentation: https://portswigger.net/burp/enterprise

## Issue

The ZAP and PortSwigger references are stale or broken, and the action pins do not match the current upstream action examples.
