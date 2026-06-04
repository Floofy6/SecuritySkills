# Benign: current DAST tool references

## DAST CI/CD Reference Evidence

```yaml
steps:
  - uses: actions/checkout@v4
  - name: ZAP Baseline Scan
    uses: zaproxy/action-baseline@v0.15.0
  - name: ZAP Full Scan
    uses: zaproxy/action-full-scan@v0.13.0
```

## References

- ZAP Docker User Guide and GitHub Actions: https://www.zaproxy.org/docs/docker/about/
- ZAP Baseline GitHub Action: https://github.com/zaproxy/action-baseline
- ZAP Full Scan GitHub Action: https://github.com/zaproxy/action-full-scan
- Burp Suite DAST Documentation: https://portswigger.net/burp/documentation/dast
- Burp Suite Documentation: https://portswigger.net/burp/documentation

## Evidence

The DAST guidance uses live upstream ZAP and PortSwigger documentation, with current action pins verified from the action repositories.
