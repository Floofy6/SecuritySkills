# Benign: CWE-1188 is reserved for insecure default initialization evidence

## Input Finding

```yaml
owasp_category: LLM09:2025 - Misinformation
downstream_sink: generated deployment template committed to repository
generated_configuration:
  resource: model-plugin-registry
  default_endpoint: "http://plugins.example.test"
  installer_expected_to_change: true
  secure_default_available: true
evidence:
  - template initializes the resource with an insecure default endpoint
  - admin guide says operators must replace it after installation
```

## Expected Result

CWE-1188 may be applicable because the evidence is about a resource initialized with an insecure default intended to be changed by an installer, administrator, or maintainer. The report should still include the LLM09 context and explain the mapping rationale.
