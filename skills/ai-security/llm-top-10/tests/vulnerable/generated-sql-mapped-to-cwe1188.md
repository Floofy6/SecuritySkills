# Vulnerable: insecure generated SQL mapped to CWE-1188 instead of the real flaw

## Input Finding

```yaml
owasp_category: LLM09:2025 - Misinformation
model_output: "const query = 'SELECT * FROM users WHERE id = ' + req.query.id;"
downstream_sink: code repository
validation_control: no code review or static analysis gate
introduced_code:
  file: routes/users.js
  behavior: concatenates request query into SQL
current_mapping:
  cwe: CWE-1188
```

## Expected Result

Report the LLM09/overreliance context, but map the introduced software weakness to the concrete generated-code flaw, such as SQL injection, instead of CWE-1188.
