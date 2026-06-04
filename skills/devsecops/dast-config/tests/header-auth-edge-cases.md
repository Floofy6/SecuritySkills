# DAST Header Authentication Edge Cases

These fixtures document how the `dast-config` skill should treat API bearer-token authentication in OWASP ZAP Automation Framework plans.

## False Positive: Unsupported Context Authentication Method

```yaml
env:
  contexts:
    - name: "api-context"
      urls:
        - "https://staging.example.com/api"
      authentication:
        method: "header"
        parameters:
          - header: "Authorization"
            value: "Bearer ${API_TOKEN}"
jobs:
  - type: openapi
    parameters:
      apiUrl: "https://staging.example.com/api/openapi.json"
      targetUrl: "https://staging.example.com"
      context: "api-context"
  - type: activeScan
    parameters:
      scanOnlyInScope: true
```

**Expected result:** Fail / Not Evaluable. `authentication.method: "header"` is not a supported ZAP Automation Framework authentication method. Do not mark API authentication as configured unless a supported header mechanism and authenticated request evidence are present.

## Benign: System-Level Header Environment Variables

```bash
export ZAP_AUTH_HEADER=Authorization
export ZAP_AUTH_HEADER_VALUE="Bearer ${API_TOKEN}"
export ZAP_AUTH_HEADER_SITE="staging.example.com"
zap.sh -cmd -autocheck af-plan.yaml
zap.sh -cmd -autorun af-plan.yaml
```

```yaml
env:
  contexts:
    - name: "api-context"
      urls:
        - "https://staging.example.com/api"
      authentication:
        method: "manual"
        verification:
          method: "poll"
          loggedInRegex: "\\Q\"userId\"\\E"
          loggedOutRegex: "\\Q\"unauthorized\"\\E"
          pollUrl: "https://staging.example.com/api/v1/me"
```

**Expected result:** Pass only when the environment variables are set before ZAP starts, `ZAP_AUTH_HEADER_SITE` or equivalent scope control is present, plan validation succeeds, and a protected API endpoint shows authenticated content.

## Benign: Header-Based Session Management

```yaml
env:
  contexts:
    - name: "api-context"
      urls:
        - "https://staging.example.com/api"
      authentication:
        method: "browser"
        parameters:
          loginPageUrl: "https://staging.example.com/login"
          loginPageWait: 5
      sessionManagement:
        method: "headers"
        parameters:
          Authorization: "Bearer: {%env:API_TOKEN%}"
      verification:
        method: "poll"
        loggedInRegex: "\\Q\"userId\"\\E"
        loggedOutRegex: "\\Q\"unauthorized\"\\E"
        pollUrl: "https://staging.example.com/api/v1/me"
```

**Expected result:** Pass only when the header-based session management add-on is available, verification succeeds, and scan evidence shows the Authorization header being applied to OpenAPI, spider, and active scan traffic for the intended host.
