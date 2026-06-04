# Vulnerable: credentialed CORS response cached without origin variation

## Input Evidence

```http
GET /api/v1/profile HTTP/1.1
Host: api.example.com
Origin: https://partner-a.example
Cookie: session=user-a

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://partner-a.example
Access-Control-Allow-Credentials: true
Cache-Control: public, max-age=300
Content-Type: application/json
```

```yaml
cdn_rule:
  path: /api/v1/profile
  cache_key:
    include_headers:
      - Accept-Encoding
```

## Expected Result

Mark the cache evidence `Not Evaluable` or vulnerable because the response varies by `Origin` and credential context, but neither `Vary: Origin` nor an equivalent origin-aware cache-key policy is present.
