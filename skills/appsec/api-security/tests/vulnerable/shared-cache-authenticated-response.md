# Vulnerable: authenticated API response cached by a shared cache

## Input Evidence

```http
GET /api/v1/account/summary HTTP/1.1
Host: api.example.com
Authorization: Bearer user-a-token

HTTP/1.1 200 OK
Cache-Control: public, s-maxage=300
Content-Type: application/json

{"user_id":"user-a","invoice_balance":18420}
```

```yaml
cdn_rule:
  path: /api/v1/account/*
  cache_everything: true
  edge_ttl: 300
  origin_cache_control: disabled
  cache_key:
    include_headers: []
```

## Expected Result

Report a High or Critical API8 finding unless there is additional evidence that the response is public and invariant. Authentication is not enough; the shared-cache rule stores a per-user response while the cache key ignores `Authorization`, cookies, or user identity.
