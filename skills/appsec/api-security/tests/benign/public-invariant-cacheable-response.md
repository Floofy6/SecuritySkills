# Benign: public invariant API response is deliberately cacheable

## Input Evidence

```http
GET /api/v1/catalog/public-products?page=1 HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
Cache-Control: public, s-maxage=600, max-age=60
Vary: Accept-Encoding
Content-Type: application/json
```

```yaml
cdn_rule:
  path: /api/v1/catalog/public-products
  origin_cache_control: enabled
  cache_key:
    include_query_string: true
    include_headers:
      - Accept-Encoding
data_classification:
  sensitivity: public
  varies_by_auth: false
  varies_by_cookie: false
  varies_by_tenant: false
  varies_by_origin: false
```

## Expected Result

Do not report a cache-isolation finding. The endpoint is documented as public and invariant, origin cache-control is honored, and the cache key includes the public pagination parameter used to shape the response.
