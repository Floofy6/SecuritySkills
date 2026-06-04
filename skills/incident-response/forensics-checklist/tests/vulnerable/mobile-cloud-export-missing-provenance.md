# Vulnerable: Mobile Cloud Export Without Provenance

```yaml
incident_id: IR-2026-056
evidence_source: android_cloud_backup
account_id: employee@example.com
requested_data: messages, photos, location history
export_portal: unknown
export_time_range: missing
request_id: missing
collector_identity: missing
hash: missing
privacy_minimization: missing
```

This should be flagged because mobile cloud evidence must preserve the account,
portal or API, query scope, request/export ID, collector identity, time range,
privacy minimization status, and hash of the exported evidence package.
