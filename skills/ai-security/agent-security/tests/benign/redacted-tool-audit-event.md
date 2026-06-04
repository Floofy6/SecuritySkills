# Benign: Secret-Aware Tool Audit Event

This audit event preserves attribution and reconstruction metadata without
copying raw credentials, prompts, customer records, or tool outputs into ordinary
searchable logs.

```json
{
  "event_type": "agent_tool_invocation",
  "agent_id": "research-agent-7",
  "user_id": "user-123",
  "timestamp": "2026-06-04T12:00:00Z",
  "tool_name": "search_customer_records",
  "parameter_names": ["customer_id", "query"],
  "parameter_fingerprints": {
    "customer_id": "sha256:8b7..."
  },
  "result_status": "success",
  "result_count": 3,
  "correlation_id": "req-123",
  "approval_id": "approval-456",
  "policy_id": "customer-record-search-v2",
  "prompt_hash": "sha256:9f1...",
  "rationale_summary": "Searched records approved for the support case scope.",
  "redaction_policy": "pii-and-secrets-v4"
}
```

Expected assessment:

- Do not flag this as missing audit evidence merely because full parameter
  values and raw tool results are omitted.
- Confirm that the log has enough safe metadata for attribution, correlation,
  authorization review, and outcome verification.
- Confirm that sensitive payloads would require a separate protected evidence
  reference if they must be retained for incident response.
