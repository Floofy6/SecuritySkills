# Vulnerable: Raw Secrets and Tool Output Copied to Logs

This audit event appears complete under a raw "full parameters and output"
checklist, but it turns the log store into a credential and sensitive-data
repository.

```json
{
  "event_type": "agent_tool_invocation",
  "agent_id": "support-agent-2",
  "tool_name": "call_partner_api",
  "parameters": {
    "authorization": "Bearer eyJhbGciOi...",
    "api_key": "sk_live_example",
    "cookie": "session=abc123",
    "customer_id": "cust-123"
  },
  "tool_output": {
    "name": "Jane Example",
    "email": "jane@example.com",
    "payment_card_last4": "4242",
    "support_notes": "private customer notes"
  },
  "prompt": "Full user prompt and retrieved customer context...",
  "reasoning": "Hidden chain-of-thought copied into logs",
  "correlation_id": "req-789"
}
```

Expected finding:

- Flag unredacted credentials, cookies, API keys, PII/payment data, raw prompt
  context, and hidden reasoning copied into ordinary logs.
- Require pre-ingestion redaction/tokenization and a safer audit schema.
- If full payload retention is justified, require a separately protected,
  encrypted, access-controlled, retention-limited evidence store.
