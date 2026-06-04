# Benign: Authorized Logical Mobile Acquisition

```yaml
incident_id: IR-2026-057
evidence_source: managed_mobile_device
custodian: employee-143
authority: HR and legal approved corporate-device collection
platform: Android 15
device_id: MOB-0007
lock_state: unlocked
network_isolation: MDM network hold before acquisition
acquisition_method: logical_backup
tool: Magnet Acquire 2.0.0
tool_hash_sha256: recorded
start_time_utc: 2026-06-04T14:00:00Z
end_time_utc: 2026-06-04T14:22:00Z
output_hash_sha256: recorded
limitations: app end-to-end encrypted content not available from logical backup
```

This should not be flagged as collection-ready risk solely because it uses a
logical mobile acquisition method. The plan records authority, lock state,
network isolation, tool provenance, timing, output hashing, and limitations.
