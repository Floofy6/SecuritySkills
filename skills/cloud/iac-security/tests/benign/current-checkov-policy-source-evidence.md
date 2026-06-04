# Benign Fixture: Current Checkov Policy Source Evidence

## Scenario

An IaC review maps a Kubernetes finding to Checkov and records:

```yaml
tool: Checkov
version: 3.2.x
framework: kubernetes
rule_id: CKV_K8S_23
rule_title: Admission of root containers not minimized
guide_url: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-22
source_status: current
custom_policy: false
```

The review uses current Checkov documentation for scanner behavior and the Prisma Cloud policy-reference guide URL emitted by the Checkov finding for policy details.

## Expected Result

Do not flag this as stale. The review records the scanner version, framework, rule ID, current policy source, and custom-policy status instead of relying on the deprecated Checkov policy-index path.
