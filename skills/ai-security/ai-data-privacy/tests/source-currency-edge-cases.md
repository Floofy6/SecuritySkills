# AI Data Privacy Source Currency Edge Cases

These fixtures document how the `ai-data-privacy` skill should treat source freshness for privacy and AI governance claims.

## Vulnerable: Broken Source Used for Current Regulatory Claim

```text
Finding: Missing AI privacy risk assessment is High.
NIST AI RMF source: https://www.nist.gov/aiframework
Reviewed date: not recorded
Claim supported: MAP 5.1 and MEASURE 2.9 require privacy risk assessment
Source status: not checked
```

**Expected result:** Not Evaluable / High evidence gap. The report relies on a stale or broken source URL and does not record a reviewed date. The reviewer must verify the official publication page or document identifier before using the source to support a client-facing finding.

## Benign: Official Source Register Row

```text
Source: NIST AI Risk Management Framework 1.0
URL: https://www.nist.gov/itl/ai-risk-management-framework
Publication date: 2023-01
Reviewed date: 2026-06-04
Claim supported: AI privacy risk mapping across GOVERN, MAP, MEASURE, and MANAGE
Confidence: Official
```

**Expected result:** Pass. The source is official, reachable, dated, and tied to the claim it supports.

## Benign: SP 800-188 Publication Page

```text
Source: NIST SP 800-188, De-Identifying Government Datasets
URL: https://csrc.nist.gov/pubs/sp/800/188/final
Publication date: 2023-09
Reviewed date: 2026-06-04
Claim supported: de-identification technique and governance evidence for privacy controls
Confidence: Official
```

**Expected result:** Pass. The skill should prefer the stable CSRC publication page over retired `publications/detail/...` links.
