# Vulnerable: stale NIST AI RMF and Playbook sources

This fixture represents an agentic-top-10 review guide that still cites retired
NIST AI RMF and AIRC Playbook URLs:

- NIST AI Risk Management Framework 1.0: https://www.nist.gov/aiframework
- NIST AI RMF Playbook: https://airc.nist.gov/AI_RMF_Playbook

Expected finding: replace both stale 404 URLs with the current official NIST and
AIRC sources.
