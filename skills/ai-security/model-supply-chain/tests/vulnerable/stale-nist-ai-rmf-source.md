# Vulnerable: stale NIST AI RMF source

This fixture represents a model supply-chain review guide that maps findings to
NIST AI RMF but still cites the retired short URL:

- NIST AI Risk Management Framework 1.0: https://www.nist.gov/aiframework

Expected finding: replace the stale 404 URL with the current official NIST AI RMF
landing page and keep NIST AI RMF present in skill discovery metadata.
