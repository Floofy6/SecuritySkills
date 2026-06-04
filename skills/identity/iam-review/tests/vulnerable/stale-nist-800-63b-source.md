# Vulnerable: stale NIST SP 800-63B source and section mapping

This fixture represents an IAM review guide that still maps authentication
findings to the older NIST SP 800-63B baseline and revision 3 password sections:

- Framework: NIST-SP-800-63B
- Password blocklist: NIST SP 800-63B Section 5.1.1.2
- Composition rules: NIST SP 800-63B Section 5.1.1.1

Expected finding: update the IAM review baseline and discovery metadata to NIST
SP 800-63B-4 and use the current revision 4 section mappings.
