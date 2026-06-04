# Vulnerable Fixture: Stale ACSC General Forensics Reference

## Scenario

A forensic collection checklist cites:

```markdown
ACSC Digital Forensics Guide -- https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/publications/digital-forensics
```

It treats the ACSC citation as a general forensic acquisition standard for endpoint memory capture, disk imaging, cloud export provenance, chain of custody, and legal authorization.

## Expected Finding

Flag this as stale and overbroad. The cited Cyber.gov.au path is no longer the current official source, and the current ASD/ACSC-NCSC guidance is scoped to forensic visibility and protective monitoring for network devices and appliances. The skill should keep NIST SP 800-86 and RFC 3227 as the general forensic process references and use the 2025 Cyber.gov.au guidance only for network device/appliance observability, logging, volatile-state, and non-volatile storage requirements.
