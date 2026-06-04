# Vulnerable: stale EO 14028 source

This fixture represents a zero trust assessment guide that references federal
zero trust mandates but still cites the retired White House EO 14028 URL:

- Executive Order 14028: https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/

Expected finding: replace the stale 404 URL with the official Federal Register
publication source and keep EO 14028 visible in skill discovery metadata.
