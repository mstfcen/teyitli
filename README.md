# Teyitli

Teyitli is a working early-stage brand impersonation, phishing analysis and automated lookalike-domain monitoring engine.

## Live

- Scanner: https://teyit.mstfcen.com
- Radar: https://teyit.mstfcen.com/radar

## v0.4

### URL analysis
- IDN / Punycode and mixed-script checks
- confusable / homograph comparison
- registered-domain and brand-similarity scoring
- DNS A/AAAA/MX/NS lookup
- TLS certificate validation
- RDAP registration-age lookup
- HTTP redirect-chain inspection
- HTML form / password / sensitive-field inspection
- external form-action and security-header checks
- real Chromium screenshots of official and target pages
- screenshot, detected-logo, DOM and visible-text similarity
- aggregate clone / impersonation score
- SSRF protections in HTTP and browser layers

### Radar
A brand is registered once with a display name, brand key and official URL. Radar then:
- generates typo, deletion, duplication, transposition and hyphen variants
- generates login/secure/verify/payment/support-style combinations
- generates alternate-TLD candidates
- generates Unicode homograph candidates
- resolves candidates and keeps only domains that are actually alive
- uses Certificate Transparency data as a passive certificate signal
- deep-analyzes high-risk live candidates with the Teyitli engine
- persists findings and scan history in SQLite
- exposes a read-only live dashboard
- runs automatically through a systemd user timer on the development host

A Radar finding is an investigation candidate, not proof that a domain is malicious.

## Local run

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn server:app --host 127.0.0.1 --port 18950
```

Chromium or Chrome is required for visual comparison.

Brand administration is deliberately not exposed on the public demo. On the development host:

```bash
.venv/bin/python radar.py add "Brand Name" https://official.example --key brand
.venv/bin/python radar.py scan-all
```

The public development deployment currently runs on Zaku behind Cloudflare Tunnel.
