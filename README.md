# Teyitli

Working early-stage brand impersonation, phishing analysis and automated lookalike-domain monitoring engine.

## Live

- Scanner: https://teyit.mstfcen.com
- Radar: https://teyit.mstfcen.com/radar

## v0.5

### URL analysis
Teyitli performs IDN/Punycode and mixed-script checks, confusable/homograph comparison, DNS/TLS/RDAP analysis, redirect and form inspection, real Chromium screenshots, DOM/text/logo similarity and aggregate clone/impersonation scoring.

### Radar
Brands are registered once and tracked separately. Radar automatically:
- generates typo, deletion, duplication, transposition, hyphen and Unicode-homograph candidates
- generates login/secure/verify/payment/support variants across multiple TLDs
- resolves candidates and keeps domains that actually exist
- performs bounded HTTP/TLS/RDAP enrichment
- spends browser/screenshot analysis only on the highest-priority unknown candidates
- stores findings and scan history in SQLite
- runs periodically through a systemd user timer

### Ownership-aware triage
Raw lexical similarity is separate from action priority.

Ownership states:
- `trusted`: explicit allowlist or official-domain tree
- `likely_owned`: strong automatic evidence such as redirect to the official domain or TLS linkage
- `unknown`: no strong ownership proof

IP/hosting overlap is recorded as context but is deliberately **not** sufficient to mark a domain trusted.

Action priority combines lexical similarity with stronger threat signals such as recent registration, credential/sensitive forms, external form actions and screenshot/DOM/text clone similarity. This prevents an old parked lookalike domain from automatically becoming a critical incident solely because its spelling is similar.

Radar defaults to an **Actionable** view and exposes per-brand filters for unknown, likely-owned, trusted and all findings.

## Local run

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn server:app --host 127.0.0.1 --port 18950
```

Chromium or Chrome is required for visual comparison.

## Radar administration

Brand administration is not exposed on the public demo.

```bash
# Add/update a brand
.venv/bin/python radar.py add "Brand Name" https://official.example --key brand

# Scan one brand
.venv/bin/python radar.py scan 2

# Add a manually verified exact allowlist entry
.venv/bin/python radar.py allow 2 owned-example.com --reason "Verified corporate domain"

# Allow an entire verified domain subtree
.venv/bin/python radar.py allow 2 owned-example.com --suffix --reason "Verified corporate domain tree"

# Recompute ownership/priority for existing findings
.venv/bin/python radar.py reclassify 2
```

A Radar finding is an investigation candidate, not proof that a domain is malicious.

The public development deployment currently runs on Zaku behind Cloudflare Tunnel.
