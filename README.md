# Teyitli

Teyitli is a working early-stage brand-impersonation, phishing-detection and automated brand-monitoring engine.

## Live

- Scanner: https://teyit.mstfcen.com
- Radar: https://teyit.mstfcen.com/radar

## v0.6

### URL analysis
The scanner combines:
- IDN / Punycode / mixed-script / homograph checks
- registered-domain and brand similarity
- DNS / TLS / RDAP analysis
- redirect and HTML form inspection
- visible-page brand traces
- Chromium screenshot, logo, DOM and text similarity
- local threat-intelligence lookup against verified phishing feeds

A verified threat-intelligence hit is treated as a strong independent signal, so phishing pages hosted on unrelated platforms such as generic cloud/static-hosting domains do not need to look like the brand in their hostname.

### Radar
Brands are tracked separately. Radar:
- generates typo, deletion, duplication, transposition, hyphen and Unicode-homograph candidates
- generates login/secure/verify/payment/support variants across multiple TLDs
- resolves candidates and keeps domains that actually exist
- performs bounded HTTP/TLS/RDAP enrichment
- performs expensive browser analysis only on selected unknown candidates
- imports the newest verified phishing hosts targeting each tracked brand from local threat intelligence
- stores findings, ownership verdicts, incidents and scan history in SQLite
- runs periodically using systemd user timers

### Ownership-aware triage
Raw lexical similarity is separate from action priority.

Ownership states:
- `trusted`: explicit allowlist or official-domain tree
- `likely_owned`: strong automatic evidence such as redirect to the official domain or TLS linkage
- `unknown`: no strong ownership proof

IP/hosting overlap is contextual only and is not sufficient to mark a domain trusted.

Action priority combines lexical similarity with recent registration, credential/sensitive forms, external form actions, clone similarity and verified threat-intelligence hits.

### Incidents
When a finding first reaches actionable priority, Radar automatically opens an incident containing a frozen evidence snapshot:
- brand and official domain
- candidate domain
- raw risk and priority
- ownership verdict
- resolved IPs
- HTTP/form evidence
- RDAP and TLS metadata
- visual-clone metrics when available
- threat-intelligence metadata when applicable

If a finding later drops below the actionable threshold, the open incident is automatically closed.

### Threat intelligence
The current development deployment imports PhishTank's online-valid feed into a local cache and refreshes it every 12 hours. Feed URLs remain internal; public Radar views expose only the minimum source/ID/host metadata needed for defensive triage.

### Regression test
`tests/live_phishing_regression.py` selects the newest cached verified-online sample for Microsoft, Facebook, Netflix, PayPal and LinkedIn and checks that the live engine returns a threat-intelligence hit and score >= 90 without executing page JavaScript.

## Local run

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn server:app --host 127.0.0.1 --port 18950
```

Chromium or Chrome is required for visual comparison.

## Radar administration

```bash
.venv/bin/python radar.py add "Brand Name" https://official.example --key brand
.venv/bin/python radar.py scan 2
.venv/bin/python radar.py allow 2 owned-example.com --reason "Verified corporate domain"
.venv/bin/python radar.py allow 2 owned-example.com --suffix --reason "Verified corporate domain tree"
.venv/bin/python radar.py reclassify 2
```

A Radar finding is an investigation candidate, not proof that a domain is malicious unless backed by an explicit verified threat-intelligence signal.

The public development deployment currently runs on Zaku behind Cloudflare Tunnel.
