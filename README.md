# Teyitli

Teyitli is a working early-stage brand impersonation and phishing analysis engine.

## Live
https://teyit.mstfcen.com

## v0.3 engine
Given an official URL/domain and a target URL, Teyitli performs:
- IDN / Punycode and mixed-script checks
- confusable / homograph comparison
- registered-domain and brand-similarity scoring
- DNS A/AAAA/MX/NS lookup
- TLS certificate validation and expiry inspection
- RDAP registration-age lookup when available
- HTTP redirect-chain inspection
- HTML form / password / sensitive-field inspection
- external form-action and security-header checks
- real headless-browser screenshots of official and target pages
- perceptual screenshot and detected-logo comparison
- DOM-structure and visible-text similarity
- aggregate clone / impersonation scoring
- SSRF protection for both HTTP and browser layers
- per-client rate limiting

The browser is forced through a local safe proxy that resolves and pins only public IPs; private/local targets and non-80/443 ports are rejected.

Risk scores are decision support, not a guarantee that a low-scoring site is safe.

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
# Chromium or Chrome must be installed.
.venv/bin/uvicorn server:app --host 127.0.0.1 --port 18950
```

The public development deployment currently runs on Zaku behind Cloudflare Tunnel.
