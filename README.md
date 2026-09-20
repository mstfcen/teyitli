# Teyitli

Teyitli is a working early-stage brand impersonation and phishing analysis engine.

## Live
https://teyit.mstfcen.com

## Current engine
Given an official domain and a target URL, the backend performs real IDN/Punycode and mixed-script checks, confusable/homograph comparison, DNS lookups, TLS inspection, RDAP age lookup, redirect inspection, HTML form analysis, security-header checks, SSRF protection, and per-client rate limiting.

The risk score is decision support, not a guarantee that a low-scoring site is safe.

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn server:app --host 127.0.0.1 --port 18950
```

The public deployment runs on Zaku behind Cloudflare Tunnel.
