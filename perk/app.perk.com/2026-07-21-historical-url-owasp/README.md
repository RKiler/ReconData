# app.perk.com historical URL OWASP assessment

This directory contains the sanitized, exact-host assessment artifacts generated on 2026-07-21 for the historical `https://app.perk.com/` URL inventory.

## Result

No new reportable OWASP Top 10 vulnerability was confirmed in this URL-focused pass.

- 137 security-relevant historical URL candidates
- 68 normalized route templates
- 274 isolated core requests: 137 anonymous and 137 authenticated
- 220 `GET` and 54 non-mutating `HEAD` requests
- Additional bounded CORS, redirect, JWT, JavaScript, source-map, and browser-context checks

See [`assessment.md`](assessment.md) for conclusions and limitations.

## Contents

- `inventory/`: redacted URL inventory and OWASP prioritization
- `data/`: status, body-shape, response-hash, and validation evidence
- `scripts/`: credential-redacting probe and reconciliation utilities

## Redaction and exclusions

This repository is public. The uploaded bundle intentionally excludes:

- cookies, JWTs, CSRF values, refresh tokens, and WAF tokens;
- original archived onboarding token and identity values;
- raw JavaScript response bodies;
- internal actor/account state and prior known-issue files;
- response bodies containing session material;
- the superseded first probe run that shared session state between anonymous and authenticated modes.

Two historical onboarding URLs are retained only in redacted form. Active testing replaced their archived query values with inert markers.

## Interpretation

A `200` frontend shell is not evidence of unauthorized data access. State-looking routes were checked with `HEAD` only and are not claimed as full workflow authorization tests. Current multi-role and state-changing validation requires separate approved credentials, disposable owned objects, exact backend request shapes, and explicit authorization.

## Running the scripts

The scripts default to the original local analysis paths and expect credentials in `/root/cookies_perk.txt`. Review and adjust paths before reuse. Never commit the credential file or unredacted output.

The browser check requires `playwright-core`, a local Chromium executable, and `PERK_PLAYWRIGHT_ROOT` pointing to the package installation root. Its route interception blocks off-host HTTP(S) requests.
