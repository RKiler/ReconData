# Perk Historical URL OWASP Assessment — 2026-07-21

## Outcome

No new reportable OWASP Top 10 vulnerability was confirmed from the 137 exact-host historical URL candidates. This is URL-shape coverage, not a claim that every backend operation or complete OWASP category has been exhaustively tested.

## Scope and Safety

- Target: `https://app.perk.com/` only.
- Authentication: the fresh `admin1` cookie/JWT bundle in `/root/cookies_perk.txt`; credentials were read only in memory and never written to evidence.
- Anonymous and authenticated traffic used separate sessions. The earlier shared-session run is explicitly superseded and excluded.
- Read routes used `GET`. Twenty-seven state-looking routes used `HEAD` only; no approval, payment, cancellation, confirmation, checkout, notification, or other state action was performed.
- Two archived onboarding URLs contained token/identity query data. The historical values were never replayed; inert markers replaced every sensitive value.
- Browser interception blocked all requests outside `app.perk.com`, so credentials and attacker navigation markers could not leave the confirmed host.

## Coverage

| Area | Coverage | Result |
| --- | ---: | --- |
| Historical candidates | 137 URLs / 68 route templates | All represented in corrected isolated matrix |
| Core HTTP matrix | 274 requests | 137 anonymous + 137 authenticated |
| Safe methods | 220 GET + 54 HEAD | No mutation request sent |
| CORS | 32 requests | No `Access-Control-Allow-Origin` for the untrusted origin |
| Redirect/reflection | 12 HTTP variants + 8 isolated browser navigations | No attacker-domain navigation and no marker reflection |
| Current JavaScript | 53 assets, about 5.96 MB | No credential-format secret or proven source-to-dangerous-sink flow |
| Source maps | 49 exact map URLs | 49 returned 404; no sources recovered |
| JWT/session controls | missing, tampered-signature, `alg:none`, valid-token controls | Invalid controls returned 401; valid actor returned 200 |

Core matrix status distribution: `200` 238, `202` 4, `301` 2, `401` 2, `404` 26, `405` 2.

## Decisive Results

1. `/api/identity/perk-seamless-login/` and `/api-token-session/` denied anonymous requests with `401` and accepted the valid supplied actor with the expected self/session token response shape. Tampered-signature and `alg:none` JWT controls were also denied.
2. `/api/v2/federated-login-redirect/` returned the same empty JSON array in both modes. External `redirect_uri`/state markers were not reflected or followed.
3. Untrusted-origin CORS checks found no `Access-Control-Allow-Origin`. Some authenticated APIs returned `Access-Control-Allow-Credentials: true`, but without ACAO the hostile origin cannot read the response.
4. `/login?coming_from=` absolute and protocol-relative variants stayed on `app.perk.com`, produced no reflected marker, and attempted no off-host navigation. The route remained behind an AWS WAF `202` JavaScript interstitial because its token-service request was blocked as out of exact-host scope.
5. Authenticated `/sso-login?return_to=` stayed on `app.perk.com` and resolved to `/home`; the hostile destination was not used. The anonymous variant remained on `/sso-login`.
6. The remaining historical trip, event, integration, onboarding, and related browser routes returned frontend SPA shells, not object/API data. A `200` shell was not treated as access-control proof.
7. All 13 historical `mfe-access` JavaScript assets were dead (`404`). Current asset review found browser-visible configuration identifiers but no credential-format secret or verified privileged use; this also overlaps the existing known API-key-disclosure issue class without adding impact.

## OWASP Accounting

| OWASP 2021 category | What this run established | Remaining gap |
| --- | --- | --- |
| A01 Broken Access Control | No data-bearing anonymous/admin differential on historical routes; public shells are not proof | Fresh lower-role and cross-tenant sessions are absent; 27 action routes need approved disposable objects and real backend request shapes |
| A02 Cryptographic Failures | Sensitive archive values were not replayed; observed refresh/session cookies were Secure, HttpOnly, and SameSite constrained | No server-side cryptographic implementation audit |
| A03 Injection | Bounded redirect/reflection markers did not reflect; offline JavaScript review found no proven executable flow | No evidence-backed SQL/NoSQL/command/template input point in these URL shapes; blind spraying was not performed |
| A04 Insecure Design | State-looking workflow routes were identified and safety-gated | Approval/payment/cancel/confirm lifecycle testing requires explicit authorization and owned disposable state |
| A05 Security Misconfiguration | No hostile-origin readable CORS response; dead source maps; public config contained no verified secret | Infrastructure and non-exact-host services were not tested |
| A06 Vulnerable Components | Current JavaScript was inventoried and reviewed for obvious security-relevant artifacts | No dependency version-to-exploit proof; component presence alone is not a finding |
| A07 Identification and Authentication Failures | Missing/tampered/`alg:none` JWT controls failed; session APIs denied anonymous access | Full recovery, MFA, SSO, revocation, and multi-actor lifecycle testing is outside this URL-only pass |
| A08 Software and Data Integrity Failures | No upload, deserialization, signed-update, or CI/CD entry point was present in the candidate set | Not meaningfully testable from these URLs |
| A09 Security Logging and Monitoring Failures | No externally observable logging bypass was claimed | Requires operator-side telemetry or a documented audit-log workflow |
| A10 SSRF | No server-fetch/webhook parameter existed in the candidate set; external redirect markers were not followed | No third-party callback or blind SSRF test was authorized |

## Outcome Classification

- 88 SPA-shell-only candidates
- 27 safe-method-only state candidates
- 13 dead historical assets
- 2 authentication controls enforced
- 2 WAF-gated login candidates
- 2 safe-substitution-only archived token URLs
- 1 empty/non-data federated-login response
- 1 method-not-allowed refresh GET
- 1 public-client-config-only response

## Blockers and Highest-Value Next Step

The current credential file contains only `admin1`. A fresh horizontal/vertical/cross-tenant conclusion requires fresh `user_1` and `admin2` credentials. State-changing workflow validation additionally requires explicit approval plus owned disposable trip/approval/checkout objects and the exact observed backend requests. The minimum useful next package is:

1. fresh `user_1` and `admin2` cookie/JWT bundles;
2. one disposable owned trip or approval object per relevant actor;
3. approval to replay only the exact approve/approve-and-pay/confirm/cancel backend operation against those disposable objects, with owner readback and cancellation/cleanup where supported.

Without those prerequisites, the 27 HEAD-only action routes remain safely covered as route existence checks, not vulnerability tests.

## Evidence

- `evidence/historical_urls_20260721_active/historical_url_active_coverage.csv`
- `evidence/historical_urls_20260721_active/reconciliation_summary.json`
- `evidence/historical_urls_20260721_active/results.jsonl`
- `evidence/historical_urls_20260721_active/followup_results.json`
- `evidence/historical_urls_20260721_active/auth_negative_controls.json`
- `evidence/historical_urls_20260721_active/browser_login_results.json`
- `evidence/historical_urls_20260721_active/source_map_results.json`

The two `superseded_shared_session_*` files are retained only as an audit trail and must not be used for conclusions.

## Method References

- AWS documents that a WAF Challenge response uses status `202` and a JavaScript interstitial, after which the browser acquires a token and resubmits the request: https://docs.aws.amazon.com/waf/latest/APIReference/API_ChallengeAction.html
- OWASP open-redirect guidance informed the absolute, encoded, and protocol-relative destination variants: https://owasp.org/www-community/attacks/open_redirect
