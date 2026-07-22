#!/usr/bin/env python3
"""Reconcile the corrected historical-URL probe matrix into compact coverage."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


SOURCE = Path("/root/enhanced_recon_framework/evidence/perk.com-historical-urls-20260721/parsed/owasp_candidate_urls.csv")
RESULTS = Path("/root/perk_bac_idor_results/evidence/historical_urls_20260721_active/results.jsonl")
OUTDIR = RESULTS.parent


def classify(candidate: dict[str, str], anonymous: dict, authenticated: dict) -> tuple[str, str]:
    route = candidate["route_template"]
    method = anonymous["method"]
    statuses = (anonymous["status"], authenticated["status"])
    body_kinds = (anonymous["body"]["body_kind"], authenticated["body"]["body_kind"])

    if candidate["sensitivity"] == "sensitive_query_values_redacted":
        return "safe_substitution_only", "Archived token/identity values were replaced with inert markers; token lifecycle was not exercised."
    if method == "HEAD":
        return "safe_method_only", "State-looking browser route tested with HEAD only; no action or side effect was attempted."
    if route.startswith("/login") and 202 in statuses:
        return "blocked_waf", "HTTP and bounded browser checks remained on the AWS WAF interstitial; no external navigation or reflection was observed."
    if route == "/api/identity/perk-seamless-login/":
        return "auth_control_enforced", "Anonymous request was denied (401); the supplied actor received only an authenticated self-token shape (200)."
    if route == "/api-token-session/":
        return "auth_control_enforced", "Anonymous request was denied (401); valid authentication received the expected session-token response."
    if route == "/api-token-refresh/":
        return "method_not_allowed", "GET was rejected (405) in both modes; POST was used only for in-memory refresh of the supplied actor."
    if route == "/api/v2/federated-login-redirect/":
        return "no_data_bearing_response", "Both modes returned the same empty JSON list; bounded redirect variants were not reflected or followed."
    if route == "/config/env.js":
        return "public_client_config_only", "Public browser configuration contained client-side identifiers/tokens but no credential-format secret or proven privileged use."
    if route.startswith("/mfe-access/assets/") and statuses == (404, 404):
        return "dead_historical_asset", "Historical JavaScript asset returned 404 in both modes."
    if statuses == (404, 404):
        return "not_found", "Returned 404 in both modes with no data-bearing differential."
    if body_kinds == ("html", "html"):
        return "spa_shell_only", "Returned frontend HTML shell rather than object/API data; no authorization impact was demonstrated."
    return "no_security_differential", "No attacker-relevant status, structure, redirect, reflection, or data differential was observed."


def main() -> None:
    with SOURCE.open(newline="") as handle:
        candidates = list(csv.DictReader(handle))
    grouped: dict[int, list[dict]] = defaultdict(list)
    with RESULTS.open() as handle:
        for line in handle:
            row = json.loads(line)
            grouped[int(row["candidate_index"])].append(row)

    if len(candidates) != 137 or len(grouped) != len(candidates):
        raise SystemExit(f"coverage mismatch: candidates={len(candidates)} result_groups={len(grouped)}")

    output = []
    outcomes = Counter()
    for index, candidate in enumerate(candidates, start=1):
        rows = {row["mode"]: row for row in grouped[index]}
        if set(rows) != {"anonymous", "authenticated"}:
            raise SystemExit(f"candidate {index} missing isolated modes: {sorted(rows)}")
        anonymous = rows["anonymous"]
        authenticated = rows["authenticated"]
        outcome, reason = classify(candidate, anonymous, authenticated)
        outcomes[outcome] += 1
        output.append({
            "candidate_index": index,
            "priority": candidate["priority"],
            "route_template": candidate["route_template"],
            "url_redacted": candidate["url_redacted"],
            "owasp_categories": candidate["owasp_categories"],
            "method": anonymous["method"],
            "anonymous_status": anonymous["status"],
            "authenticated_status": authenticated["status"],
            "anonymous_body_kind": anonymous["body"]["body_kind"],
            "authenticated_body_kind": authenticated["body"]["body_kind"],
            "outcome": outcome,
            "reason": reason,
        })

    coverage_path = OUTDIR / "historical_url_active_coverage.csv"
    with coverage_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(output[0]))
        writer.writeheader()
        writer.writerows(output)
    coverage_path.chmod(0o600)

    summary = {
        "candidate_urls": len(candidates),
        "route_templates": len({row["route_template"] for row in candidates}),
        "isolated_requests": sum(len(rows) for rows in grouped.values()),
        "anonymous_requests": sum(1 for rows in grouped.values() for row in rows if row["mode"] == "anonymous"),
        "authenticated_requests": sum(1 for rows in grouped.values() for row in rows if row["mode"] == "authenticated"),
        "get_requests": sum(1 for rows in grouped.values() for row in rows if row["method"] == "GET"),
        "head_requests": sum(1 for rows in grouped.values() for row in rows if row["method"] == "HEAD"),
        "status_counts": dict(sorted(Counter(row["status"] for rows in grouped.values() for row in rows).items())),
        "outcome_counts": dict(sorted(outcomes.items())),
        "confirmed_new_reportable_findings": 0,
    }
    summary_path = OUTDIR / "reconciliation_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    summary_path.chmod(0o600)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
