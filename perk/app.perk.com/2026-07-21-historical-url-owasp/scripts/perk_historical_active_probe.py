#!/usr/bin/env python3
"""Safely validate the OWASP-filtered historical app.perk.com URL corpus.

The harness preserves no response bodies and never writes authentication data.
State-looking browser routes use HEAD. Archived token-bearing onboarding URLs are
replaced with inert markers. Credentials are never sent over HTTP.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import time
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import requests


HOST = "app.perk.com"
COOKIE_FILE = Path("/root/cookies_perk.txt")
HISTORICAL_ROOT = Path("/root/enhanced_recon_framework/evidence/perk.com-historical-urls-20260721")
DEFAULT_OUT = Path("/root/perk_bac_idor_results/evidence/historical_urls_20260721_active")
UA = "authorized-security-research-perk-historical/2026-07-21"
MAX_BODY = 512 * 1024
SLEEP_SECONDS = 0.75


def load_headers(path: Path = COOKIE_FILE) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip()
        if key.lower() in {"cookie", "authorization", "x-csrf-token", "x-xsrf-token"}:
            headers[key] = value.strip()
    if not any(key.lower() == "authorization" for key in headers):
        raise SystemExit("Authorization header missing from credential file")
    return headers


def get_header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def jwt_claims(headers: dict[str, str]) -> dict[str, Any]:
    token = get_header(headers, "authorization").split()[-1]
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def safe_actor(claims: dict[str, Any]) -> dict[str, Any]:
    return {
        key: claims.get(key)
        for key in ("user_id", "account_id", "roles", "actor_type", "auth_method", "login_method", "exp")
        if key in claims
    }


def normalize_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url.strip())
    scheme = parts.scheme.lower() if parts.scheme else "https"
    path = parts.path or "/"
    query = urllib.parse.urlencode(
        sorted(urllib.parse.parse_qsl(parts.query, keep_blank_values=True)), doseq=True
    )
    return urllib.parse.urlunsplit((scheme, HOST, path, query, ""))


def redact_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    pairs = []
    for key, _value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        marker = "[TRACKING_REDACTED]" if key == "_gl" or key == "_gcl_au" or key.startswith("_ga") else "[REDACTED]"
        pairs.append((key, marker))
    query = urllib.parse.urlencode(pairs, doseq=True, safe="[]")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def redact_location(value: str) -> str:
    if not value:
        return ""
    try:
        parts = urllib.parse.urlsplit(value)
        pairs = []
        for key, item in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
            if re.search(r"token|jwt|code|session|auth|key|email", key, re.I) or len(item) > 80:
                item = "[REDACTED]"
            pairs.append((key, item))
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(pairs, doseq=True, safe="[]"), parts.fragment)
        )
    except ValueError:
        return "[UNPARSEABLE_LOCATION]"


def inert_url(url: str, fingerprint: str) -> tuple[str, list[str]]:
    parts = urllib.parse.urlsplit(url)
    notes: list[str] = []
    pairs = []
    sensitive_names = {"uid", "token", "name", "last_name", "account_name", "source"}
    for key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in sensitive_names:
            replacements = {
                "uid": "0",
                "token": f"invalid-codex-{fingerprint}",
                "name": "CodexMarker",
                "last_name": "CodexMarker",
                "account_name": "CodexSecurityTest",
                "source": "security-test",
            }
            value = replacements[key.lower()]
            notes.append("archived_sensitive_query_replaced")
        elif key == "_gl" or key == "_gcl_au" or key.startswith("_ga"):
            notes.append("tracking_query_removed")
            continue
        pairs.append((key, value))
    query = urllib.parse.urlencode(pairs, doseq=True)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")), sorted(set(notes))


def fingerprint(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:12]


def load_candidates() -> list[dict[str, Any]]:
    candidate_rows = list(
        csv.DictReader((HISTORICAL_ROOT / "parsed" / "owasp_candidate_urls.csv").open(encoding="utf-8"))
    )
    originals: dict[str, str] = {}
    for raw in (HISTORICAL_ROOT / "raw" / "all_exact_host_urls_sensitive.txt").read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        url = normalize_url(raw)
        originals[fingerprint(url)] = url
    output = []
    for row in candidate_rows:
        fp = row["url_fingerprint_sha256_12"]
        original = originals.get(fp)
        if not original:
            raise SystemExit(f"historical URL missing for fingerprint {fp}")
        test_url, notes = inert_url(original, fp)
        output.append({**row, "original": original, "test_url": test_url, "notes": notes})
    return output


def state_looking(path: str) -> bool:
    return bool(
        re.search(
            r"(?:approve-and-pay|/approve(?:/|$)|/confirm(?:/|$)|modify-cancel|involuntary-changes|/checkout/)",
            path,
            re.I,
        )
    )


def response_headers(resp: requests.Response) -> dict[str, Any]:
    wanted = {
        "content-type", "content-length", "cache-control", "vary", "access-control-allow-origin",
        "access-control-allow-credentials", "content-security-policy", "strict-transport-security",
        "x-frame-options", "x-content-type-options", "referrer-policy", "server", "allow",
    }
    output = {key.lower(): value for key, value in resp.headers.items() if key.lower() in wanted}
    if "Location" in resp.headers:
        output["location"] = redact_location(resp.headers["Location"])
    cookie_names = []
    for item in resp.headers.get("Set-Cookie", "").split(","):
        if "=" in item:
            name = item.split("=", 1)[0].strip().split()[-1]
            if re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                cookie_names.append(name)
    if cookie_names:
        output["set_cookie_names"] = sorted(set(cookie_names))
    return output


def json_shape(value: Any, depth: int = 0) -> Any:
    if depth > 3:
        return "max_depth"
    if isinstance(value, dict):
        return {key: json_shape(item, depth + 1) for key, item in list(value.items())[:60]}
    if isinstance(value, list):
        return {"type": "array", "length": len(value), "first_shape": json_shape(value[0], depth + 1) if value else None}
    return type(value).__name__


def classify_body(content: bytes, ctype: str) -> dict[str, Any]:
    text = content.decode("utf-8", errors="replace")
    lower = text.lower()
    result: dict[str, Any] = {
        "sampled_length": len(content),
        "sample_sha256": hashlib.sha256(content).hexdigest(),
    }
    if "json" in ctype.lower() or text.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(text)
            result["body_kind"] = "json"
            result["json_shape"] = json_shape(data)
        except Exception:
            result["body_kind"] = "json_unparsed"
    elif "html" in ctype.lower() or "<!doctype html" in lower or "<html" in lower:
        result["body_kind"] = "html"
        result["spa_shell_markers"] = {
            "root_div": bool(re.search(r'id=["\'](?:root|app)["\']', text, re.I)),
            "module_script": "type=\"module\"" in lower or "type='module'" in lower,
            "login_terms": "login" in lower or "sign in" in lower,
        }
        title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if title:
            result["title"] = re.sub(r"\s+", " ", title.group(1)).strip()[:160]
    else:
        result["body_kind"] = "other"
    result["sensitive_key_terms"] = sorted(
        set(re.findall(r"(?i)\b(?:access_token|refresh_token|id_token|client_secret|private_key|password|passport|payment|email)\b", text))
    )
    return result


def request_once(
    session: requests.Session,
    *,
    mode: str,
    method: str,
    url: str,
    auth_headers: dict[str, str],
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    parts = urllib.parse.urlsplit(url)
    if parts.hostname != HOST or parts.scheme not in {"http", "https"}:
        return {"error": "scope_rejected", "mode": mode, "method": method, "url": redact_url(url)}
    notes: list[str] = []
    request_url = url
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
        "User-Agent": UA,
        "Cache-Control": "no-cache",
    }
    if mode == "authenticated":
        if parts.scheme == "http":
            request_url = urllib.parse.urlunsplit(("https", parts.netloc, parts.path, parts.query, ""))
            notes.append("auth_upgraded_to_https")
        headers.update(auth_headers)
    headers.update(extra_headers or {})
    started = time.monotonic()
    try:
        resp = session.request(method, request_url, headers=headers, timeout=25, allow_redirects=False, stream=True)
        content = b""
        if method != "HEAD":
            for chunk in resp.iter_content(16 * 1024):
                if not chunk:
                    continue
                remaining = MAX_BODY - len(content)
                content += chunk[:remaining]
                if len(content) >= MAX_BODY:
                    notes.append("body_sample_truncated")
                    break
        elapsed_ms = int((time.monotonic() - started) * 1000)
        ctype = resp.headers.get("Content-Type", "")
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "mode": mode,
            "method": method,
            "url": redact_url(request_url),
            "status": resp.status_code,
            "elapsed_ms": elapsed_ms,
            "headers": response_headers(resp),
            "body": classify_body(content, ctype) if method != "HEAD" else {"body_kind": "not_read_head"},
            "notes": notes,
        }
    except requests.RequestException as exc:
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "mode": mode,
            "method": method,
            "url": redact_url(request_url),
            "error": type(exc).__name__,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "notes": notes,
        }


def refresh_if_needed(session: requests.Session, headers: dict[str, str], outdir: Path) -> dict[str, Any]:
    claims = jwt_claims(headers)
    seconds = int(claims.get("exp", 0) - time.time()) if claims.get("exp") else None
    result: dict[str, Any] = {"initial_seconds_remaining": seconds, "attempted": False}
    if seconds is None or seconds > 1800:
        return result
    result["attempted"] = True
    url = f"https://{HOST}/api-token-session/"
    opts = session.options(url, headers={**headers, "Accept": "application/json", "User-Agent": UA}, timeout=25, allow_redirects=False)
    result["session_status"] = opts.status_code
    try:
        refresh = opts.json().get("refresh") if opts.status_code == 200 else None
    except Exception:
        refresh = None
    if not refresh:
        result["result"] = "no_refresh_token"
        return result
    post = session.post(
        f"https://{HOST}/api-token-refresh/",
        headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": UA},
        json={"refresh": refresh},
        timeout=25,
        allow_redirects=False,
    )
    result["refresh_status"] = post.status_code
    try:
        data = post.json()
        token = data.get("token") or data.get("access")
    except Exception:
        token = None
    if not token:
        result["result"] = "refresh_failed"
        return result
    auth_key = next((key for key in headers if key.lower() == "authorization"), "Authorization")
    prefix = headers[auth_key].split()[0] if headers.get(auth_key) else "JWT"
    headers[auth_key] = f"{prefix} {token}"
    new_claims = jwt_claims(headers)
    result["result"] = "refreshed_in_memory"
    result["new_seconds_remaining"] = int(new_claims.get("exp", 0) - time.time()) if new_claims.get("exp") else None
    result["actor"] = safe_actor(new_claims)
    return result


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cmd_bootstrap(args: argparse.Namespace) -> int:
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    headers = load_headers()
    auth_session = requests.Session()
    anon_session = requests.Session()
    refresh = refresh_if_needed(auth_session, headers, outdir)
    probes = []
    for mode in ("anonymous", "authenticated"):
        mode_session = anon_session if mode == "anonymous" else auth_session
        probes.append(request_once(mode_session, mode=mode, method="GET", url=f"https://{HOST}/", auth_headers=headers))
        time.sleep(SLEEP_SECONDS)
    probes.append(
        request_once(
            auth_session,
            mode="authenticated",
            method="OPTIONS",
            url=f"https://{HOST}/api-token-session/",
            auth_headers=headers,
            extra_headers={"Accept": "application/json"},
        )
    )
    output = {"actor": safe_actor(jwt_claims(headers)), "refresh": refresh, "probes": probes}
    write_json(outdir / "bootstrap.json", output)
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if any(p.get("status") in {200, 204, 302, 303, 307, 308} for p in probes if p["mode"] == "authenticated") else 2


def cmd_batch(args: argparse.Namespace) -> int:
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    headers = load_headers()
    auth_session = requests.Session()
    anon_session = requests.Session()
    refresh = refresh_if_needed(auth_session, headers, outdir)
    candidates = load_candidates()
    result_path = outdir / "results.jsonl"
    counters = Counter()
    consecutive_429 = 0
    consecutive_failures = 0
    stopped = ""
    with result_path.open("w", encoding="utf-8") as handle:
        for index, candidate in enumerate(candidates, 1):
            test_url = candidate["test_url"]
            method = "HEAD" if state_looking(urllib.parse.urlsplit(test_url).path) else "GET"
            for mode in ("anonymous", "authenticated"):
                mode_session = anon_session if mode == "anonymous" else auth_session
                if mode == "anonymous":
                    mode_session.cookies.clear()
                result = request_once(
                    mode_session, mode=mode, method=method, url=test_url, auth_headers=headers
                )
                result.update(
                    {
                        "candidate_index": index,
                        "fingerprint": candidate["url_fingerprint_sha256_12"],
                        "priority": int(candidate["priority"]),
                        "route_template": candidate["route_template"],
                        "owasp_categories": candidate["owasp_categories"],
                        "candidate_notes": candidate["notes"],
                    }
                )
                handle.write(json.dumps(result, sort_keys=True) + "\n")
                handle.flush()
                counters["requests"] += 1
                counters[f"method_{method}"] += 1
                counters[f"mode_{mode}"] += 1
                if "status" in result:
                    counters[f"status_{result['status']}"] += 1
                else:
                    counters["errors"] += 1
                consecutive_429 = consecutive_429 + 1 if result.get("status") == 429 else 0
                consecutive_failures = consecutive_failures + 1 if "error" in result or int(result.get("status", 0)) >= 500 else 0
                if consecutive_429 >= 3:
                    stopped = "three_consecutive_429"
                    break
                if consecutive_failures >= 5:
                    stopped = "five_consecutive_errors_or_5xx"
                    break
                time.sleep(float(args.delay))
            if stopped:
                break
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actor": safe_actor(jwt_claims(headers)),
        "refresh": refresh,
        "candidate_count": len(candidates),
        "counters": dict(sorted(counters.items())),
        "stopped": stopped or None,
        "result_file": str(result_path),
    }
    write_json(outdir / "batch_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 3 if stopped else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--outdir", default=str(DEFAULT_OUT))
    sub = parser.add_subparsers(dest="command", required=True)
    bootstrap = sub.add_parser("bootstrap")
    bootstrap.set_defaults(func=cmd_bootstrap)
    batch = sub.add_parser("batch")
    batch.add_argument("--delay", type=float, default=SLEEP_SECONDS)
    batch.set_defaults(func=cmd_batch)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
