#!/usr/bin/env python3
"""Bounded CORS, redirect/reflection, and current JavaScript follow-up for Perk."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import perk_historical_active_probe as base  # noqa: E402


OUT = Path("/root/perk_bac_idor_results/evidence/historical_urls_20260721_active")
ORIGIN = "https://example.invalid"
MAX_NORMAL = 768 * 1024
MAX_ASSET = 8 * 1024 * 1024


def mode_headers(all_headers: dict[str, str], mode: str) -> dict[str, str]:
    output = {"Accept": "application/json,text/html,*/*", "User-Agent": base.UA}
    for key, value in all_headers.items():
        lower = key.lower()
        if mode == "full" or (mode == "cookie_only" and lower == "cookie") or (
            mode == "authorization_only" and lower == "authorization"
        ):
            output[key] = value
    return output


def safe_token_claims(token: str) -> dict[str, Any]:
    headers = {"Authorization": f"JWT {token}"}
    return base.safe_actor(base.jwt_claims(headers))


def request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    max_bytes: int = MAX_NORMAL,
) -> tuple[dict[str, Any], bytes]:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname != base.HOST:
        raise ValueError(f"scope rejected: {url}")
    started = time.monotonic()
    session = requests.Session()
    response = session.request(
        method,
        url,
        headers=headers or {"User-Agent": base.UA},
        timeout=30,
        allow_redirects=False,
        stream=True,
    )
    content = b""
    if method != "HEAD":
        for chunk in response.iter_content(32 * 1024):
            if not chunk:
                continue
            content += chunk[: max_bytes - len(content)]
            if len(content) >= max_bytes:
                break
    meta: dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": method,
        "url": base.redact_url(url),
        "status": response.status_code,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "headers": base.response_headers(response),
        "sampled_length": len(content),
        "sample_sha256": hashlib.sha256(content).hexdigest(),
        "truncated": len(content) >= max_bytes,
    }
    return meta, content


def safe_json_analysis(content: bytes) -> dict[str, Any]:
    try:
        data = json.loads(content)
    except Exception:
        return {"json": False}
    result: dict[str, Any] = {"json": True, "shape": base.json_shape(data)}
    if isinstance(data, dict):
        for key in ("token", "access", "access_token", "id_token"):
            value = data.get(key)
            if isinstance(value, str) and value.count(".") == 2:
                result[f"{key}_claims"] = safe_token_claims(value)
        if isinstance(data.get("redirect_to"), str):
            target = urllib.parse.urlsplit(data["redirect_to"])
            result["redirect_to"] = {
                "scheme": target.scheme,
                "host": target.hostname,
                "path": target.path,
                "has_query": bool(target.query),
            }
    return result


def cors_matrix(headers: dict[str, str]) -> list[dict[str, Any]]:
    endpoints = [
        "/api-token-session/",
        "/api/identity/perk-seamless-login/",
        "/api/v2/federated-login-redirect/",
        "/config/env.js",
    ]
    rows = []
    for path in endpoints:
        for method in ("OPTIONS", "GET"):
            for mode in ("anonymous", "cookie_only", "authorization_only", "full"):
                current = mode_headers(headers, mode)
                current["Origin"] = ORIGIN
                if method == "OPTIONS":
                    current["Access-Control-Request-Method"] = "GET"
                    current["Access-Control-Request-Headers"] = "authorization,content-type"
                meta, content = request(f"https://{base.HOST}{path}", method=method, headers=current)
                meta.update({"test": "cors", "mode": mode, "path": path, "json_analysis": safe_json_analysis(content)})
                rows.append(meta)
                time.sleep(0.4)
    return rows


def redirect_reflection_matrix(headers: dict[str, str]) -> list[dict[str, Any]]:
    variants = [
        ("login_https", "/login?coming_from=https%3A%2F%2Fexample.invalid%2Fcodex-perk"),
        ("login_protocol_relative", "/login?coming_from=%2F%2Fexample.invalid%2Fcodex-perk"),
        ("sso_return_to", "/sso-login?return_to=https%3A%2F%2Fexample.invalid%2Fcodex-perk"),
        ("sso_redirect_uri", "/sso-login?redirect_uri=https%3A%2F%2Fexample.invalid%2Fcodex-perk"),
        (
            "federated_redirect_uri",
            "/api/v2/federated-login-redirect/?redirect_uri=https%3A%2F%2Fexample.invalid%2Fcodex-perk&state=codex-marker",
        ),
        (
            "onboard_reflection",
            "/onboard/?uid=0&token=invalid-codex-marker&name=%3Ccodex-marker%3E&last_name=CodexMarker&account_name=CodexSecurityTest&source=security-test",
        ),
    ]
    rows = []
    for name, path in variants:
        for mode in ("anonymous", "full"):
            meta, content = request(
                f"https://{base.HOST}{path}", headers=mode_headers(headers, mode)
            )
            text = content.decode("utf-8", errors="replace")
            meta.update(
                {
                    "test": "redirect_reflection",
                    "variant": name,
                    "mode": mode,
                    "reflection": {
                        "external_host": "example.invalid" in text,
                        "plain_marker": "codex-marker" in text,
                        "raw_custom_tag": "<codex-marker>" in text.lower(),
                        "encoded_custom_tag": "&lt;codex-marker&gt;" in text.lower(),
                        "urlencoded_custom_tag": "%3ccodex-marker%3e" in text.lower(),
                    },
                    "body_kind": base.classify_body(content, meta["headers"].get("content-type", "")).get("body_kind"),
                }
            )
            rows.append(meta)
            time.sleep(0.5)
    return rows


def scan_secret_candidates(data: bytes, asset_url: str) -> list[dict[str, Any]]:
    text = data.decode("utf-8", errors="replace")
    patterns = {
        "aws_access_key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        "github_token": r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b",
        "stripe_secret": r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b",
        "slack_token": r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
        "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    }
    results = []
    for kind, pattern in patterns.items():
        for match in re.finditer(pattern, text):
            value = match.group(0)
            results.append(
                {
                    "kind": kind,
                    "asset": asset_url,
                    "length": len(value),
                    "sha256_12": hashlib.sha256(value.encode()).hexdigest()[:12],
                }
            )
    generic = re.compile(
        r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|secret)\b\s*[:=]\s*[\"']([^\"']{16,512})[\"']"
    )
    for match in generic.finditer(text):
        value = match.group(2)
        results.append(
            {
                "kind": "generic_assignment",
                "name": match.group(1),
                "asset": asset_url,
                "length": len(value),
                "sha256_12": hashlib.sha256(value.encode()).hexdigest()[:12],
                "likely_placeholder": bool(re.search(r"example|placeholder|your[_-]|dummy|test", value, re.I)),
            }
        )
    return results


def scan_asset(data: bytes, url: str) -> dict[str, Any]:
    text = data.decode("utf-8", errors="replace")
    sink_names = [
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
        "new Function", "postMessage", "addEventListener(\"message", "addEventListener('message",
    ]
    source_names = ["location.search", "location.hash", "document.referrer", "localStorage", "sessionStorage"]
    sourcemaps = re.findall(r"(?m)[#@]\s*sourceMappingURL=([^\s*]+)", text)
    endpoints = sorted(set(re.findall(r"[\"'](/(?:api|graphql|oauth|sso|account|company|trips?)/[^\"'\s]{1,220})", text)))[:500]
    return {
        "url": url,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sink_counts": {name: text.count(name) for name in sink_names if text.count(name)},
        "source_counts": {name: text.count(name) for name in source_names if text.count(name)},
        "source_maps": sourcemaps[:30],
        "endpoint_strings": endpoints,
        "secret_candidates": scan_secret_candidates(data, url),
    }


def current_asset_analysis() -> dict[str, Any]:
    rawdir = OUT / "raw_current_assets"
    rawdir.mkdir(parents=True, exist_ok=True)
    os.chmod(rawdir, 0o700)
    html_meta, html = request(
        f"https://{base.HOST}/trips", headers={"Accept": "text/html", "User-Agent": base.UA}, max_bytes=2 * 1024 * 1024
    )
    text = html.decode("utf-8", errors="replace")
    candidates = set()
    for value in re.findall(r"(?:src|href)=[\"']([^\"']+)[\"']", text, re.I):
        absolute = urllib.parse.urljoin(f"https://{base.HOST}/trips", value)
        parts = urllib.parse.urlsplit(absolute)
        if parts.scheme == "https" and parts.hostname == base.HOST and parts.path.endswith(".js"):
            candidates.add(urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, "")))
    candidates.add(f"https://{base.HOST}/config/env.js")
    urls = sorted(candidates)[:60]
    analyses = []
    status_counts = Counter()
    for index, url in enumerate(urls, 1):
        meta, content = request(url, headers={"Accept": "application/javascript,*/*", "User-Agent": base.UA}, max_bytes=MAX_ASSET)
        status_counts[str(meta["status"])] += 1
        record: dict[str, Any] = {"request": meta}
        if meta["status"] == 200 and content:
            filename = f"{index:03d}_{hashlib.sha256(url.encode()).hexdigest()[:12]}.js"
            path = rawdir / filename
            path.write_bytes(content)
            os.chmod(path, 0o600)
            record["saved_file"] = str(path)
            record["analysis"] = scan_asset(content, url)
        analyses.append(record)
        time.sleep(0.5)
    return {
        "html_request": html_meta,
        "discovered_exact_host_js_urls": len(candidates),
        "tested_js_urls": len(urls),
        "status_counts": dict(status_counts),
        "assets": analyses,
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    headers = base.load_headers()
    refresh_session = requests.Session()
    refresh = base.refresh_if_needed(refresh_session, headers, OUT)
    cors = cors_matrix(headers)
    redirect = redirect_reflection_matrix(headers)
    assets = current_asset_analysis()
    output = {"refresh": refresh, "cors": cors, "redirect_reflection": redirect, "current_assets": assets}
    (OUT / "followup_results.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "refresh": refresh,
                "cors_requests": len(cors),
                "redirect_reflection_requests": len(redirect),
                "js_discovered": assets["discovered_exact_host_js_urls"],
                "js_tested": assets["tested_js_urls"],
                "js_status_counts": assets["status_counts"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
