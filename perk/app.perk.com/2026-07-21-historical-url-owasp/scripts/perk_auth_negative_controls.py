#!/usr/bin/env python3
"""Safe JWT rejection controls and value-free cookie-attribute inspection."""

from __future__ import annotations

import base64
import json
import sys
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import perk_historical_active_probe as base  # noqa: E402


OUT = Path("/root/perk_bac_idor_results/evidence/historical_urls_20260721_active/auth_negative_controls.json")
URL = f"https://{base.HOST}/api-token-session/"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def response_shape(response: requests.Response) -> dict[str, Any]:
    result = {
        "status": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
        "length": len(response.content),
    }
    try:
        result["json_shape"] = base.json_shape(response.json())
    except Exception:
        result["json_shape"] = None
    return result


def cookie_attributes(response: requests.Response) -> list[dict[str, Any]]:
    values = []
    raw_headers = getattr(response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        values = raw_headers.getlist("Set-Cookie")
    if not values and response.headers.get("Set-Cookie"):
        values = [response.headers["Set-Cookie"]]
    output = []
    for value in values:
        parsed = SimpleCookie()
        try:
            parsed.load(value)
        except Exception:
            continue
        for name, morsel in parsed.items():
            output.append(
                {
                    "name": name,
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or None,
                    "path": morsel["path"] or None,
                    "domain": morsel["domain"] or None,
                    "max_age_present": bool(morsel["max-age"]),
                }
            )
    return output


def main() -> int:
    headers = base.load_headers()
    authorization = base.get_header(headers, "authorization")
    scheme, token = authorization.split(None, 1)
    token_parts = token.split(".")
    if len(token_parts) != 3:
        raise SystemExit("supplied Authorization value is not a three-part JWT")
    header_part = token_parts[0] + "=" * (-len(token_parts[0]) % 4)
    jwt_header = json.loads(base64.urlsafe_b64decode(header_part))
    tampered = token_parts[0] + "." + token_parts[1] + "." + ("A" if not token_parts[2].endswith("A") else "B")
    none_header = b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    none_token = none_header + "." + token_parts[1] + "."
    controls = []
    for name, value in (
        ("missing", None),
        ("tampered_signature", f"{scheme} {tampered}"),
        ("alg_none", f"{scheme} {none_token}"),
        ("valid_authorization_only", authorization),
    ):
        request_headers = {"Accept": "application/json", "User-Agent": base.UA}
        if value:
            request_headers["Authorization"] = value
        response = requests.get(URL, headers=request_headers, timeout=25, allow_redirects=False)
        controls.append({"control": name, **response_shape(response)})
    full_response = requests.options(
        URL,
        headers={**headers, "Accept": "application/json", "User-Agent": base.UA},
        timeout=25,
        allow_redirects=False,
    )
    output = {
        "jwt_header": {key: jwt_header.get(key) for key in ("alg", "typ", "kid") if key in jwt_header},
        "controls": controls,
        "set_cookie_attributes": cookie_attributes(full_response),
    }
    OUT.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
