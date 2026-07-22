#!/usr/bin/env python3
"""Fetch exact current app.perk.com source-map references at a conservative rate."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.parse
from collections import Counter
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
import perk_historical_active_probe as base  # noqa: E402
import perk_historical_followup as follow  # noqa: E402


OUT = Path("/root/perk_bac_idor_results/evidence/historical_urls_20260721_active")


def main() -> int:
    data = json.loads((OUT / "followup_results.json").read_text(encoding="utf-8"))
    pairs = set()
    for item in data["current_assets"]["assets"]:
        analysis = item.get("analysis", {})
        asset_url = analysis.get("url")
        if not asset_url:
            continue
        for reference in analysis.get("source_maps", []):
            url = urllib.parse.urljoin(asset_url, reference)
            parts = urllib.parse.urlsplit(url)
            if parts.scheme == "https" and parts.hostname == base.HOST:
                pairs.add((asset_url, urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))))
    rawdir = OUT / "raw_source_maps"
    rawdir.mkdir(parents=True, exist_ok=True)
    os.chmod(rawdir, 0o700)
    rows = []
    counts = Counter()
    for index, (asset_url, map_url) in enumerate(sorted(pairs), 1):
        meta, content = follow.request(
            map_url,
            headers={"Accept": "application/json,*/*", "User-Agent": base.UA},
            max_bytes=24 * 1024 * 1024,
        )
        counts[str(meta["status"])] += 1
        row = {"asset_url": asset_url, "map_url": map_url, "request": meta}
        if meta["status"] == 200 and content.lstrip().startswith(b"{"):
            try:
                parsed = json.loads(content)
            except Exception:
                parsed = None
            if isinstance(parsed, dict) and isinstance(parsed.get("sources"), list):
                filename = f"{index:03d}_{hashlib.sha256(map_url.encode()).hexdigest()[:12]}.map"
                path = rawdir / filename
                path.write_bytes(content)
                os.chmod(path, 0o600)
                contents = parsed.get("sourcesContent") if isinstance(parsed.get("sourcesContent"), list) else []
                combined = "\n".join(item for item in contents if isinstance(item, str)).encode()
                row["map_analysis"] = {
                    "saved_file": str(path),
                    "sources": len(parsed["sources"]),
                    "sources_content": len(contents),
                    "source_names": [str(name)[:240] for name in parsed["sources"][:200]],
                    "secret_candidates": follow.scan_secret_candidates(combined, map_url),
                    "sources_content_bytes": len(combined),
                }
        rows.append(row)
        time.sleep(0.5)
    output = {"map_references": len(pairs), "status_counts": dict(counts), "rows": rows}
    (OUT / "source_map_results.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"map_references": len(pairs), "status_counts": dict(counts), "maps_with_sources": sum("map_analysis" in row for row in rows)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
