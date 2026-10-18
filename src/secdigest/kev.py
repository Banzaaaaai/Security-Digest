"""Validated KEV snapshots with official-mirror fallback and rollback protection."""

import json
import re
from datetime import date, timedelta

import httpx

from .csaf import timestamp


def parse_kev(data):
    payload = json.loads(data)
    released = timestamp(payload["dateReleased"]).isoformat()
    version = payload["catalogVersion"]
    rows = payload["vulnerabilities"]
    if not isinstance(version, str) or not version or not isinstance(rows, list) or not rows:
        raise ValueError("Invalid KEV catalog")
    if payload["count"] != len(rows):
        raise ValueError("Incomplete KEV catalog")
    values = {}
    for row in rows:
        cve = row["cveID"]
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve) or cve in values:
            raise ValueError("Invalid or duplicate KEV CVE")
        for field in ("dateAdded", "dueDate"):
            date.fromisoformat(row[field])
        fields = (
            "dateAdded",
            "vendorProject",
            "product",
            "requiredAction",
            "dueDate",
            "knownRansomwareCampaignUse",
        )
        if any(not isinstance(row.get(field), str) for field in fields):
            raise ValueError("Missing KEV facts")
        values[cve] = {field: row[field] for field in fields}
    return values, {"released": released, "version": version, "count": len(values)}


async def refresh_kev(config, store, fetcher, now):
    endpoints = config.raw["feeds"]["enrichment"]
    primary = endpoints["cisa_kev_json"]
    urls = list(dict.fromkeys(filter(None, (primary, endpoints.get("cisa_kev_fallback_json")))))
    last = store.get("kev:checked")
    provenance = store.get("kev:provenance", {})
    if (
        last
        and store.get("kev")
        and now - timestamp(last) < timedelta(hours=config.settings["enrichment"].get("kev_refresh_hours", 6))
    ):
        return (
            ["KEV: using the official GitHub mirror; primary unavailable at last check"]
            if provenance.get("source") and provenance["source"] != primary
            else []
        )
    failures = []
    for url in urls:
        try:
            # Only revalidate a URL when its validators describe the active snapshot.
            conditional = bool(store.get("kev") and provenance.get("source") == url)
            if not conditional:
                store.put("http:" + url, {})
            data = await fetcher.get(url, max_bytes=20000000)
            if data is not None:
                values, metadata = parse_kev(data)
                if timestamp(metadata["released"]) > now + timedelta(minutes=5):
                    raise ValueError("KEV catalog release is in the future")
                if provenance.get("released") and timestamp(metadata["released"]) < timestamp(
                    provenance["released"]
                ):
                    raise ValueError("KEV source is older than the cached catalog")
                provenance = {**metadata, "source": url, "checked": now.isoformat()}
                # Store snapshot and provenance atomically, never a partial catalog.
                with store.db:
                    for key, value in (("kev", values), ("kev:provenance", provenance)):
                        store.db.execute("INSERT OR REPLACE INTO kv VALUES (?,?)", (key, json.dumps(value)))
            elif not conditional:
                raise ValueError("KEV returned 304 without a matching cached snapshot")
            else:
                provenance = {**provenance, "checked": now.isoformat()}
                store.put("kev:provenance", provenance)
            store.put("kev:checked", now.isoformat())
            return (
                ["KEV: using the official GitHub mirror; primary unavailable or invalid"]
                if url != primary
                else []
            )
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as exc:
            # The HTTP client caches validators before JSON validation; do not retain
            # validators for a rejected body, which would otherwise strand the cache.
            store.put("http:" + url, {})
            failures.append(type(exc).__name__)
    state = "cached data retained" if store.get("kev") else "no KEV data available"
    return [f"KEV: all configured sources failed ({', '.join(failures)}); {state}"]
