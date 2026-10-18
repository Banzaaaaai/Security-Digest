"""Cache public advisory facts and MITRE identifiers without raw API archives."""

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx

from .kev import refresh_kev
from .sources import Fetcher


async def enrich(config, store, now=None):
    now = now or datetime.now(UTC)
    endpoints = config.raw["feeds"]["enrichment"]
    warnings = []
    cves = sorted(
        {cve for cluster in store.clusters() for article in cluster["articles"] for cve in article["cves"]}
    )
    async with Fetcher(config, store) as fetcher:
        warnings.extend(await refresh_kev(config, store, fetcher, now))
        for key, url in (("attack", endpoints["mitre_attack_stix"]),):
            last = store.get(key + ":checked")
            if last and now - datetime.fromisoformat(last) < timedelta(hours=24):
                continue
            try:
                data = await fetcher.get(url, max_bytes=70000000)
                if data is not None:
                    payload = json.loads(data)
                    store.put(
                        key,
                        sorted(
                            {
                                ref["external_id"]
                                for obj in payload["objects"]
                                if obj.get("type") == "attack-pattern"
                                and not obj.get("revoked")
                                and not obj.get("x_mitre_deprecated")
                                for ref in obj.get("external_references", [])
                                if ref.get("source_name") == "mitre-attack"
                                and ref.get("external_id", "").startswith("T")
                            }
                        ),
                    )
                store.put(key + ":checked", now.isoformat())
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                warnings.append(f"{key}: {type(exc).__name__}; cached data retained if available")
        if config.settings["enrichment"]["epss"] and cves:
            values = store.get("epss", {})
            for start in range(0, len(cves), 50):
                try:
                    data = await fetcher.get(
                        endpoints["epss_api"] + "?cve=" + ",".join(cves[start : start + 50]),
                        conditional=False,
                    )
                    values.update({r["cve"]: float(r["epss"]) for r in json.loads(data)["data"]})
                except (httpx.HTTPError, ValueError, KeyError) as exc:
                    warnings.append(f"epss: {type(exc).__name__}")
            store.put("epss", values)
        cvss = store.get("cvss", {})
        for cve in cves:
            if config.settings["enrichment"]["nvd"]:
                try:
                    data = await fetcher.get(endpoints["nvd_api"] + "?cveId=" + cve, conditional=False)
                    for row in json.loads(data).get("vulnerabilities", []):
                        metrics = row["cve"].get("metrics", {})
                        candidates = (
                            metrics.get("cvssMetricV40", [])
                            or metrics.get("cvssMetricV31", [])
                            or metrics.get("cvssMetricV30", [])
                        )
                        if candidates:
                            cvss[cve] = candidates[0]["cvssData"]["baseScore"]
                except (httpx.HTTPError, ValueError, KeyError) as exc:
                    warnings.append(f"nvd: {type(exc).__name__}")
                await asyncio.sleep(6)  # unauthenticated NVD limit
            if config.settings["enrichment"]["github"]:
                try:
                    data = await fetcher.get(
                        endpoints["github_advisories_api"] + "?cve_id=" + cve, conditional=False
                    )
                    for advisory in json.loads(data):
                        value = (advisory.get("cvss") or {}).get("score")
                        if value is not None:
                            cvss.setdefault(cve, value)
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                    warnings.append(f"github: {type(exc).__name__}")
        store.put("cvss", cvss)
    store.put("enrichment_warnings", warnings)
    return warnings
