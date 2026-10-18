"""CISA ROLIE indexes and CSAF 2.0 documents, with persistent advisory identity."""

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote, urlsplit

import httpx

from .normalize import extract_ids, safe_url, source_text


def timestamp(value):
    stamp = datetime.fromisoformat(value)
    if stamp.tzinfo is None:
        raise ValueError("Advisory timestamps must include a timezone")
    return stamp.astimezone(UTC)


def scoped_url(url, prefix):
    """Documents and redirects must remain in the configured publisher directory."""
    if not safe_url(url) or not prefix or not url.startswith(prefix):
        return False
    path = unquote(urlsplit(url).path)
    return ".." not in path.split("/") and "\\" not in path and not urlsplit(url).query


def parse_rolie(data, feed):
    payload = json.loads(data)["feed"]
    if not isinstance(payload.get("entry"), list):
        raise ValueError("ROLIE feed is missing its entry list")
    if not any(c.get("term") == "csaf" for c in payload.get("category", [])):
        raise ValueError("ROLIE feed does not advertise CSAF content")
    entries, errors = [], 0
    for entry in payload["entry"]:
        try:
            ident = entry["id"].strip().upper()
            if not ident or len(ident) > 200:
                raise ValueError("Invalid advisory ID")
            url = entry["content"]["src"]
            if not scoped_url(url, feed["document_base_url"]):
                raise ValueError("Document outside configured publisher directory")
            entries.append(
                {
                    "id": ident,
                    "url": url,
                    "published": timestamp(entry["published"]).isoformat(),
                    "updated": timestamp(entry["updated"]).isoformat(),
                }
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            errors += 1
    return entries, errors


def parse_csaf(data, entry, feed, now):
    payload = json.loads(data)
    document = payload["document"]
    tracking = document["tracking"]
    if document["csaf_version"] != "2.0" or tracking["id"].strip().upper() != entry["id"]:
        raise ValueError("Unsupported CSAF version or advisory ID mismatch")
    initial = timestamp(tracking["initial_release_date"])
    current = timestamp(tracking["current_release_date"])
    if current < initial or current > now + timedelta(minutes=5):
        raise ValueError("Invalid advisory release dates")
    version = tracking["version"]
    if not isinstance(version, str) or not version.strip():
        raise ValueError("Missing advisory revision")
    title, _ = source_text(document["title"])
    publisher = document["publisher"]
    if not title or not publisher.get("name"):
        raise ValueError("Missing title or publisher")
    text = [f"Advisory {entry['id']}, version {version}.", f"Publisher: {publisher['name']}."]
    links = {entry["url"]}

    def notes(items):
        for note in items:
            if note.get("category") in {"summary", "description", "details"}:
                value, found = source_text(note["text"], entry["url"])
                text.append(value)
                links.update(found)

    def references(items):
        for ref in items:
            if safe_url(ref.get("url", "")):
                links.add(ref["url"])

    notes(document.get("notes", []))
    references(document.get("references", []))
    products = {}

    def branches(items):
        for branch in items:
            product = branch.get("product")
            if product:
                products[product["product_id"]] = product["name"]
            branches(branch.get("branches", []))

    tree = payload.get("product_tree", {})
    branches(tree.get("branches", []))
    for product in tree.get("full_product_names", []):
        products[product["product_id"]] = product["name"]
    cves = set()
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("Invalid CSAF vulnerabilities")
    for vulnerability in vulnerabilities:
        cve = vulnerability.get("cve", "").upper()
        if cve:
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                raise ValueError("Invalid CSAF CVE")
            cves.add(cve)
        text.append(f"{cve}: {vulnerability.get('title', '')}")
        notes(vulnerability.get("notes", []))
        affected = vulnerability.get("product_status", {}).get("known_affected", [])
        if affected:
            text.append("Affected products: " + "; ".join(products[p] for p in affected if p in products))
        for score in vulnerability.get("scores", []):
            for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
                if key in score:
                    metric = score[key]
                    text.append(f"{key}: {metric.get('baseScore')} {metric.get('vectorString', '')}")
        for remedy in vulnerability.get("remediations", []):
            value, found = source_text(remedy["details"], entry["url"])
            text.append(f"{remedy['category']}: {value}")
            links.update(found)
            references([remedy])
        references(vulnerability.get("references", []))
    summary = "\n".join(text)
    found_cves, techniques = extract_ids(title + " " + summary)
    # Prefer CISA's human-readable self reference when the document provides one.
    url = next(
        (
            r["url"]
            for r in document.get("references", [])
            if r.get("category") == "self"
            and safe_url(r.get("url", ""))
            and urlsplit(r["url"]).hostname in {"cisa.gov", "www.cisa.gov"}
        ),
        entry["url"],
    )
    return {
        "url": url,
        "title": title[:500],
        "summary": summary[:12000],
        "source": feed.get("source_name", feed["name"]),
        "published": current.isoformat(),
        "initial_published": initial.isoformat(),
        "fetched": now.isoformat(),
        "date_inferred": False,
        "cves": sorted(cves | set(found_cves)),
        "attack_techniques": techniques,
        "links": sorted(links),
        "independence_key": feed["independence_key"],
        "advisory_id": entry["id"],
        "advisory_version": version,
        "document_url": entry["url"],
        "publisher": publisher["name"],
    }


class CSAFReader:
    def __init__(self, config, store, fetcher, now):
        self.config, self.store, self.fetcher, self.now = config, store, fetcher, now
        self.locks = {}

    async def collect(self, feed):
        url = feed["url"]
        result = {"name": feed["name"], "ok": True, "new": 0, "updated": 0, "unchanged": 0, "failed": 0}
        cache_key = "csaf:index:" + url
        try:
            data = await self.fetcher.get(url)
            cached = self.store.get(cache_key)
            if data is None and cached is None:
                data = await self.fetcher.get(url, conditional=False)
            if data is not None:
                entries, errors = parse_rolie(data, feed)
                self.store.put(cache_key, {"entries": entries, "errors": errors})
            else:
                entries, errors = cached["entries"], cached["errors"]
            if errors:
                self.store.put("http:" + url, {})
                result["failed"] += errors
            cutoff = self.now - timedelta(days=self.config.settings["retention"]["database_days"])
            candidates = [
                e for e in entries if cutoff <= timestamp(e["updated"]) <= self.now + timedelta(minutes=5)
            ]
            # Newest revisions first; failed documents remain eligible even on index 304.
            candidates.sort(key=lambda e: e["updated"], reverse=True)
            outcomes = await asyncio.gather(*(self.document(e, feed) for e in candidates))
            for outcome in outcomes:
                result[outcome["status"]] += 1
                if outcome["status"] == "failed":
                    result.setdefault("failed_advisories", []).append(outcome)
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as exc:
            self.store.put("http:" + url, {})
            result["failed"] += 1
            result["index_error"] = type(exc).__name__
        result["ok"] = result["failed"] == 0
        if not result["ok"]:
            result["error"] = "Invalid or unavailable ROLIE/CSAF data; failed documents will be retried"
        return result

    async def document(self, entry, feed):
        source_id = feed["independence_key"] + ":" + entry["id"]
        lock = self.locks.setdefault(source_id, asyncio.Lock())
        async with lock:
            existing = self.store.advisory(source_id)
            if existing and existing["index_updated"] >= entry["updated"]:
                return {"status": "unchanged"}
            try:
                data = await self.fetcher.get(
                    entry["url"], conditional=False, url_prefix=feed["document_base_url"]
                )
                article = parse_csaf(data, entry, feed, self.now)
                return {"status": self.store.save_advisory(source_id, article, entry["updated"])}
            except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as exc:
                failure = {"status": "failed", "advisory_id": entry["id"], "error": type(exc).__name__}
                if isinstance(exc, httpx.HTTPStatusError):
                    failure["http_status"] = exc.response.status_code
                return failure
