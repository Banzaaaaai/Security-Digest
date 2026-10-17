"""Persistent clustering without transitive CVE roundup merges."""

from collections import defaultdict
from datetime import datetime, timedelta

from rapidfuzz.fuzz import ratio

from .normalize import stable_id


class Clusterer:
    def __init__(self, config, store):
        self.config, self.store = config, store
        self.by_day = defaultdict(list)
        self.urls = set()
        for cluster in store.clusters():
            reference = cluster["articles"][0]
            self.by_day[datetime.fromisoformat(reference["published"]).date()].append(
                (cluster["id"], reference)
            )
            self.urls.update(a["url"] for a in cluster["articles"])

    def add(self, article):
        if article["url"] in self.urls:
            return False
        stamp = datetime.fromisoformat(article["published"])
        days = self.config.scoring["cluster_days"]
        best, best_score = None, -1
        candidates = (
            entry
            for offset in range(-days, days + 1)
            for entry in self.by_day[stamp.date() + timedelta(days=offset)]
        )
        for ident, reference in candidates:
            if abs(stamp - datetime.fromisoformat(reference["published"])) > timedelta(days=days):
                continue
            similarity = ratio(reference["title"].casefold(), article["title"].casefold())
            cves, other = set(reference["cves"]), set(article["cves"])
            cve_match = bool(cves & other) and len(cves | other) <= 3
            if cves and other and not cves.intersection(other):
                continue
            if similarity >= self.config.scoring["title_similarity"] or (
                cve_match and similarity >= self.config.scoring["cve_title_similarity"]
            ):
                if similarity > best_score:
                    best, best_score = ident, similarity
        ident = best or stable_id(article["url"])
        added = self.store.add_article(article, ident)
        self.urls.add(article["url"])
        if not best:
            self.by_day[stamp.date()].append((ident, article))
        return added


def add_article(config, store, article):
    return Clusterer(config, store).add(article)
