"""Small transactional SQLite store with explicit schema versioning."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .normalize import stable_id


class Store:
    def __init__(self, path: Path | str):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS clusters (id TEXT PRIMARY KEY, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS articles (
          url TEXT PRIMARY KEY, cluster_id TEXT NOT NULL REFERENCES clusters(id),
          published TEXT NOT NULL, payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS articles_date ON articles(published);
        CREATE INDEX IF NOT EXISTS articles_cluster ON articles(cluster_id);
        CREATE TABLE IF NOT EXISTS classifications (
          cluster_id TEXT PRIMARY KEY REFERENCES clusters(id) ON DELETE CASCADE,
          payload TEXT NOT NULL, fingerprint TEXT NOT NULL, model TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS deliveries (
          kind TEXT NOT NULL, period TEXT NOT NULL, sent TEXT NOT NULL,
          PRIMARY KEY(kind, period));
        CREATE TABLE IF NOT EXISTS advisories (
          source_id TEXT PRIMARY KEY,
          url TEXT UNIQUE NOT NULL REFERENCES articles(url) ON DELETE CASCADE,
          index_updated TEXT NOT NULL, released TEXT NOT NULL, version TEXT NOT NULL);
        PRAGMA user_version=2;
        """)

    def close(self):
        self.db.close()

    def get(self, key, default=None):
        row = self.db.execute("SELECT payload FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key, payload):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO kv VALUES (?,?)", (key, json.dumps(payload, default=str)))

    def article(self, url):
        row = self.db.execute("SELECT payload FROM articles WHERE url=?", (url,)).fetchone()
        return json.loads(row[0]) if row else None

    def add_article(self, article, cluster_id):
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO clusters VALUES (?,?)", (cluster_id, article["published"]))
            cursor = self.db.execute(
                "INSERT OR IGNORE INTO articles VALUES (?,?,?,?)",
                (article["url"], cluster_id, article["published"], json.dumps(article)),
            )
        return cursor.rowcount > 0

    def advisory(self, source_id):
        row = self.db.execute("SELECT * FROM advisories WHERE source_id=?", (source_id,)).fetchone()
        return dict(row) if row else None

    def save_advisory(self, source_id, article, index_updated):
        """One article per publisher/advisory ID; revisions invalidate classification."""
        existing = self.advisory(source_id)
        released, version = article["published"], article["advisory_version"]
        with self.db:
            if existing:
                if released < existing["released"]:
                    return "unchanged"  # A lagging feed must never roll back a revision.
                self.db.execute(
                    "UPDATE advisories SET index_updated=max(index_updated,?) WHERE source_id=?",
                    (index_updated, source_id),
                )
                if released == existing["released"] and version == existing["version"]:
                    return "unchanged"
                # Keep the stable article URL and cluster even if a revised document moves.
                article = {**article, "url": existing["url"]}
                self.db.execute(
                    "DELETE FROM classifications WHERE cluster_id="
                    "(SELECT cluster_id FROM articles WHERE url=?)",
                    (existing["url"],),
                )
                self.db.execute(
                    "UPDATE articles SET published=?,payload=? WHERE url=?",
                    (released, json.dumps(article), existing["url"]),
                )
                self.db.execute(
                    "UPDATE advisories SET released=?,version=? WHERE source_id=?",
                    (released, version, source_id),
                )
                return "updated"
            ident = stable_id("csaf:" + source_id)
            row = self.db.execute("SELECT cluster_id FROM articles WHERE url=?", (article["url"],)).fetchone()
            if row:
                if self.db.execute("SELECT 1 FROM advisories WHERE url=?", (article["url"],)).fetchone():
                    raise ValueError("Different advisory IDs claim the same article URL")
                ident = row[0]
                self.db.execute("DELETE FROM classifications WHERE cluster_id=?", (ident,))
                self.db.execute(
                    "UPDATE articles SET published=?,payload=? WHERE url=?",
                    (released, json.dumps(article), article["url"]),
                )
            else:
                self.db.execute("INSERT OR IGNORE INTO clusters VALUES (?,?)", (ident, released))
                self.db.execute(
                    "INSERT INTO articles VALUES (?,?,?,?)",
                    (article["url"], ident, released, json.dumps(article)),
                )
            self.db.execute(
                "INSERT INTO advisories VALUES (?,?,?,?,?)",
                (source_id, article["url"], index_updated, released, version),
            )
            return "new"

    def clusters(self, start=None, end=None):
        clauses, args = [], []
        if start:
            clauses.append("published >= ?")
            args.append(start.isoformat())
        if end:
            clauses.append("published < ?")
            args.append(end.isoformat())
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        ids = [r[0] for r in self.db.execute("SELECT DISTINCT cluster_id FROM articles" + where, args)]
        result = []
        for ident in ids:
            articles = [
                json.loads(r[0])
                for r in self.db.execute(
                    "SELECT payload FROM articles WHERE cluster_id=? ORDER BY published", (ident,)
                )
            ]
            classification = self.db.execute(
                "SELECT payload FROM classifications WHERE cluster_id=?", (ident,)
            ).fetchone()
            result.append(
                {
                    "id": ident,
                    "articles": articles,
                    "classification": json.loads(classification[0]) if classification else None,
                }
            )
        return result

    def classify(self, ident, payload, fingerprint, model):
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO classifications VALUES (?,?,?,?)",
                (ident, json.dumps(payload), fingerprint, model),
            )

    def was_sent(self, kind, period):
        return (
            self.db.execute("SELECT 1 FROM deliveries WHERE kind=? AND period=?", (kind, period)).fetchone()
            is not None
        )

    def mark_sent(self, kind, period, now):
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO deliveries VALUES (?,?,?)", (kind, period, now.isoformat())
            )

    def prune(self, cutoff):
        with self.db:
            self.db.execute("DELETE FROM articles WHERE published < ?", (cutoff.isoformat(),))
            self.db.execute("DELETE FROM clusters WHERE id NOT IN (SELECT DISTINCT cluster_id FROM articles)")
        self.db.execute("VACUUM")
