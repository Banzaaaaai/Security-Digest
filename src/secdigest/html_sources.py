"""Publisher-specific public indexes; no JavaScript or article-page crawling."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .csaf import scoped_url
from .normalize import canonical_url, extract_ids

HTML_INDEX_PARSERS = {
    "amazon_linux_cves": "https://explore.alas.aws.amazon.com/",
    "anthropic_research": "https://www.anthropic.com/research",
}
VOID_TAGS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}
MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}


@dataclass
class Element:
    tag: str
    attrs: dict
    children: list = field(default_factory=list)

    def text(self):
        if self.tag in {"script", "style", "svg"}:
            return ""
        return " ".join(" ".join(c.text() if isinstance(c, Element) else c for c in self.children).split())

    def find(self, tag):
        for child in self.children:
            if isinstance(child, Element):
                if child.tag == tag:
                    yield child
                yield from child.find(tag)


class IndexHTML(HTMLParser):
    """Keep only one table row or research card tree in memory at a time."""

    def __init__(self, kind):
        super().__init__(convert_charrefs=True)
        self.kind = kind
        self.stack = []
        self.table_depth = 0
        self.headers = []
        self.records = []
        self.malformed = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if self.kind == "amazon_linux_cves" and tag == "table":
            if self.table_depth or attrs.get("id") == "index":
                self.table_depth += 1
        selected = (self.kind == "amazon_linux_cves" and self.table_depth and tag == "tr") or (
            self.kind == "anthropic_research" and tag == "article" and "data-listing-row" in attrs
        )
        if self.stack or selected:
            if len(self.stack) >= 64:
                raise ValueError("Publisher index nesting exceeds limit")
            node = Element(tag, attrs)
            if self.stack:
                self.stack[-1].children.append(node)
            if tag not in VOID_TAGS:
                self.stack.append(node)

    def handle_endtag(self, tag):
        if tag == "table" and self.table_depth:
            self.table_depth -= 1
        for position in range(len(self.stack) - 1, -1, -1):
            if self.stack[position].tag == tag:
                root = self.stack[0]
                del self.stack[position:]
                if not self.stack:
                    self.record(root)
                break

    def handle_data(self, data):
        if self.stack:
            self.stack[-1].children.append(data)

    def record(self, root):
        if self.kind == "amazon_linux_cves":
            headers = list(root.find("th"))
            if headers:
                self.headers = [cell.text() for cell in headers]
                return
            cells = list(root.find("td"))
            if len(cells) != 3:
                self.malformed += 1
                return
            link = next(cells[0].find("a"), None)
            self.records.append(
                {
                    "title": cells[0].text(),
                    "summary": cells[1].text(),
                    "date": cells[2].text(),
                    "href": link.attrs.get("href", "") if link else "",
                }
            )
        else:
            heading = next(root.find("h3"), None)
            link = next(heading.find("a"), None) if heading else None
            stamp = next(root.find("time"), None)
            summary = next(
                (p.text() for p in root.find("p") if "metaDescription" in p.attrs.get("class", "")), ""
            )
            self.records.append(
                {
                    "title": heading.text() if heading else "",
                    "summary": summary,
                    "date": (stamp.attrs.get("datetime") or stamp.text()) if stamp else "",
                    "href": link.attrs.get("href", "") if link else "",
                }
            )


def publication_day(value):
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return datetime.fromisoformat(value).replace(tzinfo=UTC)
    match = re.fullmatch(r"([A-Z][a-z]{2}) (\d{1,2}), (\d{4})", value)
    if not match or match[1] not in MONTHS:
        raise ValueError("Missing or invalid publication date")
    return datetime(int(match[3]), MONTHS[match[1]], int(match[2]), tzinfo=UTC)


def parse_html_index(payload, feed, now=None):
    now = now or datetime.now(UTC)
    kind = feed.get("parser")
    if kind not in HTML_INDEX_PARSERS or feed["url"] != HTML_INDEX_PARSERS[kind]:
        raise ValueError("Unsupported publisher index")
    parser = IndexHTML(kind)
    parser.feed(payload.decode("utf-8"))
    parser.close()
    if parser.stack or parser.table_depth or not parser.records:
        raise ValueError("Incomplete or unrecognized publisher index")
    if kind == "amazon_linux_cves" and parser.headers != ["CVE ID", "Description", "Public Date"]:
        raise ValueError("Amazon Linux index columns changed")
    stats = {"entries": len(parser.records), "invalid": parser.malformed, "future": 0, "ignored": 0}
    articles = {}
    for record in parser.records:
        try:
            title, summary = record["title"], record["summary"]
            if not title or not summary:
                raise ValueError("Missing publisher title or summary")
            url = urljoin(feed["url"], record["href"])
            if kind == "amazon_linux_cves":
                if not re.fullmatch(r"CVE-\d{4}-\d{4,}", title):
                    stats["ignored"] += 1  # The publisher also lists preview/test identifiers.
                    continue
                if url != feed["url"] + title + ".html":
                    raise ValueError("CVE link does not match its identifier")
                title += ": " + summary[:300]
                date_basis = "CVE public date, not Amazon Linux advisory or patch release date"
                summary = (
                    "Amazon Linux Security Center CVE record. The index does not establish Amazon Linux "
                    "affected status or patch availability. " + summary
                )
            else:
                if urlsplit(url).netloc == "www.anthropic.com" and urlsplit(url).path.startswith("/news/"):
                    stats["ignored"] += 1
                    continue
                if not scoped_url(url, "https://www.anthropic.com/") or not re.fullmatch(
                    r"/(research|institute)/[^/]+", urlsplit(url).path
                ):
                    raise ValueError("Research article link outside publisher scope")
                date_basis = "Research publication date"
            published = publication_day(record["date"])
            if published > now + timedelta(minutes=5):
                stats["future"] += 1
                continue
            url = canonical_url(url)
            cves, techniques = extract_ids(title + " " + summary)
            article = {
                "url": url,
                "title": title[:500],
                "summary": summary[:12000],
                "source": feed["name"],
                "published": published.isoformat(),
                "fetched": now.isoformat(),
                "date_inferred": False,
                "date_precision": "day",
                "date_basis": date_basis,
                "cves": cves,
                "attack_techniques": techniques,
                "links": [url],
                "independence_key": feed["independence_key"],
            }
            if url in articles and any(articles[url][key] != article[key] for key in ("title", "published")):
                raise ValueError("Conflicting duplicate publisher entries")
            articles[url] = article
        except (ValueError, KeyError):
            stats["invalid"] += 1
    if not articles and not stats["future"]:
        raise ValueError("Publisher index has no usable dated entries")
    return list(articles.values()), stats
