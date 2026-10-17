"""Conservative URL normalization and source-only indicator extraction."""

import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def safe_url(value):
    try:
        parts = urlsplit(str(value))
        if (
            parts.scheme.lower() not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
        ):
            return ""
        if any(ord(c) < 32 for c in str(value)):
            return ""
        return str(value)
    except ValueError:
        return ""


def canonical_url(value):
    if not safe_url(value):
        raise ValueError("Only absolute HTTP(S) URLs are supported")
    parts = urlsplit(value)
    port = parts.port
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    if port and (parts.scheme.lower(), port) not in {("http", 80), ("https", 443)}:
        host += f":{port}"
    query = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith("utm_") and k.lower() not in {"fbclid", "gclid"}
    ]
    return urlunsplit((parts.scheme.lower(), host, parts.path or "/", urlencode(sorted(query)), ""))


def extract_ids(text):
    return sorted(set(s.upper() for s in CVE.findall(text))), sorted(set(ATTACK.findall(text)))


def stable_id(value):
    return hashlib.sha256(value.encode()).hexdigest()[:24]


class SourceHTML(HTMLParser):
    def __init__(self, base=""):
        super().__init__(convert_charrefs=True)
        self.base, self.text, self.links, self.feeds = base, [], [], []

    def handle_data(self, data):
        self.text.append(data)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        href = safe_url(urljoin(self.base, attrs.get("href", "")))
        if tag == "a" and href:
            self.links.append(href)
        if (
            tag == "link"
            and "alternate" in attrs.get("rel", "").lower()
            and attrs.get("type", "").lower() in {"application/rss+xml", "application/atom+xml"}
            and href
        ):
            self.feeds.append(href)


def source_text(html, base=""):
    parser = SourceHTML(base)
    parser.feed(html)
    return " ".join(parser.text), sorted(set(parser.links))
