# Censys and Shodan source review

Verified on 24 October 2026 against the public publisher websites and feeds.
Both blog feeds are enabled in `config/feeds.yaml` as of 24 October 2026.

## Findings

| Publisher | Official blog | Verified RSS | Latest publication in feed | Digest fit |
| --- | --- | --- | --- | --- |
| Censys | <https://censys.com/resources/blog/> | <https://censys.com/feed/> | 16 October 2026 | Enabled for internet-exposure and threat research, mixed with product news. |
| Shodan | <https://blog.shodan.io/> | <https://blog.shodan.io/rss/> | 7 August 2024 | Enabled to collect future posts if publication resumes; currently no entries inside retention. |

Both feeds are public RSS 2.0, advertised in publisher page metadata, and accessible
with the digest's normal User-Agent and robots.txt checks. No credentials or new
source adapter are needed for these blog feeds. This does not integrate either
vendor's internet-scanning database or search API.

Censys also provides [ARC Security Research](https://censys.com/censys-arc/security-research/)
and [Rapid Response Advisories](https://censys.com/censys-arc/rapid-response-advisories/).
Both pages advertise the same general RSS endpoint. A separate feed for every ARC
advisory was not established, so the blog feed should not be described as
complete ARC advisory coverage.

The Censys feed contains research about industrial-system exposure, threat
infrastructure and iOS exploit infrastructure, alongside product announcements.
Examples include [the Danfoss StoreView exposure report](https://censys.com/blog/frostbitten-in-france-a-danfoss-storeview-internet-exposure-report/)
and [the DarkSword/Coruna report](https://censys.com/blog/darksword-coruna-open-directory-finding-report/).
These examples describe feed coverage; this review does not independently validate
their incident claims. The general feed is not a research-only feed.

Shodan's feed includes Malware Hunter research, favicon-analysis tutorials, service
announcements and changelogs. Its newest listed post is
[5 Free Things for Everybody](https://blog.shodan.io/5-free-things-for-everybody/).
An accessible feed with old entries is different from a failed fetch; no current
publication coverage should be claimed from this result.

## Enabled configuration

These entries are in the `feeds:` list in `config/feeds.yaml`, before the top-level
`enrichment:` section. Shodan watches for future posts without importing its old
posts under current retention settings.

```yaml
- name: Censys Blog
  url: https://censys.com/feed/
  tier: vendor
  site: https://censys.com/resources/blog/
  independence_key: censys.com
  enabled: true
  type: rss
  verified: true
  last_error: ''
  coverage_note: Public research and product posts; not the Censys database or complete ARC advisory coverage.
- name: Shodan Blog
  url: https://blog.shodan.io/rss/
  tier: vendor
  site: https://blog.shodan.io/
  independence_key: shodan.io
  enabled: true
  type: rss
  verified: true
  last_error: ''
  coverage_note: Newest entry was 2024-08-07 at verification on 2026-10-24; no entries inside 120-day retention.
```

Use these publisher identities for any future feeds from the same organizations,
so related feeds do not count as independent corroboration. Standard article
links and publication dates parse correctly; `entry_url_field: id` is unnecessary.

With the entries enabled, the existing ingestion path will collect their feed
summaries. Existing classification, clustering and report-window handling apply.
No application-code changes are required. Censys's currently exposed feed contains
only ten entries, so it is not a historical archive.

Neither feed has an entry in the trailing 24 hours or seven days at verification.
Consequently, adding them does not by itself add stories to the current daily
report. Censys's ten retained stories can be ingested, but daily classification
continues to use the report's 24-hour window. Preserve original publication dates;
do not treat old Shodan entries as newly published when collection starts.

## Verification

The two-feed configuration was validated and exercised with the existing
`Config`, `Fetcher`, `parse_feed` and `ingest` implementations. Tests used an
in-memory SQLite database; no production data, classification or email was involved.

| Check | Censys | Shodan |
| --- | ---: | ---: |
| Feed entries parsed | 10 | 15 |
| Entries with inferred publication dates | 0 | 0 |
| Articles within 120-day retention | 10 | 0 |
| Articles collected on first ingestion | 10 | 0 |
| New articles on repeat ingestion | 0 | 0 |
| Fetch/ingestion failures | 0 | 0 |

Conditional HTTP cache metadata was cleared before the repeat ingestion so the
duplicate check exercised article deduplication rather than relying on HTTP 304.
Machine-readable results, timestamps and response hashes are recorded in
[the verification evidence](censys-shodan-verification-2026-10-24.json).

Two speculative category endpoints were also checked and are unsuitable:
`https://censys.com/category/research/feed/` redirected to an HTML research-access
documentation page, and `https://censys.com/category/threat-intelligence/feed/`
returned HTTP 404. These results do not prove that no other category feed exists;
the publisher-advertised general feed is the verified integration option.
