# Amazon Linux and Anthropic sources

Verified and enabled on 24 October 2026 after approval to add public-page collectors.
Both sources use the existing HTTP client, robots policy, response-size bounds and
article storage. Configuration now has 69 source definitions, 41 enabled and 28 disabled.

| Source | Publisher page | Collector | Publisher identity |
| --- | --- | --- | --- |
| Amazon Linux Security Center | <https://explore.alas.aws.amazon.com/> | `html_index` / `amazon_linux_cves` | `amazon.com` |
| Anthropic Research | <https://www.anthropic.com/research> | `html_index` / `anthropic_research` | `anthropic.com` |

## Discovery and selection

The requested pages were reachable with the digest's normal User-Agent and did
not advertise RSS/Atom feeds. Anthropic's `/research/rss.xml`, `/research/rss`,
`/research/feed`, `/research/feed.xml`, `/research/atom.xml`, `/rss.xml`,
`/feed.xml` and `/news/rss.xml` candidates returned HTTP 404. These checks establish
that those endpoints are unsuitable, not that an official feed can never exist.

The separate Amazon Linux advisory host returned HTTP 403 for
<https://alas.aws.amazon.com/robots.txt>. The existing collector consequently refused
the `/AL2023/alas.rss` and `/AL2/alas.rss` candidates on that host. Its policy has
not been relaxed. The requested `explore.alas.aws.amazon.com` host returned HTTP 404
for robots.txt, which the existing policy treats as a missing policy and permits.

## Collected content and boundaries

The AWS collector reads the HTML table headed **CVE ID / Description / Public Date**.
It stores the linked CVE identifier, description and public date, and explicitly
identifies the content as a CVE record. This is a vulnerability reference index;
the listing alone does not establish Amazon Linux affected status, patch
availability, active exploitation or an advisory release date. Two nonstandard
preview/test identifiers were ignored. CVE-specific article bodies and the blocked
advisory host are not fetched.

The Anthropic collector reads the current HTML research cards: heading, publisher
summary, publication date and article link. It accepts research and Institute
articles linked from that index on `www.anthropic.com`. Navigation, news links and
embedded JavaScript data are excluded. The observed page rendered 24 cards; its
larger catalog is not fully collected because JavaScript pagination is not run.
Full article bodies are not fetched. Source summaries can therefore provide less
detail than the linked articles.

Both collectors accept only their configured official index URLs. They enforce
publisher article-link scope, refuse missing/invalid dates, exclude future-dated
entries, and fail when the expected layout disappears. Partial entry failures
retain valid entries and mark the source degraded; HTTP conditional metadata is
cleared so the failed content is retried. A normal HTTP 304 retains existing data.
Generic `page_watch` sources remain disabled.

AWS's final observed response was 18,567,080 bytes, within the existing 20,000,000-byte
response limit. Growth beyond that limit will produce a reported fetch failure.
Records are deduplicated by their canonical URLs. As with RSS ingestion, changes
to an already collected index entry do not implement a separate advisory-revision
history; CISA's structured revision handling remains separate.

## Publication dates and report eligibility

These pages provide dates without times. The collector stores the day at midnight
UTC as a day anchor, plus `date_precision: day` and `date_basis`; it does not claim
an observed midnight publication time. Date precision and meaning are also passed
to classification. AWS uses **CVE public date**, while Anthropic uses **research
publication date**. No missing date is replaced by collection time.

The shared report/classification query includes a day-only record when its
publication day overlaps the report window. This prevents a morning digest from
missing yesterday's articles simply because their clock times are unavailable.
Exact-timestamp sources keep their existing behavior. A date-only record can
overlap adjacent daily windows; that is distinct from duplicate storage or duplicate
entries within a report. Older historical entries remain outside the daily window.

## Verification

The final run used the enabled configuration and an in-memory SQLite database.
Conditional HTTP metadata was cleared before the repeat run to exercise article
deduplication rather than relying on HTTP 304.

| Check | Amazon Linux | Anthropic Research |
| --- | ---: | ---: |
| Index entries examined | 33,940 | 24 |
| Valid dated records parsed | 33,938 | 24 |
| Preview/test identifiers ignored | 2 | 0 |
| Records within 120-day retention | 8,835 | 24 |
| Records added on first ingestion | 8,835 | 24 |
| Records added on repeat ingestion | 0 | 0 |
| Parse/fetch failures | 0 | 0 |
| Inferred publication dates | 0 | 0 |

The isolated daily report selected 142 unclassified clusters, demonstrating date-only
eligibility without invoking a model. The first real ingestion will similarly
retain historical records, but routine daily classification selects only the
report window. Verification sent no email and did not modify production state.

All 231 tests passed, including 33 new public-page/date-window cases. Ruff lint
and formatting, the existing incident-grouping fixture check, and daily/weekly
offline previews passed. [Machine-readable evidence](aws-anthropic-verification-2026-10-24.json)
contains timestamps, response hashes, sample URLs and ingestion results.

To repeat the isolated live check:

```powershell
uv run python scripts/verify_html_sources.py
```

The default output is `output/preview/html-source-verification.json`; the check
loads the configured HTML indexes, uses an in-memory database, and does not classify
stories or send email.
