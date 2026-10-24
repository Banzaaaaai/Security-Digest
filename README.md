# SecDigest

Daily and weekly security intelligence for enterprise security architecture. Collect RSS/Atom stories, supported public-page indexes and CISA structured advisories, cluster duplicate coverage, enrich CVEs, classify with OpenAI, and generate Markdown, HTML, JSON, CSV and Gmail-ready email.

The original requirements are in [security-digest-prompt.md](security-digest-prompt.md). All taxonomies and scoring rules are editable YAML. There is no web server or hosted dashboard to operate.

## Current status

As of **22 October 2026**, scheduled daily collection, classification and email delivery are working. The scoring review covers all **106 stories in the supplied daily email**, plus seven additional stories from the later run. **PHP now leads at 96/100**, with **95% relevance in US, Europe, MEA and Other**. Relevance measures applicability to affected environments, not attack probability.

Priority now uses **60% severity, 15% location, 10% industry and 15% technical practice**, bounded by severity bands. Global software issues receive consistent regional relevance, all four regions participate, and source volume no longer raises severity. See the [review and evidence](docs/scoring-review-2026-10-22.md) for the full rationale and limitations.

| Current evidence | Result |
|---|---|
| Corrected supplied digest | [HTML](output/review/2026-10-22-original/daily/2026-10-22.html), [Markdown](output/review/2026-10-22-original/daily/2026-10-22.md), [JSON](output/review/2026-10-22-original/daily/2026-10-22.json), [CSV](output/review/2026-10-22-original/daily/2026-10-22.csv); 103 entries after three additional duplicate removals: 14 critical, 35 high, 40 medium, 14 low |
| Score comparison | [All 106 original stories, before and after](output/review/2026-10-22-original/comparison.csv), with [full score components and source evidence](output/review/2026-10-22-original/comparison.json) |
| Corrected later run | [HTML](output/review/2026-10-22-latest/daily/2026-10-22.html) and [105-story comparison](output/review/2026-10-22-latest/comparison.csv); 102 entries: 16 critical, 35 high, 38 medium, 13 low |
| Preserved live archive | [22 October report](output/daily/2026-10-22.md) and [JSON](output/daily/2026-10-22.json), generated before the scoring revision; 105 entries and no unclassified clusters |
| Sources | 69 definitions; 41 enabled, 28 disabled as of 24 October. Includes Censys/Shodan RSS and verified Amazon Linux/Anthropic public-page collectors |
| Coverage limits | One failed CISA IT advisory (`VA-26-274-03`, HTTP 404); successful advisories retained. KEV uses the official GitHub mirror after primary-source failure |
| Delivery | The 22 October 09:51 UTC run recorded successful SMTP delivery; the 10:47 UTC run skipped sending because that day's digest had already been sent. The scoring review did not send a replacement |
| Scheduling | Daily enabled; weekly disabled. Scheduled runs succeeded on 21–22 October; delayed same-day jobs are allowed and duplicate email is suppressed |
| Validation | **231 tests passed** on 24 October, Ruff checks and formatting passed, and offline daily/weekly previews completed |

The [run log](run_log.json), archived JSON and separate review artifacts preserve the distinction between the delivered report and recalculated scores. The next daily run uses the updated scoring policy. Live weekly synthesis, asynchronous Batch API execution, inbox receipt and Gmail/Outlook client presentation remain unverified; see [VALIDATION.md](VALIDATION.md).

## How it works

1. Collect feed summaries and structured advisory facts into SQLite, retaining source links, publication times and advisory revisions.
2. Cluster overlapping articles, enrich CVEs with KEV and optional advisory services, and classify new daily-window clusters with `gpt-5.4-mini`.
3. Validate generated evidence, apply configured relevance and importance rules, and merge matching incidents before calculating report totals.
4. Render the daily digest or build the weekly report from stored classifications, using `gpt-5.4` for weekly synthesis.
5. Write the archives and an optional MIME preview, or deliver email and record the report period to suppress repeat sends.

Weekly reports add an executive summary, previous-week comparisons, region and sector views, relevance heatmaps, a regulatory calendar, detection coverage, a watchlist and content outlines. News story details show location, industry and technology relevance on separate lines and omit the former "Relevant to your work" links. Case-study metadata remains available for weekly related-work sections, content outlines and structured exports.

## Quick start

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run from this folder:

```powershell
uv sync --locked --python 3.12 --group dev
uv run secdigest config check
uv run secdigest --dry-run
uv run secdigest --dry-run weekly --preview
```

Python 3.12 or newer is required. You can also use `.venv\Scripts\secdigest.exe` directly on Windows. This workspace has an alternate `.venv-openai` environment used for validation; to reuse it with uv, set `$env:UV_PROJECT_ENVIRONMENT = '.venv-openai'` before running the commands above.

Dry runs use a fixed clock and 12 synthetic clusters / 14 source items. They make **no network calls and send no email**, even with `--send` or `--force-send`. They use an in-memory database and write only under `output/samples/`:

- [Daily HTML preview](output/samples/daily/2026-10-17.html)
- [Weekly HTML preview](output/samples/weekly/2026-W42.html)
- `output/samples/preview/secdigest-daily-2026-10-17.eml`
- `output/samples/preview/secdigest-weekly-2026-W42.eml`

These are demonstrations, not live news reports. Open the HTML files in a browser. Open the `.eml` files in a mail client; review an actual delivered test in Gmail on desktop and phone before enabling schedules.

## Live operation

Set environment variables through your shell/session or secret manager. The application deliberately does not read a checked-in `.env` file. Never put credentials in YAML, source code or Git.

| Variable | Use |
|---|---|
| `OPENAI_API_KEY` | OpenAI classification and weekly synthesis |
| `OPENAI_BASE_URL` | Optional API endpoint/base URL; defaults to `https://api.openai.com/v1` when omitted or blank |
| `SMTP_HOST` | SMTP server; defaults to `smtp.gmail.com` |
| `SMTP_PORT` | STARTTLS port; defaults to `587` |
| `SMTP_USER` | Gmail sender address |
| `SMTP_PASSWORD` | Gmail app password |
| `EMAIL_TO` | Comma-separated recipient addresses; whitespace and empty entries removed |

The defaults in `config/settings.yaml` are `gpt-5.4-mini` for classification and `gpt-5.4` for weekly synthesis. Both use the OpenAI Responses API with strict function schemas and local evidence validation. Live classification checks model metadata when permitted. If the metadata endpoint returns 403, the requested API operation validates model access instead, since model reading and generation have separate permissions. Generation errors still stop the run; it does not silently choose another model. Access depends on the configured provider and API project. Set `OPENAI_API_KEY` and, if needed, `OPENAI_BASE_URL` for this integration.

For a custom API endpoint, add a GitHub Actions repository secret named **`OPENAI_BASE_URL`**, alongside **`OPENAI_API_KEY`**. Set it to the provider's API base URL, for example `https://gateway.example.com/v1` or `https://resource.openai.azure.com/openai/v1`. Include the provider's required path prefix, but omit operation suffixes such as `/responses` or `/chat/completions`, credentials, query parameters and fragments. The application uses this endpoint for classification, weekly synthesis, model lookup and Batch/Files API calls. The provider must support the Responses API with strict function calls and the configured model IDs; batch backfills also require its Batch/Files APIs. Configure model names and pricing for that provider in `config/settings.yaml`. Do not change the endpoint while a batch job is pending.

The same environment variable works locally. Surrounding whitespace is trimmed; an empty GitHub secret keeps the standard OpenAI endpoint. Fixture mode removes both API settings and stays offline. The endpoint is not printed in application logs.

```powershell
# Validate sources, then collect and classify the daily window without sending.
uv run secdigest feeds check
uv run secdigest run-daily --no-send --preview

# Re-render stored daily classifications or synthesize a selected week.
uv run secdigest daily --preview
uv run secdigest weekly --week 2026-W42 --preview
```

For collection without classification, use `uv run secdigest ingest`. To test SMTP or deliver a full digest:

```powershell
uv run secdigest email test
uv run secdigest run-daily
```

`run-daily` classifies only the report's 24-hour window. This matters because some feeds, especially MSRC, expose thousands of historical entries. Regular daily runs reuse previously stored classifications. `weekly` and `run-weekly` use stored classifications and synthesize the week's summary; they do not ingest or reclassify stories. Reports prominently show the count of unclassified clusters so incomplete collection is not represented as a quiet period.

For today's date, the daily window ends at execution time and covers the preceding 24 hours. An explicit historical date ends at the following local midnight and also covers 24 hours. Weekly reports default to the previous Monday-to-Monday calendar week in `Europe/Amsterdam`; `--week` selects an ISO week, and `weekly.window: rolling` selects the preceding seven days when no week is supplied. Regenerating a report uses the current stored classifications and advisory cache, so it is not an immutable historical snapshot.

A local live preview still ingests or synthesizes as requested and writes the local database, archives and run log; `--preview` suppresses email delivery. Use `--dry-run` for the isolated offline demonstration. GitHub Actions preview modes discard database changes after the run.

After classification, a second duplicate check combines matching incident coverage into one report entry with all distinct source links. Besides normalized headline/summary matching, it recognizes source-supported named events such as PHP2Shell even when feeds omit CVEs. Product-specific vulnerability reports can match through compatible event context; supply-chain reports require a shared product and additional source-supported distribution/tooling context. Differing named subjects, CVEs, advisory IDs, actors, regulatory events and conflicting vulnerability mechanisms remain protected. Roundups are excluded, and every member of a group must match every other member. `scoring.yaml` → `post_dedup` controls the 48-hour publication window, general similarity thresholds (70/65) and product/event thresholds (55/50). This is a conservative text heuristic: ambiguous matches remain separate. It adds no API calls and leaves stored articles and classifications intact.

The representative is selected by severity, then priority. Merged summaries attribute the representative and complementary sentences to their sources; additional actions are retained without generating new claims. Repeated wording and generic analytical restatements are omitted from the compact narrative. JSON `source_coverage` preserves each member's full original summary, action and source links. Original relevance scores are retained before deterministic recalibration. Validated CVEs, technologies, actors, techniques, detection links and countries are combined, and scoring overrides are recomputed from the original model values. An exact CVE set plus a shared affected product can also combine vulnerability disclosures, patch notices and exploitation updates despite different headlines. Deduplication runs before daily and weekly totals, previous-week comparisons, synthesis and every output format, including email. JSON includes `duplicates_removed` and each merged item's `merged_cluster_ids`; the run log also records the removed count.

The [23 October duplicate review](docs/deduplication-review-2026-10-23.md) replays the delivered window against its matching source snapshot: **94 stories become 85**, retaining all source links. The PHP2Shell early-exploitation coverage becomes one item with six articles from five publishers; LiteLLM and VeloCloud each combine three articles. A [separate corrected preview](output/review/2026-10-23-deduplicated/daily/2026-10-23.html) preserves the original delivery and database.

Both scheduled and manually dispatched daily/weekly workflows run `scripts/check_digest_deduplication.py` before report generation. This offline check exercises the installed production report builder with the saved duplicate examples: it verifies expected incident groups, all source links, and complementary details. A failure prevents the `Run digest` step from executing. CI runs the same check and the broader regression suite. The daily and weekly commands share the deduplication logic; no separate workflow-specific matching implementation is used.

For an initial backfill, `secdigest classify` processes **all unclassified stored clusters** and can incur substantial API usage. Prefer the asynchronous batch option:

```powershell
uv run secdigest classify --batch-api
# Repeat this command later to consume completed results.
uv run secdigest classify --batch-api
uv run secdigest weekly --week 2026-W42 --preview
```

OpenAI Batch API input file IDs, job IDs and memberships are persisted in SQLite. Jobs target `/v1/responses` with a 24-hour completion window. A pending batch is logged as pending, does not produce a success digest, and is resumed without resubmission. Keep configuration unchanged while a batch is pending. Failed or missing requests remain unclassified for a subsequent run. A pending job from another provider must be resolved before migration. `--reclassify` explicitly replaces saved classifications.

## Commands

| Command | Behavior |
|---|---|
| `secdigest ingest` | Validate sources on first run, ingest summaries and refresh advisory data |
| `secdigest classify [--reclassify] [--batch-api]` | Classify all pending stored clusters or resume a batch |
| `secdigest daily [--date YYYY-MM-DD]` | Render the daily archive from stored classifications |
| `secdigest weekly [--week YYYY-Www]` | Render a weekly archive and generate/reuse its synthesis |
| `secdigest run-daily [--date ...] [--force-send]` | Ingest, enrich, classify the daily window, render and send |
| `secdigest run-weekly [--week ...] [--force-send]` | Render the weekly digest from stored classifications and send |
| `secdigest email test` | Send a short real SMTP test to `EMAIL_TO` |
| `secdigest feeds check` | Revalidate all sources, discover feed links, update source status |
| `secdigest config check` | Validate config and taxonomy cross-references |
| `secdigest schedule-guard daily\|weekly` | Print `true` or `false` for scheduled execution |
| `secdigest --dry-run` | Generate the complete synthetic daily report and email preview |

All report commands accept mutually exclusive `--send` / `--no-send`, plus `--preview`. A preview writes the exact MIME message without sending, even if combined with `--send`. Standalone `daily`/`weekly` commands default to no sending; `run-*` defaults to delivery. `--root PATH` selects a project folder and goes before the command. `--dry-run` can go before a command or after a pipeline/report command.

Email story details display **Location relevance**, **Industry relevance** and **Technology relevance** on separate labeled lines in both HTML and plain text. The HTML priority table uses the same layout. Technology relevance shows the existing technical practice-area scores; the labels and line breaks do not change scoring.

Optional full text is available for classification only:

```powershell
uv sync --extra fulltext
uv run secdigest classify --fetch-fulltext
```

Full text is fetched under the site's robots policy, used transiently as classification context and never archived or republished. Feed and supported index summaries remain the audit evidence, so detection links and dates absent from summaries are conservatively omitted. Generic `page_watch` sources remain disabled. Explicit `html_index` collectors support only the configured Amazon Linux CVE index and Anthropic Research listing; they collect index summaries without crawling article bodies or executing JavaScript.

## Configuration

All files below live in [`config/`](config/). The current configuration defines 4 regions, 10 industries and 11 technical practice areas.

| File | Controls |
|---|---|
| `settings.yaml` | Timezone, file paths, HTTP limits, models, pricing, optional enrichment, email, retention, activation |
| `feeds.yaml` | All 69 source definitions, discovered URLs, enabled state, verification status, advisory endpoints and supported HTML index parsers |
| `regions.yaml` | Region keys, priority-country mappings, country aliases and bonuses |
| `industries.yaml` | Industry keys, display names and classification signals |
| `practice_areas.yaml` | Practice keys, display names and classification signals |
| `watch_tech.yaml` | Products grouped by vendor, aliases and cross-industry applicability |
| `regulations.yaml` | Regulation keys, jurisdiction, region, relevant industries and milestones |
| `case_studies.yaml` | Published anonymized studies and sector/practice/country references |
| `writing.yaml` | Published writing used by content outlines |
| `scoring.yaml` | Importance rubric, weights, severity bands, global deployment profiles, aliases, deduplication thresholds and inclusion rules |

The JSON tool schema and cached system prompt are generated at runtime from these files. Adding an industry or practice requires no Python edits. Existing classifications do not silently acquire scores for new keys: explicitly reclassify affected stored clusters after a taxonomy change. Run `config check` after edits.

To add a case study, append a slug entry to `case_studies.yaml` containing `title`, `industry`, `country`, `practice_areas` and `url`. Use existing industry/practice keys and an anonymized published URL. A case study can be linked only when its sector, country or practice overlaps the story. Never add client names.

To add a technology alias, extend that product's `aliases` list. Matching is case insensitive and uses word boundaries. Set `cross_industry: true` for generic enterprise platforms that should raise every industry score to the configured minimum.

Set `independence_key` on related feed definitions when publishers share editorial ownership or syndicated coverage. Otherwise, feed hostnames identify independent sources. Source independence is an approximation; editorial duplication may still need configuration.

The default score is **60% importance, 15% location, 10% industry and 15% technical practice**. All four regions, including `Other`, participate equally through the strongest applicable regional score. The result is bounded by severity: critical 85–100, high 65–84.99, medium 35–64.99 and low 0–34.99. A highly relevant product announcement cannot outrank a critical incident. Weights, regions and bands are editable in `scoring.yaml`.

Relevance percentages measure **applicability**, not the probability of attack, the share of victims, or evidence that your organization uses an affected product. Source-supported security issues in common web/OS infrastructure (including PHP and Node.js) receive 95% in every region; enterprise platforms and software distribution infrastructure receive 85%; specialist/consumer software receives 75%. These are configurable calibration anchors, not measured market shares. Deployment profiles require the affected technology in both the classification and source evidence. Regional incidents, regulations, research and ordinary product announcements retain their separate geographic assessment. An advisory issuer's country does not bias a global software issue.

Reported exploitation attempts and actual systemic supply-chain compromise raise urgency. A critical vulnerability with a PoC or emergency patch alone remains high; predictions and lab demonstrations are not treated as active exploitation. EPSS can establish a high floor but cannot by itself establish a critical incident. Older KEV entries retain a high floor without implying a new active campaign. Source counts record corroboration and never raise severity. Source-text recognition is conservative, currently covering English and selected Dutch phrases; an absent signal means it was not established by the available summaries. The classifier still provides assessments for cases outside these rules.

Priority-country aliases normalize UK/GB and UAE/AE. For nonglobal events, the country bonus applies at most once per region, even when several priority countries are mentioned. Global deployment profiles replace geographic estimates consistently and apply cross-industry floors. Technical practice scores remain the saved assessment. Every calculation starts from the original classification, so reruns do not compound adjustments. JSON and CSV expose the weighted components, severity band, source-linked risk signals, deployment scope and independent-source count.

The [22 October scoring review](docs/scoring-review-2026-10-22.md) includes all 106 stories from the supplied email, the exact original window, and a before/after comparison. To repeat a review using an archive and database from the same run:

```powershell
uv run python scripts/review_scoring.py --report output/daily/2026-10-22.json --database data/secdigest.sqlite --output output/review/2026-10-22
```

This works offline, copies the database into memory, checks report membership, and writes separate HTML, Markdown, JSON and CSV reports plus a row for every original story. It performs no API calls, email sends or original archive/database writes.

For regional country grouping beyond priority countries, optionally add `country_regions: {DE: Europe, ZA: MEA, ...}` to `regions.yaml`. Unmapped countries use the story's strongest regional score, so this grouping is an assessment rather than a verified geolocation database.

Regulations ship with `milestones: []` and `needs_dates: true`. Add only confirmed milestones, for example:

```yaml
milestones:
  - date: YYYY-MM-DD  # Replace with a confirmed ISO date; this is not a real date.
    description: Your sourced milestone description
needs_dates: false
```

Unconfirmed dates remain empty and appear in the weekly missing-date list. Business signals default to disabled. When enabled, their wording is rebuilt from approved sector, region and signal-type values so individual victims cannot appear as sales targets.

## Sources and evidence

`feeds check` checks the supplied URL or discovers RSS/Atom links from a site's `<link rel="alternate">` metadata; CSAF sources use their configured JSON indexes directly, and explicit `html_index` sources validate their supported publisher layout. Failed sources are disabled with a reason. Sources with no discovered feed or supported collector become disabled `page_watch` entries. The source check report is written to `output/source-check.json`, including discovered candidates. Run the check again after editing a URL to re-enable a recovered source. The checked-in configuration currently enables 41 sources and disables 28; this is a configuration snapshot, not a guarantee that every enabled source will fetch successfully.

The [18 October threat-intelligence source review](THREAT-INTELLIGENCE-SOURCES.md) added ten public feeds from Contagio, GitHub, Google Project Zero, GreyNoise, Rapid7/Metasploit, Qualys, ReversingLabs and Seebug, and enabled FIRST EPSS enrichment. The review documents all 24 requested sources, including commercial services, reference datasets, blocked endpoints and unidentified catalogs. At verification, Contagio and GreyNoise Labs had no entries inside retention and Seebug's feed was empty. Vendor blogs do not provide full commercial database coverage. The 22 October archives include the expanded feed configuration.

On 21 October 2026, three more RSS feeds were verified and enabled: [CERT-EU Security Advisories](https://cert.europa.eu/publications/security-advisories-rss), [CERT-EU Threat Intelligence](https://cert.europa.eu/publications/threat-intelligence-rss), and [Ars Technica Security](https://arstechnica.com/security/feed/). Both CERT-EU feeds share `independence_key: cert.europa.eu`. Ars Technica uses its security category feed. [Verification results](docs/cert-eu-ars-technica-verification-2026-10-21.json) record feed parsing and isolated ingestion checks.

On 24 October 2026, [Censys Blog](https://censys.com/feed/) and [Shodan Blog](https://blog.shodan.io/rss/) were verified and enabled with publisher identities `censys.com` and `shodan.io`. Censys mixes security research and product news; its feed supplied ten articles within 120-day retention. Shodan's latest feed entry was 7 August 2024, so it currently contributes no retained articles and is enabled to collect future posts. Repeat ingestion produced zero duplicates. Both use public RSS without API keys; these feeds do not provide the vendors' scanning databases or complete Censys ARC advisory coverage. See the [source review](docs/censys-shodan-source-review-2026-10-24.md) and [verification evidence](docs/censys-shodan-verification-2026-10-24.json).

Also on 24 October, [Amazon Linux Security Center](https://explore.alas.aws.amazon.com/) and [Anthropic Research](https://www.anthropic.com/research) were enabled as `html_index` sources with publisher identities `amazon.com` and `anthropic.com`. The Amazon Linux collector reads CVE descriptions and public dates; a listing does not establish Amazon Linux affected status or patch availability. The Anthropic collector reads dated research cards, including linked Institute research, from the current rendered index. It does not follow JavaScript pagination. Isolated verification retained 8,835 AWS records and 24 Anthropic posts, with zero repeat duplicates. This historical ingestion does not classify the entire retained catalog: daily classification still selects the report window. [Implementation and coverage limits](docs/aws-anthropic-source-review-2026-10-24.md) and [verification evidence](docs/aws-anthropic-verification-2026-10-24.json) record the checks.

These page sources publish dates without times. Records retain `date_precision: day` and the date's meaning; publication days are included when they overlap a report window, so a morning digest does not silently omit yesterday's posts. A date-only record can overlap adjacent daily windows. Sources with exact timestamps keep their existing window behavior. Unknown dates, off-publisher links, changed layouts and oversized responses are rejected; partial parsing retains valid entries, marks the source degraded and retries the failed content.

For a publisher whose article links are broken but whose URL-shaped entry IDs have been verified, set `entry_url_field: id` on that feed. This option accepts only HTTP(S) IDs on the feed's own host. Qualys research uses it because its feed repeats a category URL in every article link; all other feeds default to `link`.

Routine fetch errors do not permanently disable feeds. Collection uses bounded concurrency, timeouts, response-size limits, conditional ETag/Last-Modified requests, robots policies, crawl delays and HTTP retry/backoff. It collects feed summaries only by default. Publication and collection timestamps are stored separately; missing publication dates are labelled as inferred and future-dated items are excluded.

CISA uses its official `cisagov/CSAF` GitHub repository's ROLIE JSON indexes for IT, OT and VA advisories. The `csaf` source adapter retrieves the referenced CSAF 2.0 documents and extracts publisher-provided summaries, CVEs, affected products, scores, remediation and source links. `feeds check` validates these JSON indexes directly. Documents and redirects are restricted to each feed's configured `document_base_url`. All three feeds share `independence_key: cisa.gov`, so overlapping CISA coverage does not count as independent corroboration.

These structured feeds replace the legacy CISA advisory RSS path. The initial 18 October collection contributed 267 distinct advisories and consolidated three IT/VA overlaps. The latest 22 October ingestion retained 224 unchanged OT, 39 IT and four vulnerability-advisory entries. CISA IT entry `VA-26-274-03` (Joyland AI) still returned HTTP 404. A document failure marks that source as degraded and is retried on subsequent ingestion; successfully collected advisories are retained. Inspect `source_health` in the report JSON for per-source counts and failed advisory IDs.

Advisories are deduplicated by publisher and advisory ID across feeds and runs. A newer release updates the existing article and invalidates its classification; the original release date is retained separately, while the current release date determines report eligibility. Older versions cannot overwrite newer cached releases. Index responses are cached so failed documents can be retried even after an HTTP 304. Initial collection considers the configured database retention window (120 days); daily classification still uses only the daily report window. SQLite schema version 2 adds the advisory identity table automatically.

KEV remains JSON enrichment. The CISA website is primary; the official `cisagov/kev-data` GitHub JSON mirror is the fallback on transport or validation failure. `enrichment.kev_refresh_hours` defaults to 6. Both unavailable sources leave existing data intact and produce a warning. Catalog count, CVE identifiers, required fields and dates are validated; older snapshots cannot replace a newer cached release. JSON reports record KEV source URL, catalog version, release time and last successful check in `kev_provenance`.

GovDelivery email subscription and mailbox ingestion are excluded. Structured advisories and KEV do not cover every broader CISA announcement; live HTML, Markdown and email reports display this coverage note. No CISA subscription credentials are needed. See [CISA subscription research](CISA-SUBSCRIPTIONS-RESEARCH.md) for verified endpoints and the original investigation.

CVEs are checked against CISA KEV. EPSS is enabled; NVD and per-CVE GitHub advisory enrichment remain disabled and independently optional. GitHub's public security blog is collected separately; enabling the current per-CVE API lookup across retained history could exceed GitHub's unauthenticated REST request budget. NVD calls observe its unauthenticated rate limit. MITRE's enterprise ATT&CK dataset validates technique IDs. Unavailable enrichment is labelled rather than converted to zero or invented. KEV addition dates have day precision, so counts include catalog dates overlapping the report's local date window.

Source CVEs, published detection URLs, regulation dates, case-study references and actor names are validated against available evidence. Reports label detection recommendations as assessments. These checks constrain generated output; they do not independently prove every factual claim or relevance score. Review original sources before operational action.

## Archives and email

Live archives are `output/daily/YYYY-MM-DD.{md,html,json,csv}` and `output/weekly/YYYY-Www.{md,html,json,csv}`. Local email previews are `output/preview/secdigest-daily-YYYY-MM-DD.eml` and `output/preview/secdigest-weekly-YYYY-Www.eml`. CSV exports retain every regional, industry and practice score, overrides, CVEs and advisory facts, technologies, techniques, regulations, related studies and source URLs. Spreadsheet formula prefixes are escaped. JSON also exposes unclassified counts, merged cluster IDs, source health, enrichment warnings, KEV provenance and coverage notes.

Daily emails attach full HTML and CSV. Weekly emails also attach Markdown. MIME structure is mixed → alternative (plain text, HTML) → attachments. HTML email uses inline CSS, table layout, text-labelled importance badges and no external images/fonts/scripts. Feed-derived text is escaped and links are restricted to HTTP/HTTPS.

The HTML email body is strictly below 90,000 UTF-8 bytes. Lowest-priority content moves to the attachment first; unusually large high-severity sets are compacted with a clear notice. The attachment always retains the complete report. Real Gmail/Outlook rendering and forced dark mode still require review in those clients.

Successful sends are recorded by digest type and report period. Reruns do not resend unless `--force-send` is used. SMTP retries transient failures three times with backoff, never authentication errors. SMTP cannot guarantee exactly-once delivery if the connection fails after acceptance; inspect delivery before forcing a retry after an ambiguous failure.

Source-health emails trigger when more than 30% of enabled sources fail or no new article has arrived in 24 hours. Successful source-health alerts suppress repeats for three days. Each run records all email attempts, including failure alerts, in `run_log.json`. Logs retain the last 365 runs; `badge.json` reports the latest result. Exception logs omit raw exception messages, response bodies, source lines and environment values.

Daily outputs are retained for 90 days and stored news for 120 days; weekly archives are retained indefinitely. The application closes SQLite before workflow commit-back. Preview emails are ignored by Git because they may contain configured sender/recipient addresses.

## Scheduling

Daily automatic delivery is enabled from **21 October 2026**: `scheduling.enabled: true` and `daily_enabled: true`. Weekly automatic delivery remains disabled with `weekly_enabled: false`. The global switch disables both schedules; per-kind switches default to enabled when omitted for compatibility with older configurations. Manual dispatch remains available regardless of these switches.

The 20 October scheduled runs arrived several hours late and skipped collection because the previous guards accepted only the target hour. Automatic delivery was also disabled in the published configuration. Both guards now accept delayed runs later that day. For a new installation, configure the API/email repository secrets and verify previews and SMTP delivery before enabling a schedule. Live weekly synthesis remains unverified.

Daily schedules use `0 5 * * *` and `0 6 * * *` UTC, guarded for 07:00 Europe/Amsterdam or later that day. Weekly schedules use `0 6 * * 1` and `0 7 * * 1`, guarded for Monday 08:00 or later that Monday. Manual dispatch skips the timing/activation guards and supports `mode`, `force_send` and date/week overrides. GitHub scheduled jobs may start hours late; both guards allow same-day catch-up, and recorded successful deliveries suppress repeat emails for the same period. Jobs that arrive before the target hour, disabled schedules and weekly jobs outside Monday remain blocked. If you change the configured timezone or target hours, update the workflow's early hour guard and UTC schedules too.

Manual runs default to `mode=preview`:

| Actions mode | Data and credentials | Result |
|---|---|---|
| `preview` | Live daily collection/classification or weekly synthesis from stored news; API credentials only | Reports and `.eml` preview; no email or persistent database changes |
| `fixtures` | Synthetic fixtures; API and SMTP credentials removed | Offline sample reports and `.eml` preview |
| `send` | Live pipeline; API and SMTP credentials | Email delivery and committed runtime artifacts; database cache saved when enabled |

Preview artifacts are downloadable from the Actions run for seven days and are not committed back or saved to the database cache. Failed previews also upload their diagnostic log: check its latest status, since the artifact may contain historical sample reports. API diagnostics retain only the HTTP status and recognized error codes, never raw provider messages. Only `send` honors `force_send`; enabled scheduled runs also use `send`.

Once a valid `OPENAI_API_KEY` Actions secret and these workflow changes are on the selected GitHub branch, run **Actions → SecDigest daily → Run workflow → mode: preview**. Without a key, choose `fixtures`.

Select the branch containing the intended code and configuration when dispatching manually. GitHub scheduled workflows run from the repository's default branch, so those changes must be present there before enabling schedules.

Both workflows serialize within each branch on the same concurrency group because they share SQLite and archives. The [shared runner](.github/workflows/run-digest.yml) uses Python 3.12, pip caching, the locked requirements export, and the `github-actions[bot]` identity. Send mode commits only runtime artifacts when changed, including failure logs. It never force-pushes. A database above 50 MB switches to `actions/cache` and emits a notice; `data/storage-mode.json` records that choice. Keep an independent database backup because Actions caches can be evicted. A missing required database cache stops processing instead of silently rebuilding history.

For a server whose cron supports `CRON_TZ`, provision environment variables through the service's secret management and use:

```cron
CRON_TZ=Europe/Amsterdam
0 7 * * * cd /opt/Security-Digest && /opt/Security-Digest/.venv/bin/secdigest run-daily >> /var/log/secdigest.log 2>&1
0 8 * * 1 cd /opt/Security-Digest && /opt/Security-Digest/.venv/bin/secdigest run-weekly >> /var/log/secdigest.log 2>&1
```

On cron implementations without `CRON_TZ`, use equivalent UTC schedules with `secdigest schedule-guard`; ensure the scheduler supplies credentials. A local file lock prevents concurrent database mutation.

## Model usage and cost

Each run records uncached input, cached input and output tokens (including reasoning tokens). OpenAI prompt caching is automatic for eligible repeated prefixes; the shared rubric and schemas precede story data. Requests set `store=false`. Configure `models.prices_per_million` for your chosen model IDs:

```yaml
prices_per_million:
  your-verified-model-id:
    input_tokens: 0.0
    output_tokens: 0.0
    cache_read_input_tokens: 0.0
```

The zeroes above are placeholders. The shipped configuration uses public standard rates checked on 2026-10-17: [GPT-5.4 mini](https://developers.openai.com/api/docs/models/gpt-5.4-mini) costs $0.75 / $0.075 / $4.50 per million uncached input / cached input / output tokens; [GPT-5.4](https://developers.openai.com/api/docs/models/gpt-5.4) costs $2.50 / $0.25 / $15.00 respectively. Cached input is subtracted from the API's input total before pricing, so it is not counted twice. Missing rates produce an unknown estimate. Batch estimates apply the standard 50% discount; synchronous validation retries use standard rates. Weekly usage is recorded separately. Estimates exclude regional/long-context surcharges and contractual differences; recheck rates for your account.

Daily budget planning: for `N` new daily clusters and batch size 5, expect `ceil(N / 5)` classification calls plus at most one validation retry per call. A weekly run adds one synthesis call and at most one retry, reusing daily classifications. As a token-volume example, 100 daily clusters at 1,000 source tokens and 800 output tokens each imply roughly 100,000 source-input and 80,000 output tokens per day, plus cached rubric/schema overhead; a seven-day week is roughly seven times that plus synthesis. Actual usage appears after a successful live call. Initial historical backfills are additional usage.

## Tests and validation

```powershell
uv run pytest -q
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
```

The suite covers dynamic taxonomy schemas, custom API endpoints, denied model-metadata access, safe API diagnostics, invalid-model retries, claim filtering, batch resumption, URL/indicator normalization, clustering, report-time incident deduplication, scoring overrides, country bonuses, watch aliases, date windows, DST, source discovery and caching, idempotent ingestion, Markdown golden files, HTML escaping, 200-item email limits, CSV scores, MIME structure, SMTP retry policy, failure alerts, source-health silence and CLI/workflow credential isolation. CISA tests cover ROLIE/CSAF parsing, advisory identity and revisions, overlapping feeds, failed-document retries, document URL restrictions, KEV mirror fallback, catalog validation and provenance.

The 22 October scoring revision passed **178 tests**. Added coverage checks global versus local applicability, severity ordering, observed attempts versus predictions/lab work, negated claims, source-backed supply-chain compromise, old/future KEV dates, equal `Other` weighting, exact-CVE consolidation and preservation of read-only review snapshots. Both daily and weekly fixture previews were regenerated.

The [CI workflow](.github/workflows/ci.yml) runs Ruff, pytest and offline daily/weekly previews on pushes and pull requests, then uploads the synthetic reports as an artifact.

`scripts/fixture_previews.py` regenerates synthetic report archives. Its `--update-golden` flag deliberately replaces test expectations; review rendered changes before using it. `scripts/seed_config.py` is a one-time importer from the original prompt and refuses to overwrite existing configuration. The running application does not depend on the prompt file.

See [VALIDATION.md](VALIDATION.md) for observed checks, remaining credential-dependent checks and limitations.
