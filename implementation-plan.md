# SecDigest implementation plan

Status: approved by the user on 2026-10-17. Application implemented; offline tests, live source ingestion, an OpenAI daily preview and a full daily run with SMTP acceptance are verified. Live weekly synthesis, inbox/client review and schedule activation remain pending. See `VALIDATION.md`. The plan below records the original approved architecture; the original prompt is unchanged.

## Checked starting point

- The repository contains `.gitattributes` and the supplied `security-digest-prompt.md`; there is no application or existing test suite.
- The prompt is currently untracked. Preserve it unchanged.
- Python 3.14 and `uv` are available on this machine. Target Python 3.12 as requested, using a project environment managed by `uv`.
- Read the referenced tracker files: [scraper.py](https://github.com/Banzaaaaai/flex-gateway-release-tracker/blob/main/scraper.py) and [tracker.yml](https://github.com/Banzaaaaai/flex-gateway-release-tracker/blob/main/.github/workflows/tracker.yml).
- Reuse their SMTP environment names, bot identity, run history and badge conventions. Implement the prompt's corrections to MIME structure, escaping, TLS, retries and alert accounting.

## Architecture

A Python command-line application with SQLite persistence. Collection, classification, scoring, rendering and delivery are separate components so tests and previews can run without network access, API charges or SMTP credentials.

```text
YAML configuration
  -> validated settings + generated Pydantic/JSON schemas + cached model rubric

RSS / Atom + advisory feeds
  -> asynchronous collection and HTTP cache
  -> normalization and persistent story clustering
  -> KEV / optional EPSS and CVSS enrichment
  -> Claude classification, once per cluster
  -> evidence validation and deterministic scoring
  -> SQLite classifications and source provenance
  -> daily / weekly report data
  -> Markdown + HTML + JSON + CSV archives
  -> size-limited email + full-report attachments / .eml preview

Fixture feeds + fixture classifications
  -> the same scoring, reporting and delivery-preview components
```

Use `httpx`, `feedparser`, `rapidfuzz`, `anthropic`, Pydantic v2, PyYAML, Jinja2 and standard-library SQLite/SMTP. Use `argparse` for the CLI, `zoneinfo` with `tzdata` for Windows timezone support, and pytest/Ruff for checks. Keep optional full-text extraction in a separate dependency extra.

## Proposed file layout

```text
Security-Digest/
  security-digest-prompt.md           Original requirements
  implementation-plan.md             This plan
  README.md
  pyproject.toml
  uv.lock
  requirements.txt                   Locked export for pip-based Actions
  .python-version
  .gitignore
  config/
    settings.yaml                    Runtime, models, mail and retention
    feeds.yaml                       All supplied sources and discovery state
    regions.yaml
    industries.yaml
    practice_areas.yaml
    watch_tech.yaml                   Products, aliases and vendor groupings
    regulations.yaml
    case_studies.yaml
    writing.yaml
    scoring.yaml                     Rubric, categories, weights and thresholds
  src/secdigest/
    __init__.py
    __main__.py
    cli.py
    config.py                        Config validation and cross-references
    schemas.py                       Dynamic classification schema
    storage.py                       Migrations, transactions and repositories
    sources.py                       Feed discovery, validation and ingestion
    normalize.py
    clustering.py
    enrichment.py
    classification.py                Claude, caching, retries and batch jobs
    evidence.py                      Validation of links, IDs and model claims
    scoring.py
    reporting.py                     Daily/weekly aggregation and trends
    synthesis.py                     Weekly executive summary and outlines
    rendering.py                     Archive formats and email byte budget
    delivery.py                      MIME, SMTP, previews and delivery state
    operations.py                    Run history, badge, alerts and retention
    scheduling.py                    DST guard and report windows
    templates/                       Daily/weekly archive and email templates
  tests/
    fixtures/                        10-15 synthetic stories and advisory data
    golden/                          Stable rendered daily/weekly examples
    test_*.py
  data/
    secdigest.sqlite                 Created at runtime
  output/
    daily/
    weekly/
    preview/
    samples/                         Clearly labelled synthetic examples
  .github/workflows/
    ci.yml
    daily.yml
    weekly.yml
  run_log.json                       Created at runtime; last 365 runs
  badge.json                         Created at runtime
```

## Storage and processing decisions

- SQLite stores sources and conditional HTTP-cache metadata, articles, clusters and memberships, classification versions, advisory snapshots, batch-job state, report runs and delivery attempts. Unique canonical URLs and transactional cluster membership make ingestion repeatable.
- Keep each source's publication timestamp and the collection timestamp separately. An undated item is marked as such; a future-dated item is excluded from the current window. Preserve evidence timestamps when counting independent sources within 24 hours.
- Combine URL, title similarity and CVE evidence when clustering. A shared CVE must not accidentally merge unrelated roundup articles into one giant story. Keep every original source link.
- Store model classifications separately from computed overrides. Recompute overrides from the original classification so reruns cannot repeatedly increase importance or country scores. Reuse classifications unless `--reclassify` is supplied; record schema/model/config fingerprints for traceability.
- Generate all taxonomy fields and allowlists from YAML. Seed all 4 regions, 10 industries, 11 practice areas, 12 case studies and 3 writing references from the prompt. Validate regulation and case-study cross-references during `config check`.
- Keep the requested Claude model names configurable and verify availability before live classification; do not assume the supplied identifiers or pricing are valid. Record token usage, cache usage and estimates from configurable verified prices; label unavailable estimates rather than inventing them.
- Classify 5-10 clusters per call using strict tool schemas and a cached system rubric. Retry invalid output once. Persist asynchronous Message Batches jobs so backfills can resume and are never reported as complete while results are pending.
- Treat source text as untrusted data. Require source support for CVEs, exploitation claims, detection links and reported dates. Validate ATT&CK identifiers against cached MITRE data and case-study slugs against config. Keep missing CVSS/EPSS values distinct from zero.
- Business signals default to disabled. When enabled, construct sector/region signals from validated taxonomy and evidence, with checks that reject individual victim targeting.
- Keep source checks separate from routine fetch failures: initial validation disables invalid feeds and records reasons; transient failures remain visible and retryable. Discover `TODO_VERIFY` feeds from site metadata. Sites without feeds become disabled `page_watch` records.

## Time, scoring and report behavior

- Retain `Europe/Amsterdam` as the application's configurable default because the specification explicitly requires it. Store timestamps in UTC.
- Daily reports use the preceding 24 elapsed hours. Historical `--date` selects a window ending at the next local midnight; today's report ends at the current run time. Show the exact window in every report.
- Weekly reports default to the previous completed ISO week, using local Monday boundaries and an exclusive next-Monday endpoint. `--week` selects a specific ISO week; a rolling seven-day window remains configurable.
- Normalize the supplied country aliases (`UK` to `GB`, `UAE` to `AE`) through configuration. Apply the configured bonus once per distinct directly involved priority country, capped at 100 per region.
- Apply KEV and exploitation floors, then EPSS and independent-source increases, with an audit record for each override. Priority weights and included regions are configurable. Technology matching uses explicit aliases to avoid ambiguous substring matches.
- Produce all six daily sections and all thirteen weekly sections, with business signals conditional. Heatmaps display counts and average relevance. Week-over-week comparisons explicitly report when prior data is unavailable.
- Retain all region, industry and practice scores in JSON/CSV even when the visible table shows only the top two. Preserve original-source links and label detection advice as an assessment.
- Leave regulatory milestone dates empty unless supported by source evidence or explicitly entered in configuration. Weekly reports list entries needing dates.
- Archive daily output for 90 days, SQLite news data for 120 days, and weekly outputs indefinitely. Keep API keys, SMTP credentials, full API responses and optional full article text out of archives and commits.

## Delivery and scheduling

- Implement all CLI commands and flags in the prompt, including `--no-send`, `--preview`, `--dry-run`, `--force-send`, `--reclassify`, `--batch-api` and optional `--fetch-fulltext`. Standalone report commands default to file generation; `run-daily` and `run-weekly` include delivery.
- Compose `multipart/mixed` containing `multipart/alternative` with plain text before HTML, followed by attachments. Use the specified From, Date, Message-ID and X-SecDigest headers.
- Escape all untrusted content and permit only HTTP/HTTPS content links. Use an inline-styled, table-based email layout that fits a 375 px viewport and a 680 px desktop container.
- Enforce a strict HTML-body limit below 90,000 UTF-8 bytes. Remove lowest-priority rows first. If detailed critical/high content alone exceeds the limit, compact it and explicitly refer to the complete attachment; the byte limit must still hold.
- Retry only transient SMTP failures, with three retries and exponential backoff; authentication errors stop immediately. Failure-alert errors cannot replace or hide the original run failure.
- Track every daily, weekly, failure and source-health delivery independently in each run record. Persist send status and period identifiers so successful runs are not resent without `--force-send`. Document SMTP's unavoidable ambiguity if a connection fails after a server accepts a message.
- Write run history and the badge in finalization. Source-health alerts use successful alert timestamps for the three-day silence window.
- Prepare daily and weekly GitHub Actions workflows with dual UTC crons, a timezone guard and manual dispatch. All work after the guard is conditional so the wrong-hour invocation truly skips processing.
- Serialize access to shared SQLite/archive state across both workflows, as well as preventing same-workflow overlap. Commit only the prescribed runtime artifacts when changed, including failure logs after a failed run. If the database exceeds 50 MB, use an Actions cache and report the change.
- Initially gate scheduled execution until daily/weekly `.eml` previews have been reviewed and a real test message has succeeded. Provide equivalent server crontab instructions.

## Build phases and completion checks

1. **Foundation and fixture path.** Create packaging, all configuration, dynamic schemas, SQLite migrations, the CLI skeleton and synthetic input data. Establish a minimal rendered daily fixture report. Verify config cross-references, taxonomy extensibility and offline operation.
2. **Ingestion and scoring.** Implement source discovery, caching, normalization, clustering, advisory enrichment, technology matching and deterministic scoring. Test parsing, time windows, rerun idempotence, every override and country bonuses with fixtures. Show the updated daily sample before connecting ingestion to live sources.
3. **Claude classification and weekly synthesis.** Implement schema generation, cached prompts, batched classification, retries, evidence validation, persisted batch jobs and usage accounting. Test malformed output, unsupported claims, invented links/slugs, business-signal restrictions and reuse of stored classifications. Show the fixture daily sample before live API validation.
4. **Complete reports.** Implement every daily and weekly section and all archive formats, including heatmaps, trends, regulatory calendars, detection coverage, related work, content outlines and watchlists. Golden-file tests cover fixture daily/weekly output; verify every score is exported and missing data stays explicit.
5. **Email and operations.** Implement MIME construction, attachments, size limiting, SMTP retries, preview files, alerts and log/badge finalization. Mock SMTP to test all four email types, recipients, hostile feed text, 200-item size limits, failure handling and source-health suppression. Generate both daily and weekly `.eml` previews.
6. **Live verification and scheduling.** Validate and report all supplied feed URLs, verify accessible Claude models and pricing, run a live ingestion/classification/daily cycle, measure the five-minute target and confirm rerun behavior. Test real email once credentials are configured and complete preview review before activating schedules. Verify January/July DST guards and document setup, config, tuning, costs and server scheduling.

Run the relevant tests and Ruff after each phase and show a fixture daily sample at every phase boundary. Network-dependent checks require actual access and configured credentials; record their outcomes separately from offline tests. Do not describe a fixture report as live news or mark unexecuted live acceptance checks as passed.

## Implementation notes

The user approved this plan. Daily and weekly workflows share `run-digest.yml` to avoid duplicating deployment logic. `run-daily` classifies the requested 24-hour window; the standalone classification/batch command processes historical backfills. Live ingestion confirmed that the MSRC feed can supply thousands of historical entries, so daily operation must not automatically classify the entire retained database. The original prompt remains unchanged.
