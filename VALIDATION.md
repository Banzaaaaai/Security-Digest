# SecDigest validation record

Latest validation: **18 October 2026**, Europe/Paris. Live checks below were performed on 17 October unless stated otherwise.

## Post-classification duplicate check

**99 tests pass locally**, with Ruff lint and formatting checks passing. New regression coverage includes the three ConnectWise reports, identical Drupal coverage, distinct victims/products/CVEs/actors, a CVE roundup, separate regulatory events, publication timing, transitive roundup protection, source URL normalization, preserved evidence, repeatability and unmodified stored inputs. Daily output tests verify one incident entry with all sources across HTML, Markdown, CSV and email. Weekly tests verify unique incident counts, previous-week comparisons, CVE-specific source attribution and the input to synthesis.

The actual 18 October daily report was regenerated from a read-only copy of the saved database using its original reporting window, without API requests or SMTP delivery. **9 entries became 6 incidents**: ConnectWise coverage merged from three entries into one with three source links, and Drupal coverage merged from two entries into one with two source links. The revised counts are **1 critical, 3 high and 2 medium**. All nine source links remain available. HTML, Markdown, JSON, CSV and an email preview were generated under `output/preview/deduplicated/`; the CSV has six rows and the MIME preview has both expected attachments. The previously sent archives, database and daily delivery marker are unchanged.

Deduplication runs before report totals, weekly synthesis and rendering. It preserves the selected representative's prose and relevance scores, combines validated evidence and recomputes scoring overrides from original values. JSON records the removed count and merged cluster IDs; run logs record the removed count. This is a conservative text heuristic with configurable thresholds and a 48-hour publication window. It keeps uncertain matches separate and does not guarantee detection of every paraphrase.

## Custom API endpoint

`OPENAI_BASE_URL` is now an optional environment variable and GitHub Actions repository secret. All OpenAI client operations use it, including classification, weekly synthesis, model lookup and batch/files requests. Missing or blank values select `https://api.openai.com/v1`; surrounding whitespace is trimmed. Fixture workflows remove the key and endpoint from the child environment.

**83 tests passed locally**, with Ruff and formatting checks passing. Mock HTTP tests verify classification/model requests at both the default endpoint and a custom endpoint with a path prefix, empty-value fallback and rejection of invalid URLs without printing their values. Tests also verify that denied model metadata access does not block permitted generation, while a generation denial still stops the run.

The [live daily preview for 18 October 2026](https://github.com/Banzaaaaai/Security-Digest/actions/runs/39074207750) succeeded at the user-configured endpoint. It classified **9 story clusters** (3 critical, 4 high, 2 medium), with **zero unclassified clusters**, in **19.35 seconds** of application runtime. HTML, Markdown, JSON, CSV and an email preview were downloaded and inspected. The run log confirms `synthetic: false` and `email_sent: false`; the MIME preview uses placeholder addresses. The model metadata endpoint returned 403, but actual generation was permitted. OpenAI documents [separate model-read and model-request permissions](https://developers.openai.com/api/docs/guides/rbac).

Recorded usage was 9,912 uncached input tokens, 6,400 cached input tokens and 4,110 output tokens. The configured-rate estimate was **$0.026409**; this is not a measured charge for the configured endpoint.

## Full daily delivery

The [full daily run for 18 October 2026](https://github.com/Banzaaaaai/Security-Digest/actions/runs/39074556888) succeeded in **16.89 seconds**, including SMTP delivery. It generated nine classified clusters (3 critical, 4 high, 2 medium) with zero unclassified clusters and sent the daily email with full HTML and CSV attachments to the configured recipients. SMTP accepted the message; the run log records the daily email as sent, and SQLite contains the delivery marker for `daily` / `2026-10-18`. Inbox receipt and client rendering still require recipient review.

The workflow archived the reports, classifications and delivery state on `codex/openai-daily-preview`. Those artifacts were synchronized locally and the delivery record was verified. The configured-rate API estimate for this run was $0.020334. CISA Advisories was the only failed source among 22 enabled feeds; the report records that coverage gap.

## Completed

| Check | Observed result |
|---|---|
| Project environment | Python 3.12.13 installed through uv; dependency lock and pip requirements export generated |
| Configuration | 4 regions, 10 industries, 11 practice areas, 12 case studies, 3 writing references and 51 feed definitions |
| Automated tests | **99 passed locally** after the duplicate-check update; includes report deduplication, SDK HTTP request mocks, invalid-output retries, cached-token cost accounting, batch resumption/failure handling, weekly reference validation, preview credential isolation and secret-safe error metadata distinguishing quota exhaustion from rate limiting |
| Ruff | Lint passed; source, tests and scripts formatted |
| Python syntax | `compileall` completed for source and scripts |
| Workflow files | All four workflow YAML files parsed successfully |
| Daily fixture run | 12 clusters / 14 source items; 4 critical, 1 high, 6 medium, 1 low after overrides |
| Weekly fixture run | Complete weekly report, including heatmaps, regulatory calendar, detection coverage, related work, content outlines and watchlist; optional business signals disabled |
| Report formats | HTML, Markdown, JSON and CSV generated for daily and weekly samples |
| Email previews | Correct mixed/alternative MIME structure and attachments; daily and weekly `.eml` files generated |
| Sample email size | Daily HTML: 24,708 bytes; weekly HTML: 39,326 bytes, including MIME line endings |
| Large email case | 200-item fixture stays below 90,000 HTML bytes; full attachment retains every item |
| Live feed validation | 22 usable feeds enabled; 29 sources disabled with recorded reasons |
| First live ingestion | 5,211 articles stored in 5,204 clusters; 22 enabled feeds succeeded, zero fetch failures; 53.98 seconds including enrichment |
| Live rerun | Zero new articles and zero duplicate clusters; zero enabled-feed failures; 4.30 seconds recorded by the application |
| CISA KEV cache | 1,748 entries loaded |
| MITRE ATT&CK cache | 706 active, non-deprecated enterprise technique/subtechnique IDs loaded |
| Enrichment health | No KEV/ATT&CK refresh warnings in the live ingestion run |
| Database size | Approximately 7 MB; below the 50 MB Actions-cache threshold |

Fixture reports are explicitly synthetic. Their CVEs, headlines and scores are test inputs, not real incident reports. The committed database now also contains live classifications and the successful daily delivery marker from the full run. Preview runs themselves do not commit or cache database changes.

## OpenAI migration

At the user's request, classification and weekly synthesis now use the OpenAI Responses API with strict function calls. Historical backfills use the OpenAI Batch API, including persisted file/job IDs and partial-failure handling. Defaults are `gpt-5.4-mini` and `gpt-5.4`; public model support and standard pricing were checked against the official model pages. Dependencies are locked to OpenAI SDK 2.54.0; Anthropic is no longer a runtime dependency.

Earlier attempts at the default endpoint encountered authentication and quota errors. After the user configured the custom endpoint, its model metadata endpoint returned 403. Model lookup now tolerates that specific denial, allowing the requested generation operation to validate model access itself. The subsequent live daily preview succeeded, including strict function-schema acceptance and evidence validation. No alternate model was selected.

That run checked 22 enabled feeds: 21 succeeded, CISA Advisories returned an HTTP error, and no new articles were added. The existing database was reused. Preview mode provided no SMTP credentials and the diagnostic log confirms `email_sent: false`.

The suite passed in `.venv-openai` (Python 3.12.13) after Windows blocked removal of an old package in `.venv`; pytest required execution outside the filesystem sandbox to access its temporary directory. Daily and weekly fixture runs through `scripts/workflow_digest.py` succeeded with API and email credentials removed from the child environment. Both produced all four report formats and `.eml` previews, with 12 synthetic clusters and zero unclassified items. No email was sent.

Manual Actions runs now default to `preview`; `fixtures` works without a key and `send` explicitly enables email. Preview modes do not commit artifacts or update the persistent database cache. The [GitHub daily fixture preview](https://github.com/Banzaaaaai/Security-Digest/actions/runs/39071318944) succeeded, and its downloaded artifact was verified: 12 synthetic clusters, all four report formats, an `.eml` preview and `email_sent: false`. Failed previews also upload a diagnostic run log; inspect its latest status before treating any archived files in the artifact as a completed live report.

## Artifacts

- [Daily sample HTML](output/samples/daily/2026-10-17.html)
- [Weekly sample HTML](output/samples/weekly/2026-W42.html)
- [Daily sample Markdown](output/samples/daily/2026-10-17.md)
- [Weekly sample Markdown](output/samples/weekly/2026-W42.md)
- [Sent daily digest HTML](output/daily/2026-10-18.html)
- [Sent daily digest CSV](output/daily/2026-10-18.csv)
- `output/samples/preview/secdigest-daily-2026-10-17.eml`
- `output/samples/preview/secdigest-weekly-2026-W42.eml`
- `output/source-check.json`: source-by-source status and discovered feed candidates
- `data/secdigest.sqlite`: live ingestion state, advisory caches and source provenance
- `run_log.json` and `badge.json`: live command history and status

Preview messages and sample run logs are ignored by Git. Archived sample reports are intended to be reviewable project artifacts.

## Still requiring live credentials or client review

Email secrets and working API key/endpoint secrets exist in GitHub Actions. Secret values were neither requested in chat nor exposed. Remaining checks:

- Live classification with `gpt-5.4-mini` succeeded. Live weekly synthesis with `gpt-5.4` and asynchronous Batch API execution remain unverified.
- Strict classification schema acceptance and real token usage are verified. Generated summaries and scores still require editorial review; cost calculations use configured rates rather than measured charges.
- The daily email was accepted by the configured SMTP server. MIME structure, STARTTLS context, recipient parsing, transient retries and authentication-error handling are also covered by mocked SMTP tests; inbox receipt is not independently verified.
- Gmail/Outlook desktop, phone presentation and forced dark-mode behavior have not been reviewed in those clients.
- The full daily run, including SMTP delivery, completed in 16.89 seconds for nine clusters, below the five-minute target. Larger workloads have not been timed.
- EPSS, NVD and GitHub enrichment are optional and disabled by default; these integrations were not exercised against live services during this build.
- Manual daily fixture, live preview and full email-delivery workflows succeeded. Scheduled delivery and server cron have not been exercised.

`scheduling.enabled` remains **false**. Confirm inbox receipt and review client rendering before activating schedules. Manual workflow dispatch bypasses timing/activation guards and should be used deliberately.

## Operational limits

- The disabled-source list includes sites with no discovered feed, access restrictions and failed feed candidates. Their coverage is unavailable until a valid feed is configured; no page scrapers were created. Review the source-check report for the specific outcome per source.
- MSRC contributed 4,609 of the stored articles. Backfilling every retained cluster is substantially larger than a normal daily window. Use the resumable batch command deliberately and configure verified pricing first.
- Source-independence counts use configured publisher identities or feed hosts; syndicated content may require `independence_key` overrides.
- Raw ingestion clusters can contain overlapping coverage. The report-time duplicate check now consolidates the observed ConnectWise and Drupal duplicates; substantially different wording, classification errors or coverage outside the configured window may still leave separate entries. Stored cluster counts remain distinct from report item counts.
- Historical reports reuse stored classifications and currently cached advisory facts; they are not immutable snapshots of what was known at the historical date.
- Relevance scores and model-written summaries remain analytical judgments. Evidence filtering is conservative but is not an independent factual investigation.
- If an Actions database cache is evicted, restore a backup before resuming. Cache storage is not an archival backup service.

The migration and diagnostic changes are published on `codex/openai-daily-preview`; they have not been merged into `main`. Scheduling remains disabled.
