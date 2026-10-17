# SecDigest validation record

Validation date: **17 October 2026**, Europe/Paris.

## Completed

| Check | Observed result |
|---|---|
| Project environment | Python 3.12.13 installed through uv; dependency lock and pip requirements export generated |
| Configuration | 4 regions, 10 industries, 11 practice areas, 12 case studies, 3 writing references and 51 feed definitions |
| Automated tests | **71 passed** on GitHub after the OpenAI migration and diagnostics update; includes SDK HTTP request mocks, invalid-output retries, cached-token cost accounting, batch resumption/failure handling, weekly reference validation, preview credential isolation and secret-safe error metadata distinguishing quota exhaustion from rate limiting |
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

Fixture reports are explicitly synthetic. Their CVEs, headlines and scores are test inputs, not real incident reports. The live database contains source summaries and advisory facts but **no live AI classifications**.

## OpenAI migration

At the user's request, classification and weekly synthesis now use the OpenAI Responses API with strict function calls. Historical backfills use the OpenAI Batch API, including persisted file/job IDs and partial-failure handling. Defaults are `gpt-5.4-mini` and `gpt-5.4`; public model support and standard pricing were checked against the official model pages. Dependencies are locked to OpenAI SDK 2.54.0; Anthropic is no longer a runtime dependency.

The latest [GitHub live daily preview](https://github.com/Banzaaaaai/Security-Digest/actions/runs/39072206668) successfully authenticated and retrieved the configured classification model, resolving the earlier HTTP 401 issue. The first Responses API classification request then failed with HTTP **429**, categorized from the provider response as **quota exhaustion**. No token usage was recorded, and no live digest was generated. Check API credits and spending limits for the key's project before retrying; another key rotation is not indicated by this response. Actual schema acceptance and generated content remain unverified.

That run checked 22 enabled feeds: 21 succeeded, CISA Advisories returned an HTTP error, and no new articles were added. The existing database was reused. Preview mode provided no SMTP credentials and the diagnostic log confirms `email_sent: false`.

The suite passed in `.venv-openai` (Python 3.12.13) after Windows blocked removal of an old package in `.venv`; pytest required execution outside the filesystem sandbox to access its temporary directory. Daily and weekly fixture runs through `scripts/workflow_digest.py` succeeded with API and email credentials removed from the child environment. Both produced all four report formats and `.eml` previews, with 12 synthetic clusters and zero unclassified items. No email was sent.

Manual Actions runs now default to `preview`; `fixtures` works without a key and `send` explicitly enables email. Preview modes do not commit artifacts or update the persistent database cache. The [GitHub daily fixture preview](https://github.com/Banzaaaaai/Security-Digest/actions/runs/39071318944) succeeded, and its downloaded artifact was verified: 12 synthetic clusters, all four report formats, an `.eml` preview and `email_sent: false`. Failed previews also upload a diagnostic run log; inspect its latest status before treating any archived files in the artifact as a completed live report.

## Artifacts

- [Daily sample HTML](output/samples/daily/2026-10-17.html)
- [Weekly sample HTML](output/samples/weekly/2026-W42.html)
- [Daily sample Markdown](output/samples/daily/2026-10-17.md)
- [Weekly sample Markdown](output/samples/weekly/2026-W42.md)
- `output/samples/preview/secdigest-daily-2026-10-17.eml`
- `output/samples/preview/secdigest-weekly-2026-W42.eml`
- `output/source-check.json`: source-by-source status and discovered feed candidates
- `data/secdigest.sqlite`: live ingestion state, advisory caches and source provenance
- `run_log.json` and `badge.json`: live command history and status

Preview messages and sample run logs are ignored by Git. Archived sample reports are intended to be reviewable project artifacts.

## Still requiring live credentials or client review

Email secrets and an authenticated `OPENAI_API_KEY` exist in GitHub Actions. Available OpenAI API quota is still needed. Secret values were neither requested in chat nor exposed. Consequently:

- Retrieval of `gpt-5.4-mini` succeeded against the user's API project. Successful generation and access to the weekly synthesis model remain unverified.
- OpenAI tool-schema acceptance, actual classification/synthesis quality and real token usage remain unverified. Retry, evidence validation, SDK request structure and Batch API resumption were exercised with mocks; cost calculations use published standard rates rather than measured charges.
- No Gmail message was sent. MIME structure, STARTTLS context, recipient parsing, transient retries and authentication-error handling were tested with mocked SMTP.
- Gmail/Outlook desktop, phone presentation and forced dark-mode behavior have not been reviewed in those clients.
- The complete live `run-daily` acceptance target of under five minutes is **not yet verified**. The measured 53.98 seconds covers collection and advisory enrichment only; API classification and email would add time.
- EPSS, NVD and GitHub enrichment are optional and disabled by default; these integrations were not exercised against live services during this build.
- The updated [GitHub checks workflow passed](https://github.com/Banzaaaaai/Security-Digest/actions/runs/39072205428), including 71 tests, Ruff and daily/weekly fixture previews. Manual daily fixture execution passed; live execution remains blocked by OpenAI API quota exhaustion. Scheduled delivery and server cron have not been exercised.

`scheduling.enabled` remains **false**. Complete the preview review and successful real email test required by the original prompt before activating schedules. Manual workflow dispatch bypasses timing/activation guards and should be used deliberately.

## Operational limits

- The disabled-source list includes sites with no discovered feed, access restrictions and failed feed candidates. Their coverage is unavailable until a valid feed is configured; no page scrapers were created. Review the source-check report for the specific outcome per source.
- MSRC contributed 4,609 of the stored articles. Backfilling every retained cluster is substantially larger than a normal daily window. Use the resumable batch command deliberately and configure verified pricing first.
- Source-independence counts use configured publisher identities or feed hosts; syndicated content may require `independence_key` overrides.
- Historical reports reuse stored classifications and currently cached advisory facts; they are not immutable snapshots of what was known at the historical date.
- Relevance scores and model-written summaries remain analytical judgments. Evidence filtering is conservative but is not an independent factual investigation.
- If an Actions database cache is evicted, restore a backup before resuming. Cache storage is not an archival backup service.

The migration and diagnostic changes are published on `codex/openai-daily-preview`; they have not been merged into `main`. Scheduling remains disabled.
