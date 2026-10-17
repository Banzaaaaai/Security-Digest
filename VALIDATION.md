# SecDigest validation record

Validation date: **17 October 2026**, Europe/Paris.

## Completed

| Check | Observed result |
|---|---|
| Project environment | Python 3.12.13 installed through uv; dependency lock and pip requirements export generated |
| Configuration | 4 regions, 10 industries, 11 practice areas, 12 case studies, 3 writing references and 51 feed definitions |
| Automated tests | **59 passed** after the OpenAI migration; includes SDK HTTP request mocks, invalid-output retries, cached-token cost accounting, batch resumption/failure handling, weekly reference validation and preview credential isolation |
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

The authorized local key was added to GitHub Actions secrets without displaying it, but an OpenAI model-list request returned HTTP 401. The user will replace `OPENAI_API_KEY` later and requested implementation-only verification meanwhile. No live classification or synthesis was attempted after that instruction. API project model access, actual schema acceptance and generated content remain unverified.

The suite passed in `.venv-openai` (Python 3.12.13) after Windows blocked removal of an old package in `.venv`; pytest required execution outside the filesystem sandbox to access its temporary directory. Daily and weekly fixture runs through `scripts/workflow_digest.py` succeeded with API and email credentials removed from the child environment. Both produced all four report formats and `.eml` previews, with 12 synthetic clusters and zero unclassified items. No email was sent.

Manual Actions runs now default to `preview`; `fixtures` works without a key and `send` explicitly enables email. Preview modes do not commit artifacts or update the persistent database cache. The updated workflows have been checked locally, not dispatched on GitHub.

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

Email secrets exist in GitHub Actions. A working `OPENAI_API_KEY` is still needed. Secret values were neither requested in chat nor exposed. Consequently:

- The configured OpenAI model IDs have not been verified against the user's API project. Confirm access before enabling live classification.
- OpenAI tool-schema acceptance, actual classification/synthesis quality and real token usage remain unverified. Retry, evidence validation, SDK request structure and Batch API resumption were exercised with mocks; cost calculations use published standard rates rather than measured charges.
- No Gmail message was sent. MIME structure, STARTTLS context, recipient parsing, transient retries and authentication-error handling were tested with mocked SMTP.
- Gmail/Outlook desktop, phone presentation and forced dark-mode behavior have not been reviewed in those clients.
- The complete live `run-daily` acceptance target of under five minutes is **not yet verified**. The measured 53.98 seconds covers collection and advisory enrichment only; API classification and email would add time.
- EPSS, NVD and GitHub enrichment are optional and disabled by default; these integrations were not exercised against live services during this build.
- The original GitHub checks workflow passed ([run 39069412641](https://github.com/Banzaaaaai/Security-Digest/actions/runs/39069412641)). The updated OpenAI workflows, live digest workflow and server cron have not been executed. YAML parsing and mocked/local DST tests do not substitute for an actual scheduled run.

`scheduling.enabled` remains **false**. Complete the preview review and successful real email test required by the original prompt before activating schedules. Manual workflow dispatch bypasses timing/activation guards and should be used deliberately.

## Operational limits

- The disabled-source list includes sites with no discovered feed, access restrictions and failed feed candidates. Their coverage is unavailable until a valid feed is configured; no page scrapers were created. Review the source-check report for the specific outcome per source.
- MSRC contributed 4,609 of the stored articles. Backfilling every retained cluster is substantially larger than a normal daily window. Use the resumable batch command deliberately and configure verified pricing first.
- Source-independence counts use configured publisher identities or feed hosts; syndicated content may require `independence_key` overrides.
- Historical reports reuse stored classifications and currently cached advisory facts; they are not immutable snapshots of what was known at the historical date.
- Relevance scores and model-written summaries remain analytical judgments. Evidence filtering is conservative but is not an independent factual investigation.
- If an Actions database cache is evicted, restore a backup before resuming. Cache storage is not an archival backup service.

This migration has not been committed or pushed. Scheduling remains disabled.
