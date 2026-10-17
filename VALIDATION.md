# SecDigest validation record

Validation date: **17 October 2026**, Europe/Paris.

## Completed

| Check | Observed result |
|---|---|
| Project environment | Python 3.12.13 installed through uv; dependency lock and pip requirements export generated |
| Configuration | 4 regions, 10 industries, 11 practice areas, 12 case studies, 3 writing references and 51 feed definitions |
| Automated tests | **41 passed** in the final offline suite |
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

Fixture reports are explicitly synthetic. Their CVEs, headlines and scores are test inputs, not real incident reports. The live database contains source summaries and advisory facts but **no live Claude classifications**.

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

`ANTHROPIC_API_KEY`, `SMTP_USER`, `SMTP_PASSWORD` and `EMAIL_TO` were not configured. Their values were neither requested in chat nor exposed. Consequently:

- The configured `claude-haiku-5-5` and `claude-sonnet-5-5` IDs have not been verified against an Anthropic account. Choose accessible model IDs before enabling live classification.
- Claude tool-schema acceptance, actual classification/synthesis quality, real token usage and real model pricing remain unverified. Retry, evidence validation, cache request structure and Message Batches resumption were exercised with mocks.
- No Gmail message was sent. MIME structure, STARTTLS context, recipient parsing, transient retries and authentication-error handling were tested with mocked SMTP.
- Gmail/Outlook desktop, phone presentation and forced dark-mode behavior have not been reviewed in those clients.
- The complete live `run-daily` acceptance target of under five minutes is **not yet verified**. The measured 53.98 seconds covers collection and advisory enrichment only; API classification and email would add time.
- EPSS, NVD and GitHub enrichment are optional and disabled by default; these integrations were not exercised against live services during this build.
- GitHub Actions and server cron have not been deployed or executed. YAML parsing and mocked/local DST tests do not substitute for an actual scheduled run.

`scheduling.enabled` remains **false**. Complete the preview review and successful real email test required by the original prompt before activating schedules. Manual workflow dispatch bypasses timing/activation guards and should be used deliberately.

## Operational limits

- The disabled-source list includes sites with no discovered feed, access restrictions and failed feed candidates. Their coverage is unavailable until a valid feed is configured; no page scrapers were created. Review the source-check report for the specific outcome per source.
- MSRC contributed 4,609 of the stored articles. Backfilling every retained cluster is substantially larger than a normal daily window. Use the resumable batch command deliberately and configure verified pricing first.
- Source-independence counts use configured publisher identities or feed hosts; syndicated content may require `independence_key` overrides.
- Historical reports reuse stored classifications and currently cached advisory facts; they are not immutable snapshots of what was known at the historical date.
- Relevance scores and model-written summaries remain analytical judgments. Evidence filtering is conservative but is not an independent factual investigation.
- If an Actions database cache is evicted, restore a backup before resuming. Cache storage is not an archival backup service.

No repository commit, push, external publication or scheduled activation was performed during this build.
