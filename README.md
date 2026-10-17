# SecDigest

Daily and weekly security intelligence for enterprise security architecture. Collect RSS/Atom stories, cluster duplicate coverage, enrich CVEs, classify with OpenAI, and generate Markdown, HTML, JSON, CSV and Gmail-ready email.

The original requirements are in [security-digest-prompt.md](security-digest-prompt.md). All taxonomies and scoring rules are editable YAML. There is no web server or hosted dashboard to operate.

## Quick start

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run from this folder:

```powershell
uv sync --locked --python 3.12 --group dev
uv run secdigest config check
uv run secdigest --dry-run
uv run secdigest --dry-run weekly --preview
```

You can also use `.venv\Scripts\secdigest.exe` directly. On this Windows workspace, migration checks use `.venv-openai\Scripts\secdigest.exe` because Windows denied removing a package from the older environment. To use that environment with uv, set `$env:UV_PROJECT_ENVIRONMENT = '.venv-openai'` before the commands above.

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

The defaults in `config/settings.yaml` are `gpt-5.4-mini` for classification and `gpt-5.4` for weekly synthesis. Both use the OpenAI Responses API with strict function schemas and local evidence validation. Live classification checks model metadata when permitted. If the metadata endpoint returns 403, the requested API operation validates model access instead, since model reading and generation have separate permissions. Generation errors still stop the run; it does not silently choose another model. The model IDs and public rates are documented by OpenAI, but access still depends on your API project. Anthropic credentials are no longer used. The original prompt is preserved as the initial specification; the provider was changed at the user's request.

For a custom API endpoint, add a GitHub Actions repository secret named **`OPENAI_BASE_URL`**, alongside **`OPENAI_API_KEY`**. Set it to the provider's API base URL, for example `https://gateway.example.com/v1` or `https://resource.openai.azure.com/openai/v1`. Include the provider's required path prefix, but omit operation suffixes such as `/responses` or `/chat/completions`, credentials, query parameters and fragments. The application uses this endpoint for classification, weekly synthesis, model lookup and Batch/Files API calls. The provider must support the Responses API with strict function calls and the configured model IDs; batch backfills also require its Batch/Files APIs. Configure model names and pricing for that provider in `config/settings.yaml`. Do not change the endpoint while a batch job is pending.

The same environment variable works locally. Surrounding whitespace is trimmed; an empty GitHub secret keeps the standard OpenAI endpoint. Fixture mode removes both API settings and stays offline. The endpoint is not printed in application logs.

```powershell
uv run secdigest feeds check
uv run secdigest ingest
uv run secdigest run-daily --no-send --preview
uv run secdigest daily --preview
uv run secdigest weekly --week 2026-W42 --preview
uv run secdigest email test
uv run secdigest run-daily
```

The first daily command classifies only the report's 24-hour window. This matters because some feeds, especially MSRC, expose thousands of historical entries. Regular daily runs reuse previously stored classifications. `weekly` and `run-weekly` use stored classifications and synthesize the week's summary; they do not reclassify stories. Reports prominently show the count of unclassified clusters so incomplete collection is not represented as a quiet period.

After classification, a second duplicate check combines matching incident coverage into one report entry with all distinct source links. It compares normalized headlines and summaries, protects differing named subjects, CVEs and regulatory events, and requires every member of a group to match every other member. `scoring.yaml` → `post_dedup` controls the publication window (48 hours by default) and headline/summary similarity thresholds (70/65). This is a conservative text heuristic: ambiguous matches remain separate. It adds no API calls and leaves stored articles and classifications intact.

The representative is selected by severity, then priority; its prose and relevance scores are retained. Validated CVEs, technologies, actors, techniques, detection links and countries are combined, and scoring overrides are recomputed from the original model values. Deduplication runs before daily and weekly totals, previous-week comparisons, synthesis and every output format, including email. JSON includes `duplicates_removed` and each merged item's `merged_cluster_ids`; the run log also records the removed count.

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

Optional full text is available for classification only:

```powershell
uv sync --extra fulltext
uv run secdigest classify --fetch-fulltext
```

Full text is fetched under the site's robots policy, used transiently as classification context and never archived or republished. Feed summaries remain the audit evidence, so detection links and dates absent from summaries are conservatively omitted. `page_watch` sources remain disabled; the application does not scrape them.

## Configuration

| File | Controls |
|---|---|
| `settings.yaml` | Timezone, file paths, HTTP limits, models, pricing, optional enrichment, email, retention, activation |
| `feeds.yaml` | All 51 source definitions, discovered URLs, enabled state, verification status, advisory endpoints |
| `regions.yaml` | Region keys, priority-country mappings, country aliases and bonuses |
| `industries.yaml` | Industry keys, display names and classification signals |
| `practice_areas.yaml` | Practice keys, display names and classification signals |
| `watch_tech.yaml` | Products grouped by vendor, aliases and cross-industry applicability |
| `regulations.yaml` | Regulation keys, jurisdiction, region, relevant industries and milestones |
| `case_studies.yaml` | Published anonymized studies and sector/practice/country references |
| `writing.yaml` | Published writing used by content outlines |
| `scoring.yaml` | Cached importance rubric, categories, weights, deduplication thresholds and inclusion rules |

The JSON tool schema and cached system prompt are generated at runtime from these files. Adding an industry or practice requires no Python edits. Existing classifications do not silently acquire scores for new keys: explicitly reclassify affected stored clusters after a taxonomy change. Run `config check` after edits.

To add a case study, append a slug entry to `case_studies.yaml` containing `title`, `industry`, `country`, `practice_areas` and `url`. Use existing industry/practice keys and an anonymized published URL. A case study can be linked only when its sector, country or practice overlaps the story. Never add client names.

To add a technology alias, extend that product's `aliases` list. Matching is case insensitive and uses word boundaries. Set `cross_industry: true` for generic enterprise platforms that should raise every industry score to the configured minimum.

Set `independence_key` on related feed definitions when publishers share editorial ownership or syndicated coverage. Otherwise, feed hostnames identify independent sources. Source independence is an approximation; editorial duplication may still need configuration.

The default score is 40% importance plus 20% each for the strongest configured priority region, industry and practice. `Other` is retained in every report but excluded from priority by default. Priority-country aliases normalize UK/GB and UAE/AE. Each distinct directly involved priority country adds its configured bonus once, capped at 100 for that region. Overrides always start from the original saved model output, so reruns do not repeatedly increase scores.

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

`feeds check` checks the supplied URL or discovers RSS/Atom links from a site's `<link rel="alternate">` metadata. Failed sources are disabled with a reason. Sources with no discovered feed become disabled `page_watch` entries. The source check report is written to `output/source-check.json`, including discovered candidates. Run the check again after editing a URL to re-enable a recovered source.

Routine fetch errors do not permanently disable feeds. Collection uses bounded concurrency, timeouts, response-size limits, conditional ETag/Last-Modified requests, robots policies, crawl delays and HTTP retry/backoff. It collects feed summaries only by default. Publication and collection timestamps are stored separately; missing publication dates are labelled as inferred and future-dated items are excluded.

CVEs are checked against CISA KEV. EPSS, NVD and GitHub advisory enrichment are independently optional. NVD calls observe its unauthenticated rate limit. MITRE's enterprise ATT&CK dataset validates technique IDs. Unavailable enrichment is labelled rather than converted to zero or invented. KEV addition dates have day precision, so counts include catalog dates overlapping the report's local date window.

Source CVEs, published detection URLs, regulation dates, case-study references and actor names are validated against available evidence. Reports label detection recommendations as assessments. These checks constrain generated output; they do not independently prove every factual claim or relevance score. Review original sources before operational action.

## Archives and email

Live archives are `output/daily/YYYY-MM-DD.{md,html,json,csv}` and `output/weekly/YYYY-Www.{md,html,json,csv}`. CSV exports retain every regional, industry and practice score, overrides, CVEs and advisory facts, technologies, techniques, regulations, related studies and source URLs. Spreadsheet formula prefixes are escaped.

Daily emails attach full HTML and CSV. Weekly emails also attach Markdown. MIME structure is mixed → alternative (plain text, HTML) → attachments. HTML email uses inline CSS, table layout, text-labelled importance badges and no external images/fonts/scripts. Feed-derived text is escaped and links are restricted to HTTP/HTTPS.

The HTML email body is strictly below 90,000 UTF-8 bytes. Lowest-priority content moves to the attachment first; unusually large high-severity sets are compacted with a clear notice. The attachment always retains the complete report. Real Gmail/Outlook rendering and forced dark mode still require review in those clients.

Successful sends are recorded by digest type and report period. Reruns do not resend unless `--force-send` is used. SMTP retries transient failures three times with backoff, never authentication errors. SMTP cannot guarantee exactly-once delivery if the connection fails after acceptance; inspect delivery before forcing a retry after an ambiguous failure.

Source-health emails trigger when more than 30% of enabled sources fail or no new article has arrived in 24 hours. Successful source-health alerts suppress repeats for three days. Each run records all email attempts, including failure alerts, in `run_log.json`. Logs retain the last 365 runs; `badge.json` reports the latest result. Exception logs omit raw exception messages, response bodies, source lines and environment values.

Daily outputs are retained for 90 days and stored news for 120 days; weekly archives are retained indefinitely. The application closes SQLite before workflow commit-back. Preview emails are ignored by Git because they may contain configured sender/recipient addresses.

## Scheduling

The workflows are ready but `scheduling.enabled` is **false**. Before changing it:

1. Configure `OPENAI_API_KEY`, optional `OPENAI_BASE_URL`, and the email repository secrets listed above, and verify model access at that endpoint.
2. Generate and review daily/weekly previews, including Gmail desktop and phone presentation.
3. Run `secdigest email test` and confirm receipt.
4. Run a live daily digest and a weekly preview, verify coverage and usage, then set `scheduling.enabled: true`.

Daily schedules use `0 5 * * *` and `0 6 * * *` UTC, guarded for 07:00 Europe/Amsterdam. Weekly schedules use `0 6 * * 1` and `0 7 * * 1`, guarded for Monday 08:00. Manual dispatch skips the timing/activation guards and supports `mode`, `force_send` and date/week overrides. GitHub scheduled jobs may start late; the guard accepts the target hour. If you change the configured timezone or target hours, update the workflow's early hour guard and UTC schedules too.

Manual runs default to `mode=preview`: daily runs collect and classify live news; weekly runs summarize stored news. Both generate reports and `.eml` previews without SMTP credentials or delivery. Choose `mode=fixtures` for an offline demonstration requiring no API key. Preview artifacts are downloadable from the Actions run for seven days and are not committed back or saved to the database cache. Failed previews also upload their diagnostic log: check its latest status, since the artifact may contain historical sample reports. API diagnostics retain only the HTTP status and recognized error codes, never raw provider messages. Choose `mode=send` explicitly for email delivery; only that mode honors `force_send`. Enabled scheduled runs use `send`.

Once a valid `OPENAI_API_KEY` Actions secret and these workflow changes are on the selected GitHub branch, run **Actions → SecDigest daily → Run workflow → mode: preview**. Without a key, choose `fixtures`.

Both workflows serialize on the same concurrency group because they share SQLite and archives. The shared runner uses Python 3.12, pip caching, the locked requirements export, and the existing tracker's `github-actions[bot]` identity. It commits only runtime artifacts when changed, including failure logs. It never force-pushes. A database above 50 MB switches to `actions/cache` and emits a notice; `data/storage-mode.json` records that choice. Keep an independent database backup because Actions caches can be evicted. A missing required database cache stops processing instead of silently rebuilding history.

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

The suite covers dynamic taxonomy schemas, invalid-model retries, claim filtering, batch resumption, URL/indicator normalization, clustering, scoring overrides, country bonuses, watch aliases, date windows, DST, source discovery and caching, idempotent ingestion, Markdown golden files, HTML escaping, 200-item email limits, CSV scores, MIME structure, SMTP retry policy, failure alerts, source-health silence and CLI isolation.

`scripts/fixture_previews.py` regenerates synthetic report archives. Its `--update-golden` flag deliberately replaces test expectations; review rendered changes before using it. `scripts/seed_config.py` is a one-time importer from the original prompt and refuses to overwrite existing configuration. The running application does not depend on the prompt file.

See [VALIDATION.md](VALIDATION.md) for observed checks, remaining credential-dependent checks and limitations.
