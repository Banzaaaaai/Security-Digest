# Daily digest duplicate review — 23 October 2026

The delivered digest listed the same PHP2Shell early-exploitation event under several headlines. The report-time matcher required near-identical vocabulary or an exact CVE set. Most of these feed summaries omitted CVEs, and wording such as “started before patches” and “exploitation before disclosure” failed the text comparison. Existing merges also retained only the representative's prose.

The updated matcher uses source-supported event names, affected products and additional event context. It can connect short, differently worded reports without another model call. Merged items keep all distinct source links, combine validated technical evidence, and include complementary sentences and actions with attribution. Full original summaries and actions remain in JSON `source_coverage`.

## Replay results

The original window was **22 October 09:45:05 UTC through 23 October 09:45:05 UTC**, end exclusive (11:45:05 in Paris). The replay used the archive and SQLite snapshot from GitHub commit `f1525f578e872c0ed3007b023824c1c21b1a57df`. The downloaded database's Git blob hash was verified against `8338ce18b452571a08c66004eede352f4558e3ab`.

| Measure | Delivered | Corrected preview |
|---|---:|---:|
| Stories | 94 | 85 |
| Distinct source URLs | 97 | 97 |
| Underlying classified clusters | 95 | 95 |
| Critical / high / medium / low | 10 / 43 / 26 / 15 | 6 / 38 / 26 / 15 |

The original report already removed one duplicate. The revised engine removes nine additional duplicates, ten in total:

- PHP2Shell early-exploitation and response coverage: six articles in one item, from five publishers. Both SecurityWeek links remain; they count as one independent publisher.
- LiteLLM supply-chain compromise: three articles in one item. GitHub token abuse, malicious package/container distribution and secret theft details are combined.
- VeloCloud Orchestrator: three articles in one item. The exploitation/patch notice retains the SQL-injection and privilege-escalation details from other coverage.

The engine still separates uncertain related stories, including the Mirai exploitation campaign, a separate vendor-impact report and the Dutch parliamentary response. Existing ConnectWise reports with inconsistent actor descriptions also remain separate. This change does not claim that every possible duplicate has been resolved.

## Safeguards and validation

Different CVE sets, advisory IDs, named subjects, actors and regulatory events remain protected. Without an exact CVE identity, conflicting vulnerability mechanisms prevent a merge. Roundups are excluded. Each member must match every other member, preventing a bridging article from joining unrelated incidents. Publication times must remain within the configured 48-hour interval. A shared vendor or product alone is insufficient.

Summary merging is extractive: it preserves selected sentences verbatim, including uncertainty and attribution, and omits generic restatements. It does not independently verify every pre-existing classification claim. JSON retains the complete member summaries and actions when the compact narrative omits a sentence.

Regression fixtures include 15 actual clusters from this window. Tests cover paraphrases without CVEs, combined details/actions, contrary outcomes and numbers, multiple publishers, stable ordering, unchanged storage, daily/weekly totals, all output formats, and false-merge cases including publisher boilerplate. Replay checks establish identical windows, all 97 source URLs retained and all 95 cluster IDs accounted for.

The snapshot was copied into memory for replay. The original database, archives, run log and delivery state were unchanged. No classification API call or email send was performed for the replay.

## Scheduled workflow integration

The daily and weekly workflows both invoke the shared runner, which installs the checked-out package and calls `scripts/workflow_digest.py`. That script uses the same production CLI and report builder as the regression tests; the improved matching is applied before archive generation and email composition.

The shared runner now requires `scripts/check_digest_deduplication.py` to pass before `Run digest` executes, for scheduled and manual runs in every delivery mode. This credential-free check loads the fixed real-world fixture into an in-memory database and verifies its six expected story groups, all 15 source URLs, and complementary PHP2Shell/LiteLLM/VeloCloud details. It also protects the three separate related stories from being merged. A mismatch stops report generation and delivery.

CI executes the same check. Tests deliberately disable deduplication, combine unrelated stories, remove a source link and discard complementary details to confirm that the workflow gate rejects regressions. Workflow wiring tests verify the gate is required before daily and weekly generation.

Local validation passed **198 tests**, the standalone workflow gate, Ruff lint/format checks, and whitespace checks. The full suite used approved access because Windows sandbox restrictions can block pytest's temporary directories.

## Artifacts

- [Corrected HTML preview](../output/review/2026-10-23-deduplicated/daily/2026-10-23.html)
- [Corrected Markdown](../output/review/2026-10-23-deduplicated/daily/2026-10-23.md), [JSON](../output/review/2026-10-23-deduplicated/daily/2026-10-23.json), and [CSV](../output/review/2026-10-23-deduplicated/daily/2026-10-23.csv)
- [All 94 original stories mapped to revised items](../output/review/2026-10-23-deduplicated/comparison.json)
- [Snapshot identity and source-conservation evidence](../output/review/2026-10-23-deduplicated/evidence.json)
- [Real-world regression fixture](../tests/fixtures/deduplication-2026-10-23.json)

To repeat the offline replay with the matching archive and database:

```powershell
.\.venv-openai\Scripts\python.exe scripts/review_scoring.py `
  --report output/preview/2026-10-23-original.json `
  --database output/preview/2026-10-23-snapshot.sqlite `
  --output output/review/2026-10-23-deduplicated
```

The downloaded snapshots are in the ignored preview directory; the original files are also available at the pinned GitHub commit above.
