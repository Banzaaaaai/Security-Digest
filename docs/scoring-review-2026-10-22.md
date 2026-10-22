# Scoring review — 22 October 2026

PHP was underweighted because regional applicability was treated like the location of reported victims. The original formula gave relevance 60% of the score, excluded `Other`, rewarded each priority-country mention and could raise severity merely because more publishers covered a story. Critical vulnerability, exploitation and supply-chain classifications also varied between reports of the same event.

The revised calculation puts the leading PHP exploitation report first at **96/100**, with **US 95%, Europe 95%, MEA 95%, Other 95%**. These percentages describe applicability to organizations using affected software, not the probability of compromise or a claim that 95% of organizations are affected.

## Scope and artifacts

Reviewed the source titles and stored summaries for **all 106 entries in the supplied email**, including its attachment-only coverage. The original window is **21 October 09:51:07.747282 UTC to 22 October 09:51:07.747282 UTC**, end exclusive. The matching archive and database were recovered from commit `d482993ff8a3a91480b25410474aaeb67b34810e` so the comparison does not change collection time or membership.

- [Corrected report for the supplied email (HTML)](../output/review/2026-10-22-original/daily/2026-10-22.html)
- [Corrected report (Markdown)](../output/review/2026-10-22-original/daily/2026-10-22.md)
- [All 106 before/after rows (CSV)](../output/review/2026-10-22-original/comparison.csv)
- [Complete comparison with industry/practice percentages, reasons and evidence (JSON)](../output/review/2026-10-22-original/comparison.json)
- [Corrected report data (JSON)](../output/review/2026-10-22-original/daily/2026-10-22.json)

The later archived run ends at **22 October 10:47:26.276043 UTC** and contains 105 entries, seven absent from the supplied email. Those seven source summaries were also reviewed: PAN-OS/Panorama applicability, BlackX espionage, Cisco patches, Dutch parliamentary questions, two PHP exploitation updates and a pseudonymization opinion. This covers **113 distinct archived story entries** across both windows.

- [Corrected later report (HTML)](../output/review/2026-10-22-latest/daily/2026-10-22.html)
- [All 105 later-run comparisons (CSV)](../output/review/2026-10-22-latest/comparison.csv)

No email was sent. Original daily archives and runtime data remain unchanged. The review script opens a matching SQLite snapshot read-only, copies it into memory, checks identical story membership and writes separate artifacts. No OpenAI calls or reclassification charges were needed.

## What changed

1. **Severity leads priority.** Weights are 60% importance, 15% location, 10% industry and 15% technical practice. Results stay within ordered bands: critical 85–100; high 65–84.99; medium 35–64.99; low 0–34.99. Regional relevance cannot move a medium product announcement above a critical incident.
2. **Global deployment is assessed consistently.** PHP, Node.js and common web/OS infrastructure receive 95% in all regions for source-supported product security events. Enterprise distribution infrastructure receives 85%; specialist/consumer software receives 75%. These editable anchors are judgments about applicability, not measured installation shares. Technology aliases must match both the affected-technology assessment and source evidence. Local incidents, court decisions, regulatory activity, research and ordinary announcements retain their separate geographic assessment.
3. **All regions participate.** `Other` now contributes equally to the priority calculation. A material incident in Japan is no longer discounted simply because it is outside US/Europe/MEA. Nonglobal country bonuses apply at most once per region; global product events do not receive issuer-country bonuses.
4. **Evidence controls urgency.** Source-reported exploitation attempts and actual systemic supplier/package compromise can establish critical urgency. A critical RCE with a PoC or emergency patch alone remains high. Negated claims, predictions and lab demonstrations do not establish active attacks. High EPSS and older KEV entries establish at most a high floor by themselves. Source counts record corroboration without increasing severity.
5. **Cross-industry relevance reflects deployment.** Common infrastructure establishes a 60% minimum; enterprise distribution infrastructure 50%; specialist software 30%. Higher source assessments remain. Technical practice scores are retained, with a reduced weight in the final priority.
6. **Exact vulnerability coverage shares evidence.** Matching CVE sets and a shared affected product can combine patch/disclosure/exploitation coverage. Different CVE sets, advisory identities and actors remain protected. Three additional duplicate entries are consolidated in each reviewed window. All original stories retain a comparison row and source links.
7. **Calculations are auditable.** JSON/CSV include weighted components, severity bands, source URLs for recognized risk signals, deployment scope and corroboration counts. Scoring always starts from the original saved classification. When severity changes, its displayed rationale changes too.

## Representative results from the supplied email

| Story | Before | After | Revised location applicability |
|---|---:|---:|---|
| PHP exploitation, broad web exposure | Critical 82 | **Critical 96** | **95% in every region** |
| LiteLLM credential-stealing package compromise | High 69 | **Critical 94.75** | 85% in every region |
| ConnectWise / Microsoft 365 campaign | Critical 90 | Critical 93.75 | 85% in every region |
| Active Plex exploitation | Critical 84 | Critical 87.25 | 75% in every region; CISA's US location does not imply US-only exposure |
| GitLab unauthenticated RCE patch | Critical 78 | High 79.25 | 85% in every region; available summary does not establish active exploitation |
| Node.js Brotli RCE update | High 70 | High 78.75 | 95% in every region |
| Windows Defender local privilege-escalation analysis | High 68 | High 77.25 | 95% in every region; lab analysis/older KEV does not establish a new active campaign |
| African cybercrime operation | High 78 | High 77.5 | MEA 85%; regional scope retained |
| Japan VPS provider compromise | High 59 | High 75.75 | Other 85%; regional scope retained and now counted equally |
| UAE government AI rollout | Medium 75 | Medium 64.99 | MEA 100%; relevance cannot override its medium severity |

For the original 106 rows, 17 severity labels, 46 location assessments, 42 industry assessments and 105 priority values change. The revised report has 103 entries: 14 critical, 35 high, 40 medium and 14 low. The later report has 102 entries: 16 critical, 35 high, 38 medium and 13 low. Counts describe report entries; ambiguous duplicate coverage remains separate.

## PHP source checks

The original PHP vendor advisories were read through GitHub's API during this review:

- [CVE-2026-109618 — RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 — RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

Both list critical severity and fixes in PHP **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. The source snapshot also contains [CISA advisory VA-26-295-01](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/va-26-295-01.json), which identifies both CVEs and describes application-independent RCE against mod_php under the stated conditions. Reports from [KrebsOnSecurity](https://krebsonsecurity.com/2026/10/widespread-php-flaw-may-cause-many-site-outages-today/) and [SecurityWeek](https://www.securityweek.com/php2shell-patches-land-as-first-exploitation-attempts-hit-sensors/) supply the stored exploitation/attempt observations used by the scorer. An observed attempt is not relabeled as a successful compromise.

Unavailable EPSS/CVSS enrichment remains unknown. No percentage of affected websites or organizations was invented to justify priority.

## Validation and limits

**178 tests passed**, including new cases for global PHP versus local news, source negation, future predictions, lab demonstrations, reported attempts, systemic compromise, old/future KEV entries, equal `Other` weighting, duplicate CVE coverage, rerun stability and read-only review snapshots. Ruff checks and formatting passed. Offline daily and weekly CLI previews also completed.

The review covers the archived evidence, not every publisher's full article or an independent forensic validation of every claim. Risk phrase recognition currently covers English and selected Dutch phrases. Missing signals are not proof of absence. Different summaries of the same incident can retain different importance until their identity and evidence can be linked safely; exact-CVE merging addresses the strongest identifiable cases. The updated classification instructions guide future assessments, while deterministic rules immediately recalculate stored classifications.

The implementation and separate review artifacts accompany this repository update. Subsequent daily runs use the revised policy. The original daily archives and delivery history are preserved; this review did not send a replacement digest.
