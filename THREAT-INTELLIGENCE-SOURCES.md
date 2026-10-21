# Threat intelligence source review

Reviewed **18 October 2026**. Ten public RSS/Atom feeds were added to
`config/feeds.yaml`, taking the configuration from **24 to 34 enabled feeds**
(62 definitions total). FIRST EPSS enrichment is now enabled. CISA KEV and
MITRE ATT&CK were already active.

Here, subscribing means polling a public endpoint during digest collection.
No accounts, paid subscriptions, mailbox subscriptions, or email deliveries
were created. The daily archive predates these source additions.

## Added subscriptions

| Feed | Endpoint | Entries ingested in the live smoke check |
|---|---|---:|
| Contagio | [RSS](https://contagiodump.blogspot.com/feeds/posts/default?alt=rss) | 0; newest entry 2024-11-12 |
| GitHub Security Blog | [RSS](https://github.blog/security/feed/) | 10 |
| Google Project Zero | [Atom](https://projectzero.google/feed.xml) | 3 |
| GreyNoise Blog | [RSS](https://www.greynoise.io/blog/rss.xml) | 13 |
| GreyNoise Labs | [RSS](https://www.labs.greynoise.io/grimoire/index.xml) | 0; newest entry 2026-03-23 |
| Metasploit Blog | [RSS](https://www.rapid7.com/blog/tag/metasploit/rss/) | 10 |
| Qualys Vulnerabilities and Threat Research | [RSS](https://blog.qualys.com/vulnerabilities-threat-research/feed) | 10 |
| Qualys ThreatPROTECT | [RSS](https://threatprotect.qualys.com/feed/) | 10 |
| ReversingLabs Blog | [RSS](https://www.reversinglabs.com/blog/rss.xml) | 50 |
| Seebug Vulnerabilities | [RSS](https://www.seebug.org/rss/new/) | 0; feed contained no entries |

Counts are source articles within the existing 120-day retention window, not
daily report items or independently corroborated incidents. Contagio and
GreyNoise Labs remain subscribed for future updates; their old posts do not
become fresh news. Seebug is reachable, but useful publication coverage is
unproven. The public vendor blogs do not provide their commercial databases.

Qualys's research RSS currently repeats its category URL for every article.
Its URL-shaped GUIDs were verified to resolve to individual posts. That feed
uses `entry_url_field: id`; the parser accepts only safe URLs on the feed's
own host for this option. Other feeds retain their normal article links.
Related GreyNoise and Qualys feeds share publisher independence keys.
GitHub and Microsoft's configured feeds share `microsoft.com` for future
ingestion; existing stored articles are not rewritten by a configuration edit.

## Every requested source

| Requested source | Decision and observed access |
|---|---|
| CISA Known Exploited Vulnerabilities | Already active as JSON enrichment, with the [official GitHub mirror](https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json). The mirror was reachable. The catalog's ransomware-use field is retained. |
| Contagio | Added public RSS. Stale at the time of verification; only feed text and references are collected, not linked sample archives. |
| Core Impact | Not enabled. The [Core Labs exploits page](https://www.coresecurity.com/core-labs/exploits) could not be checked because robots retrieval was denied/unavailable. No usable public feed was verified. Product access is not established by this review. |
| EPSS | Enabled the existing FIRST integration. The [public API](https://api.first.org/data/v1/epss?cve=CVE-2024-3094) returned a dated probability and percentile without credentials. This enriches CVEs already found in collected articles; it is not a news feed. |
| GitHub | Added GitHub Security Blog. The [advisory API](https://api.github.com/advisories?per_page=1) also responded publicly, but per-CVE API enrichment remains disabled: the current implementation queries all retained CVEs and could exceed the [unauthenticated REST budget](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api). The attempted advisories Atom URL returned HTTP 406. Blog coverage is not the complete Advisory Database. |
| Google Zero Day | Added Project Zero's current Atom endpoint, discovered via the old Blogger feed's redirect. The separate [0days-in-the-wild feed](https://googleprojectzero.github.io/0days-in-the-wild/feed.xml) was valid but empty; the [tracking site](https://googleprojectzero.github.io/0days-in-the-wild/) is not ingested as a catalog. |
| GreyNoise | Added Blog and Labs RSS. These provide research, not full scanner telemetry or IP enrichment. [Community API documentation](https://docs.greynoise.io/docs/using-the-greynoise-community-api) describes a separate integration; none was configured. |
| Immunity Canvas | Not enabled. The checked [legacy product URL](https://www.immunityinc.com/products/canvas/) returned 404; no current subscribable endpoint was verified. Qualys's historical exploit-source documentation mentions Canvas, but does not grant access to its catalog. |
| MISP Exploits | No news subscription added. The public [MISP exploit-kit galaxy](https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/exploit-kit.json) was reachable (54 entries), but it is an exploit-kit reference vocabulary, not a dated exploit/CVE feed and not proven to be the exact source meant by this label. |
| MISP Threat Actors | The public [threat-actor galaxy](https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json) was reachable (1,097 entries). It is a reference dataset, not a chronological story feed. Integrating its aliases/relationships needs a dedicated consumer; it is not falsely marked as active digest coverage. MISP event feeds also have provider-specific formats and terms. |
| McAfee Threat Landscape | Not enabled. McAfee feed and threat-center checks timed out or failed; Trellix research could not be checked because robots retrieval was denied/unavailable. A search result for the [historical dashboard announcement](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-launches-threat-landscape-dashboard/) mentioned RSS, but a current working dashboard feed was not verified. |
| Metasploit | Added Rapid7's Metasploit RSS for module/research announcements. This does not execute or ingest the framework's exploit modules. |
| Mitre ATT&CK | Already active: the [enterprise STIX dataset](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json) validates technique IDs. Its configured consumer was inspected; the large dataset was not downloaded again during this review. It is not a threat-news stream. |
| Packetstorm | Kept the existing entry disabled and updated its error. The [news](https://packetstorm.news/rss/news) and files RSS paths were disallowed by robots.txt for the digest collector. This is blocked collection, not an empty feed. |
| Qualys Cloud Threat DB | Added public Qualys research and ThreatPROTECT feeds as explicitly limited alternatives. The [Cloud Threat Database description](https://blog.qualys.com/product-tech/2023/02/08/introducing-qualys-ml-based-threat-intelligence) describes intelligence unified inside Qualys products. No public bulk database API or tenant entitlement was verified. |
| Ransomware Vulnerability Catalog | No independent publisher/endpoint verified for this exact name. Exact-name and broader web searches did not establish a subscribable catalog. The already-active CISA KEV ransomware-use field supplies narrower, explicitly attributed context; it is not claimed to be this catalog. |
| Reversing Labs | Added public research RSS. Commercial file reputation, sample analysis, and intelligence APIs remain outside this subscription. |
| Seebug | Added the reachable vulnerability RSS; it currently has zero entries. [Paper Seebug RSS](https://paper.seebug.org/rss/) could not be checked because robots retrieval was denied/unavailable. No authenticated API was configured. |
| Trending CVE's Catalog | No independent public endpoint verified. [Qualys VMDR documentation](https://docs.qualys.com/en/vmdr/latest/mergedProjects/prioritize_your_vulnerabilities/threat_intelligence/threat_intelligence.htm) describes its trending-CVE widget and data-source view, not an export/feed for this named catalog. |
| Twitter Trending CVE's | No public subscribable endpoint verified. A CVE Details candidate could not be checked because robots retrieval was denied/unavailable. No X account/API access was assumed; no third-party ranking was silently substituted. |
| Weaponized Vulnerability Catalog | No independent public endpoint verified. Qualys documentation describes weaponized-exploit views, while its [exploit-source announcement](https://notifications.qualys.com/product/2023/05/12/new-exploit-sources-added-to-vulnerability-management) explains aggregation into its products. Neither establishes a public feed for this exact label. |
| White Phosphorus | Not enabled. The checked [legacy product URL](https://www.immunityinc.com/products/white-phosphorus/) returned 404; no usable current feed was verified. |
| d2ExploitPack | Not enabled. [d2sec.com](https://www.d2sec.com/) returned a tiny JavaScript redirect to `/lander`, without a usable publisher feed. This is not evidence of a working catalog. |
| d2elliot | Not enabled. The checked [Elliot page](https://www.d2sec.com/elliot.html) returned the same landing-page redirect; no usable feed was verified. |

The four generic catalog names are consistent with categories shown by Qualys,
but the exact source identities remain unconfirmed. Search results were treated
as discovery leads; enabled endpoints were fetched and parsed directly. Some
search providers disallowed collection or returned a challenge; these were not
bypassed. A failed lookup does not prove that a source has ceased operation.

## Validation and operation

- Full offline suite: **139 tests passed**. Ruff lint and formatting checks pass.
- Synthetic daily and weekly previews generated under
  `output/preview/threat-sources-fixtures/` before live ingestion.
- Live ingestion of the ten added feeds used an in-memory database: **10/10
  fetches succeeded, 106 retained articles**, followed by **zero new articles**
  on repeat ingestion. No classification or delivery was run.
- EPSS returned a valid probability for a sample CVE with a score date of
  **2026-10-18**. No new secret is needed for the enabled sources.
- Compact endpoint observations and the ingestion results are recorded in
  [the verification artifact](docs/threat-source-verification-2026-10-18.json).

The next digest run using this configuration will collect the added feeds and
use EPSS enrichment. Scheduled execution was disabled at the time of this
review; see the README for current scheduling settings. This review does not
refresh or resend the previous daily report.
Public feed availability and licensing/access arrangements can change.
