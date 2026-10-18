CISA subscriptions and SecDigest ingestion research
==================================================

Verified on **18 October 2026, Europe/Paris**, using public HTTP requests, CISA's official GitHub repositories and SecDigest's existing HTTP fetcher with its normal robots checks. No subscription was submitted, no email was sent, and production configuration was not changed. Endpoint availability was tested from this workstation; it was not separately tested from GitHub Actions during this research.

**Accepted implementation:** keep the official KEV JSON with CISA's GitHub mirror as a fallback, and ingest the IT, OT and VA ROLIE/CSAF feeds with advisory-ID deduplication. GovDelivery email subscriptions and mailbox ingestion are excluded at the user's request. Broader announcements may therefore be absent; live digests disclose this coverage gap. The observations below describe the research snapshot before implementation.

**How to subscribe by email**

These instructions are retained as research only; email subscriptions are outside the accepted implementation.

1. Open [CISA's official GovDelivery subscriber page](https://public.govdelivery.com/accounts/USDHSCISA/subscriber/new). It returned HTTP 200 and identifies the agency as the Cybersecurity and Infrastructure Security Agency. The general `content.govdelivery.com` homepage is not the subscription entry point.
2. Enter the email address that should receive notifications and follow the signup or subscriber-preferences flow.
3. Select **Known Exploited Vulnerabilities Catalog** and **Cybersecurity Advisories**. Also select the relevant **ICS/industrial-control-system advisory** topics if offered, particularly for energy and operational-technology coverage. Check the current labels in the preferences screen; that screen was not accessed because it requires submitting an email address.
4. Save the selections and complete any confirmation requested by the service. Use subscriber preferences to change topics later.

The current signup page states that CISA's emails come from **CISA@messages.cisa.gov**. Mail filtering can use that sender, while automated ingestion should also check the receiving mail provider's authentication results rather than trust the From header alone.

A [KEV-specific signup link with topic ID `USDHSCISA_138`](https://public.govdelivery.com/accounts/USDHSCISA/subscriber/new?topic_id=USDHSCISA_138) is linked from [Socket's contemporaneous account of CISA's distribution change](https://socket.dev/blog/cisa-kills-off-rss-feeds-for-kevs-and-cyber-alerts). It currently opens the CISA signup page successfully. The public page does not display the selected topic, so confirm the KEV selection after entering the preferences flow. The general agency signup link above is the safest starting point when topic identifiers or labels change.

**Why the old advisory feed is not a dependable subscription path**

CISA published [“Update on How CISA Shares Cyber-Related Alerts and Notifications,” dated 12 May 2025](https://www.cisa.gov/news-events/alerts/2025/05/12/update-how-cisa-shares-cyber-related-alerts-and-notifications). [Socket's report](https://socket.dev/blog/cisa-kills-off-rss-feeds-for-kevs-and-cyber-alerts) reproduces the announcement: routine cybersecurity updates and new-guidance announcements would move to email and social media, while the Alerts & Advisories webpage would focus on urgent emerging threats and major cyber activity. It specifically directs people who followed KEV updates through RSS to the KEV GovDelivery subscription.

The original CISA announcement returned HTTP 403 here, so the historical wording was checked through that clearly identified secondary source. The current signup page and machine-readable repositories were inspected directly.

SecDigest currently enables `https://www.cisa.gov/cybersecurity-advisories/all.xml` as an RSS source. A direct request returned **HTTP 403**, as did several CISA HTML pages. This establishes an access failure from this environment; it does not establish that the resource is permanently deleted or explain the server's access policy. Meanwhile, the KEV JSON endpoint returned HTTP 200. The existing “CISA Advisories” failure therefore does not mean KEV enrichment is unavailable.

The guessed GovDelivery account URLs ending in `bulletins.rss` and `bulletins.atom` both returned **HTTP 406**, with the explicit message “the request was for an unrecognized format.” The account's `/bulletins` path redirected toward a sign-in route rather than providing a public archive index. No supported, complete GovDelivery account RSS replacement was verified. Individual public bulletin links should not be treated as a discoverable feed.

**Verified sources for automatic collection**

| Source | Observed result | Appropriate use |
|---|---|---|
| [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | HTTP 200; 1,748 entries; catalog version `2026.10.16` | Primary source for catalog additions, changes and vulnerability enrichment |
| [Official KEV GitHub JSON mirror](https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json) | HTTP 200; parsed JSON exactly matched CISA's version and all records | Fallback for the same dataset, not a second independent source |
| [CISA IT advisory feed](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json) | HTTP 200; 100 entries; newest listed advisory publication 5 October 2026 | Structured information-technology advisories |
| [CISA OT advisory feed](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json) | HTTP 200; 3,966 entries; newest listed publication 15 October 2026 | Industrial-control and medical-device advisories |
| [CISA VA advisory feed](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/VA/white/cisa-csaf-va-feed-tlp-white.json) | HTTP 200; 4 entries; newest listed publication 24 September 2026 | Additional vulnerability advisories; overlaps with IT |
| [KEV repository commit Atom feed](https://github.com/cisagov/kev-data/commits/develop.atom) | HTTP 200; valid Atom; 20 recent entries | Feed-reader notification that the repository changed |

All six sources in this table were also successfully fetched with SecDigest's own `Fetcher`, an in-memory store and the existing robots-policy checks. No public-data API key was required. The OT feed was approximately 4.4 MB, within the application's current 20 MB response limit.

Implementation validation subsequently collected 267 distinct advisories within the 120-day retention window, merged the three IT/VA overlaps, and produced zero additional articles on a repeated ingestion. One IT index entry, `VA-26-274-03` (Joyland AI), points to a missing document in the official repository; the reader reports this as a source failure and retries it without discarding the successfully collected advisories. KEV primary and mirror data matched across all 1,748 records.

CISA's [KEV repository documentation](https://github.com/cisagov/kev-data/blob/develop/README.md) explicitly describes the repository as a copy of the official catalog, supplies JSON/CSV/schema files, and says synchronization normally follows canonical updates within minutes. That is the publisher's expectation, not a guaranteed delivery deadline. The two datasets were identical at verification. The public [KEV change dashboard](https://cisagov.github.io/kev-data/) is also linked from the repository documentation; the dashboard itself was not exercised in this research.

The commit Atom feed is a usable subscription for a feed reader, but it describes commits, not individual vulnerabilities. It can include maintenance commits and should not create one security-news item per commit. For SecDigest, compare the actual KEV records keyed by `cveID`, including changes to existing records as well as new additions. `dateAdded` alone will not identify every subsequent correction.

**What the structured advisory feeds provide**

CISA's [CSAF repository documentation](https://github.com/cisagov/CSAF/blob/develop/README.md) describes machine-readable IT and OT security advisories using CSAF 2.0. The feeds above are **ROLIE JSON indexes pointing to CSAF JSON documents**. They are not RSS/XML: SecDigest's current RSS parser returned an empty feed version for each, meaning that changing only the configured URL would fail.

The indexes provide advisory identifiers, titles, publication/update timestamps and direct `content.src` URLs. Two downloaded documents were inspected:

- [VA-26-278-01, Canimaan Software ClamXAV local privilege escalation](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/va-26-278-01.json): CISA publisher, revision history, one vulnerability, affected-product information and remediation fields.
- [ICSMA-26-288-02, J4Care dcm4che](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsma-26-288-02.json): CISA publisher, revision history, six vulnerabilities, remediation information and a human-readable CISA advisory reference.

The repository also supplies small change lists, including [IT `changes.csv`](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/changes.csv) and [OT `changes.csv`](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/changes.csv), both successfully downloaded. These can support incremental collection without repeatedly fetching every historic advisory.

Three advisory IDs occur in both the current IT and VA indexes: `VA-26-225-01`, `VA-26-251-01` and `VA-26-267-01`. They must be consolidated by advisory ID before article classification. This is particularly relevant to SecDigest's recent duplicate-story fix.

The repository notes that it also republishes vendor advisories and preserves their original dates/revision histories. Preserve publisher and timestamp provenance during ingestion; do not substitute the download time for the original publication date. Availability of these files does not establish that they contain every CISA email, urgent alert, campaign notice or new-guidance announcement. Their observed publication dates also differ across channels. GovDelivery remains useful for broader notification coverage.

**Concrete changes recommended for SecDigest**

1. Keep KEV as a distinct enrichment channel. Add the official GitHub JSON mirror as a fallback, validate the expected schema and catalog version, retain the last valid snapshot on failure, and report which source and version were used. Make refresh timing configurable rather than relying only on the current hard-coded 24-hour cache interval.
2. Add a `csaf`/ROLIE source adapter alongside the RSS adapter. Poll IT, OT and VA indexes or change lists, fetch only new or revised documents, and extract source-backed summaries, CVEs, products, remediation and original links into the existing classification pipeline. This can use public endpoints without adding an API secret.
3. Track advisory ID, version and current release timestamp. The current article store inserts by URL and ignores an existing URL; merely passing revised documents through that path would miss updates. Refresh or explicitly version the stored source when an advisory changes, and reconsider its cached classification.
4. Deduplicate shared advisory IDs across IT/VA and group mirrored CISA channels under one source-independence identity. Keep the existing report-time incident deduplication for different articles describing the same incident. Do not increase independent-source importance solely because one advisory appears in several CISA feeds.
5. After the replacement is validated, retire the failing legacy RSS configuration with a clear recorded reason. Track the health of KEV, IT, OT and VA separately, and distinguish “no new advisory” from “could not fetch the source.” Preserve a visible coverage limitation for CISA announcements that are not supplied in the structured feeds.
6. If the digest must include the broader GovDelivery announcements, subscribe a dedicated mailbox and add authenticated inbound-mail ingestion. The current SMTP configuration sends mail; it does not retrieve subscriptions. A mailbox API or IMAP integration would be additional implementation work. Retain message IDs and public bulletin links, avoid publishing subscriber-management tokens, and route those messages through the same duplicate checks.

For an initial rollout, use a preview workflow to verify source health, advisory revisions, duplicate handling and provenance before sending the revised digest. These are recommendations and inspected integration points, not changes already deployed.

Raw public-page responses, downloaded sample documents and endpoint-check results are retained locally under the ignored directory `output/preview/cisa-research/`. The checks used no OpenAI calls and did not modify the live database, subscription preferences or GitHub secrets.
