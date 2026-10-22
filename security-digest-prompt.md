# Prompt for Claude Code — Security News Digest (Daily + Weekly), v2

> Paste everything below the line into Claude Code, run from an empty project folder.

---

## Role and goal

You are building a production-quality Python tool called **`secdigest`** for an independent Enterprise Security Architect who consults for mid-sized and large organisations. His public profile is at https://brusiantsou.com. The tool collects cybersecurity news from RSS/Atom feeds and advisory sources, deduplicates it, classifies every story with the Claude API, and produces two outputs:

1. **Daily digest**: the last 24 hours, built for triage.
2. **Weekly digest**: the last 7 days, built for trends, an executive summary, client conversations and content ideas.

Every news item must be tagged with:
- **Importance**: `low` | `medium` | `high` | `critical`
- **Location relevance (%)**: separate 0–100 scores for **US**, **Europe** and **MEA** (Middle East and Africa), plus **Other** (India, CIS, APAC)
- **Industry relevance (%)**: one 0–100 score for each of the 10 target industries
- **Practice-area relevance (%)**: one 0–100 score for each of the 11 practice areas
- **Related case study**: up to 2 of the consultant's published case studies that the story relates to, if any

Start in **plan mode**. Propose the architecture and file layout, wait for my approval, then build phase by phase. Run the tests after each phase.

### Configuration is the single source of truth
All taxonomies (regions, industries, practice areas, watch technologies, regulations, case studies) live in YAML under `config/`. The classification system prompt and the JSON schema are **generated at runtime from these files**. No taxonomy key is hard-coded in Python, so adding an industry or a case study is a config change only.

---

## Tech stack (defaults, adjust if there is good reason)

- Python 3.12, `uv` for dependency management
- `feedparser` and `httpx` (async) for ingestion
- SQLite through `sqlite3` or SQLModel for storage, with idempotent re-runs
- `anthropic` SDK for classification and synthesis, `pydantic` v2 for schemas
- `jinja2` for Markdown and HTML templates
- `rapidfuzz` for title similarity in deduplication
- `pytest` for tests, `ruff` for linting
- Email is sent with the standard library (`smtplib`, `email.mime`, `ssl`); no third-party mail service.
- Secrets come only from environment variables (`ANTHROPIC_API_KEY`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `EMAIL_TO`) and never appear in code, logs or the repository.

### Model usage
- **Per-item classification**: `claude-haiku-5-5` by default (high volume, low cost). Configurable.
- **Weekly synthesis** (executive summary, trend narrative, content ideas): `claude-sonnet-5-5`. Configurable.
- Use **tool use with a strict JSON schema** for classification output. Validate it with pydantic and retry once on a validation failure.
- Put the generated rubric and taxonomies in the system prompt and use **prompt caching** on it.
- Classify items in small batches (5–10 per call) to reduce cost. Add an optional `--batch-api` mode that uses the Message Batches API for the weekly backfill.
- Log tokens used and estimated cost for each run.

---

## Sources (`config/feeds.yaml`)

On first run, validate every URL. Log failures, mark failed feeds `enabled: false`, and keep going. Some URLs below may have changed, so verify them rather than trusting them. For each `TODO_VERIFY` entry, try to discover the feed URL from the site's `<link rel="alternate">` tag and report what you found. If a source has no feed, mark it `type: page_watch` and leave it disabled; do not build scrapers without my approval.

```yaml
feeds:
  # Breaking news
  - {name: The Hacker News,       url: https://feeds.feedburner.com/TheHackersNews,        tier: news}
  - {name: BleepingComputer,      url: https://www.bleepingcomputer.com/feed/,              tier: news}
  - {name: The Register Security, url: https://www.theregister.com/security/headlines.atom, tier: news}
  - {name: Help Net Security,     url: https://www.helpnetsecurity.com/feed/,               tier: news}
  # Enterprise / analysis
  - {name: SecurityWeek,          url: https://www.securityweek.com/feed/,                  tier: news}
  - {name: Dark Reading,          url: https://www.darkreading.com/rss.xml,                 tier: news}
  - {name: Infosecurity Magazine, url: https://www.infosecurity-magazine.com/rss/news/,     tier: news}
  - {name: Cybersecurity Dive,    url: https://www.cybersecuritydive.com/feeds/news/,       tier: news}
  - {name: SC Media,              url: TODO_VERIFY,                                         tier: news}
  - {name: CSO Online,            url: TODO_VERIFY,                                         tier: news}
  # Policy / investigations
  - {name: KrebsOnSecurity,       url: https://krebsonsecurity.com/feed/,                   tier: investigation}
  - {name: The Record,            url: https://therecord.media/feed,                        tier: investigation}
  - {name: CyberScoop,            url: https://cyberscoop.com/feed/,                        tier: policy}
  - {name: Schneier on Security,  url: https://www.schneier.com/feed/atom/,                 tier: analysis}
  # Aggregators
  - {name: Security Boulevard (Security Bloggers Network), url: TODO_VERIFY,                tier: aggregator}
  - {name: Packet Storm News,     url: https://packetstorm.news/rss/news,                   tier: aggregator}
  # Vendor research
  - {name: Microsoft Security Blog, url: https://www.microsoft.com/en-us/security/blog/feed/, tier: vendor}
  - {name: WeLiveSecurity (ESET), url: TODO_VERIFY,                                         tier: vendor}
  - {name: Unit 42,               url: TODO_VERIFY,                                         tier: vendor}
  - {name: Cisco Talos,           url: TODO_VERIFY,                                         tier: vendor}
  - {name: Sophos X-Ops,          url: TODO_VERIFY,                                         tier: vendor}
  # Cloud and identity
  - {name: Wiz Research,          url: TODO_VERIFY,                                         tier: vendor}
  - {name: Okta Security Advisories, url: TODO_VERIFY,                                      tier: advisory}
  # Email and phishing
  - {name: Proofpoint Threat Insight, url: TODO_VERIFY,                                     tier: vendor}
  - {name: Abnormal Threat Research,  url: TODO_VERIFY,                                     tier: vendor}
  - {name: Cofense Intelligence,      url: TODO_VERIFY,                                     tier: vendor}
  # OT / ICS
  - {name: CISA ICS Advisories,   url: TODO_VERIFY,                                         tier: advisory}
  - {name: Dragos Blog,           url: TODO_VERIFY,                                         tier: vendor}
  - {name: Claroty Team82,        url: TODO_VERIFY,                                         tier: vendor}
  - {name: Nozomi Networks Labs,  url: TODO_VERIFY,                                         tier: vendor}
  - {name: SANS ICS Blog,         url: TODO_VERIFY,                                         tier: vendor}
  # AI and MCP security
  - {name: OWASP GenAI Security Project, url: TODO_VERIFY,                                  tier: research}
  - {name: Embrace The Red,       url: TODO_VERIFY,                                         tier: research}
  - {name: Simon Willison (prompt injection), url: TODO_VERIFY,                             tier: research}
  # Supply chain and CI/CD
  - {name: Socket.dev Blog,       url: TODO_VERIFY,                                         tier: vendor}
  - {name: StepSecurity Blog,     url: TODO_VERIFY,                                         tier: vendor}
  # Advisories
  - {name: SANS ISC,              url: https://isc.sans.edu/rssfeed.xml,                    tier: advisory}
  - {name: CISA Advisories,       url: https://www.cisa.gov/cybersecurity-advisories/all.xml, tier: advisory}
  - {name: MSRC Update Guide,     url: https://api.msrc.microsoft.com/update-guide/rss,     tier: advisory}
  # Regional: Europe
  - {name: NCSC-NL,               url: TODO_VERIFY,                                         tier: regional, region: Europe}
  - {name: NCSC-UK,               url: TODO_VERIFY,                                         tier: regional, region: Europe}
  - {name: ENISA,                 url: TODO_VERIFY,                                         tier: regional, region: Europe}
  - {name: Security.NL,           url: TODO_VERIFY,                                         tier: regional, region: Europe}
  - {name: NCSC Ireland,         url: TODO_VERIFY,                                         tier: regional, region: Europe}
  - {name: Central Bank of Ireland, url: TODO_VERIFY,                                     tier: regulator, region: Europe}
  - {name: NCSC.ch / BACS,        url: TODO_VERIFY,                                         tier: regional, region: Europe}
  - {name: FINMA News,            url: TODO_VERIFY,                                         tier: regulator, region: Europe}
  # Regional: Middle East
  - {name: UAE Cyber Security Council, url: TODO_VERIFY,                                    tier: regional, region: MEA}
  - {name: Saudi NCA,             url: TODO_VERIFY,                                         tier: regional, region: MEA}
  - {name: Gulf Business (tech/security), url: TODO_VERIFY,                                 tier: regional, region: MEA}
  - {name: ITP.net (security),    url: TODO_VERIFY,                                         tier: regional, region: MEA}

enrichment:
  cisa_kev_json: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  epss_api: https://api.first.org/data/v1/epss                 # optional
  nvd_api:  https://services.nvd.nist.gov/rest/json/cves/2.0   # optional, respect rate limits
  github_advisories_api: https://api.github.com/advisories     # optional, supply-chain items
  mitre_attack_stix: https://github.com/mitre-attack/attack-stix-data  # for validating technique IDs
```

---

## Taxonomies (generate these config files)

### `config/regions.yaml`

| Key | Covers |
|---|---|
| `US` | United States |
| `Europe` | EU, EEA, UK, Switzerland |
| `MEA` | Middle East and Africa: GCC (UAE, KSA, Kuwait, Oman, Qatar, Bahrain), Iraq, rest of the Middle East, Algeria, rest of Africa |
| `Other` | India, CIS, APAC, LATAM |

Priority countries, each giving a `+10` bonus (capped at 100) to its region score when directly involved: **NL, IE, CH, UK, UAE, SA, US**. The list is configurable.

### `config/industries.yaml`

| Key | Industry | Signals |
|---|---|---|
| `energy_services` | Energy services | utilities, oil & gas, oilfield and offshore services, power grid, renewables, OT/ICS/SCADA, pipelines, NERC CIP |
| `telecommunications` | Telecommunications | carriers, ISPs, cable operators, 5G core, SS7/Diameter, SIM swap, lawful-intercept systems, Salt Typhoon-style campaigns, routers and CPE |
| `private_banking` | Private banking | wealth management, HNWI targeting, Swiss and Luxembourg banks, family offices, BEC/wire fraud against clients, FINMA |
| `investment_management` | Investment management | asset managers, hedge funds, brokers, trading platforms, SEC/FCA rules, market-data providers, file-transfer platform breaches |
| `government` | Government | federal, national, state and municipal bodies, defense, elections, public services, CISA/ENISA/NCSC directives |
| `retail_banking` | Retail banking | consumer banks, payments, cards, banking trojans, mobile banking malware, account takeover, DORA, PSD2/PSD3, SWIFT, SAMA, Central Bank of Ireland |
| `global_it_services` | Global IT services | MSPs, outsourcers, consultancies, system integrators, RMM tools, IT supply chain, cloud providers, managed SOCs |
| `logistics` | Logistics | shipping, ports, freight forwarding, cargo operations, warehousing, fleet telematics |
| `industrial_manufacturing` | Industrial manufacturing | factories, PLCs, MES, ICS vendors (Siemens, Rockwell, Schneider), industrial IP theft |
| `automotive` | Automotive | OEMs, tier-1 suppliers, dealer-management systems, connected vehicles, EV charging, UNECE R155/R156 |

### `config/practice_areas.yaml`

| Key | Practice area | Signals |
|---|---|---|
| `zero_trust_cloud` | Zero Trust and cloud security | Azure/AWS/GCP misconfigurations, landing zones, conditional access, ZTNA, SASE, cloud migration risk |
| `vuln_exposure_mgmt` | Vulnerability and exposure management | CVEs, KEV, EPSS, patch cadence, attack-surface management, scanner vendors (Qualys, Tenable, Wiz) |
| `devsecops` | Secure software delivery and DevSecOps | CI/CD compromise, GitHub Actions, package supply chain, SAST/DAST/SCA, SBOM, NIST SSDF, code-signing |
| `siem_detection` | SIEM, monitoring and detection engineering | new TTPs, detection rules, log sources, Sentinel/Splunk/QRadar/Wazuh/Elastic, SOC operations |
| `iam_pam` | Identity and privileged access | Entra ID, Okta, MFA bypass, token theft, OAuth abuse, CyberArk, BeyondTrust, service accounts |
| `email_phishing` | Email protection and phishing response | phishing kits, BEC, QR phishing, DMARC/SPF/DKIM, Proofpoint, Abnormal, Cofense |
| `data_protection_dlp` | Data protection and DLP | data breaches, exfiltration, Purview, classification, GDPR/FADP incidents, insider risk |
| `ot_ics` | OT and industrial control systems | ICS advisories, PLC/HMI vulnerabilities, removable-media threats, OT ransomware, IEC 62443 |
| `grc_audit` | Audit readiness, governance and risk | regulations, enforcement actions, ISO 27001, PCI DSS, NIST CSF, SOC 2, audit findings, board reporting |
| `security_automation` | Security automation and reporting | SOAR, security dashboards, automation tooling, metrics, API-driven security operations |
| `ai_governance` | AI-assisted work and AI governance | LLM/agent vulnerabilities, prompt injection, MCP security, model supply chain, EU AI Act, AI policy |

### `config/watch_tech.yaml`

Technologies the consultant's clients run. A CISA KEV entry or confirmed in-the-wild exploitation for any of these makes an item `critical` (see overrides).

```yaml
watch_tech:
  microsoft: [Defender for Endpoint, Defender for Office 365, Defender for Identity, Defender for Cloud, Sentinel, Entra ID, Azure, Microsoft 365, Exchange, SharePoint, Windows Server, Intune, Purview]
  endpoint_network: [CrowdStrike Falcon, SentinelOne, Zscaler, Cloudflare, Palo Alto PAN-OS, GlobalProtect, Fortinet FortiOS, FortiGate, Cisco ASA, Cisco IOS XE, Citrix NetScaler, Ivanti Connect Secure]
  identity: [Okta, Cisco Duo, CyberArk, BeyondTrust]
  vulnerability: [Qualys, Tenable, Wiz, OpenVAS]
  siem: [Splunk, IBM QRadar, Wazuh, Elastic]
  email: [Proofpoint, Abnormal Security, Cofense]
  devops_appsec: [GitHub, GitHub Actions, GitLab, Jenkins, SonarQube, Checkmarx, Burp Suite, OWASP ZAP]
  infrastructure: [Kubernetes, Docker, VMware ESXi, VMware vCenter, Terraform, AWS, Google Cloud]
  ai: [Claude API, Claude Code, OpenAI API, Model Context Protocol (MCP), AI agent frameworks]
  enterprise_apps: [SAP, Oracle, Atlassian Confluence, Atlassian Jira, MuleSoft]
```

### `config/regulations.yaml`

Each entry has `key`, `name`, `jurisdiction`, `region`, `industries` (or `all`), and an optional list of `milestones` with dates that I can fill in. Seed it with:

| Region | Regulations |
|---|---|
| Global / standards | ISO 27001, PCI DSS, NIST CSF 2.0, NIST SSDF, SOC 2, IEC 62443 |
| EU | NIS2, DORA, GDPR, EU AI Act, Cyber Resilience Act (CRA) |
| UK | UK GDPR, UK Cyber Security and Resilience Bill, FCA operational resilience |
| Switzerland | FINMA circulars (operational risks and resilience), revised FADP, NCSC/BACS cyberattack reporting obligation |
| Netherlands | Cyberbeveiligingswet (NIS2 implementation), DNB requirements |
| UAE | UAE Information Assurance Standard, Cyber Security Council directives, CBUAE requirements |
| KSA | NCA Essential Cybersecurity Controls (ECC), NCA OT controls, SAMA Cyber Security Framework |
| Ireland | NIS2 transposition (National Cyber Security Bill), Central Bank of Ireland cross-industry guidance on operational resilience and outsourcing, DORA supervision by the Central Bank |
| US | SEC cyber disclosure rules, CIRCIA, NYDFS Part 500, CMMC, state privacy laws |
| Sector | UNECE R155/R156 (automotive), NERC CIP (energy), TSA pipeline directives |

Do not invent milestone dates. Leave `milestones: []` and mark entries `needs_dates: true`; the weekly digest lists those so I can fill them in.

### `config/case_studies.yaml`

The consultant's published, anonymised case studies. Links are `https://brusiantsou.com/stories/<slug>/`.

| Slug | Sector | Region | Main practice areas |
|---|---|---|---|
| `security-at-telecom-scale` | Telecommunications | NL | vuln_exposure_mgmt, siem_detection, security_automation |
| `secure-azure-migration` | Private banking | CH | zero_trust_cloud, data_protection_dlp, grc_audit |
| `zero-trust-at-enterprise-scale` | Energy services | UAE | zero_trust_cloud, iam_pam |
| `continuous-vulnerability-management` | Energy services | UAE | vuln_exposure_mgmt, security_automation |
| `security-in-the-delivery-path` | Government | UAE | devsecops |
| `vendor-release-automation` | Retail banking | IE | vuln_exposure_mgmt, security_automation, devsecops |
| `audit-ready-by-design` | Global IT services | US | grc_audit |
| `security-foundations-for-logistics` | Logistics | UAE | grc_audit, zero_trust_cloud |
| `security-visibility-for-manufacturing` | Industrial manufacturing | CIS | siem_detection, ot_ics |
| `security-services-for-investment-management` | Investment management | US | grc_audit, security_automation |
| `secure-development-for-automotive` | Automotive | US | devsecops |
| `securing-offshore-operations` | Energy services | Multi-country | ot_ics, data_protection_dlp |

Also add `config/writing.yaml` with the published articles (links are `https://brusiantsou.com/writing/<slug>/`): `from-log-feeds-to-detections` (siem_detection), `discovery-before-the-roadmap` (grc_audit, vuln_exposure_mgmt), `privacy-and-security-in-private-banking` (private_banking, data_protection_dlp). The weekly content-ideas section may link to these.

---

## Pipeline

1. **Ingest**: fetch all enabled feeds concurrently with timeouts, ETag/Last-Modified caching and a polite User-Agent. Store title, link, published time (UTC), source, and the feed-provided summary. Do not scrape full article text by default. An optional `--fetch-fulltext` flag may use `trafilatura`, but only for internal classification. Full text is never republished.
2. **Normalize**: canonicalize URLs (strip utm_* parameters and fragments) and extract CVE IDs and MITRE ATT&CK technique IDs (`T\d{4}(\.\d{3})?`) with regexes.
3. **Deduplicate and cluster**: merge the same story across sources using URL match, title similarity (≥ 85, configurable) and shared CVE IDs. A cluster becomes one digest item with a list of all its sources. Classify the cluster once.
4. **Enrich**: match CVEs against CISA KEV (flag `kev: true` with the date added). Optionally add EPSS and CVSS. Match `affected_technologies` against `watch_tech` (case-insensitive, with an alias list per product).
5. **Classify** with Claude, using the generated rubric and schema below.
6. **Apply deterministic overrides** (see the importance rubric).
7. **Validate model claims**: drop any ATT&CK technique ID that is not in the MITRE STIX data; drop any detection-rule link or case-study slug that was not in the source text or the config.
8. **Compute the priority score** used for sorting.
9. **Render** the daily or weekly digest, then optionally deliver it.

---

## Classification schema (tool input schema)

Generate this from the config files at runtime. The shape is:

```json
{
  "cluster_id": "string",
  "headline": "string, max 120 chars, neutral rewrite",
  "summary": "string, 2-3 sentences in your own words, no verbatim copying from sources",
  "category": "vulnerability | exploitation_in_the_wild | data_breach | ransomware | apt_nation_state | supply_chain | fraud_phishing | regulation_policy | law_enforcement | research | vendor_product | other",
  "importance": "low | medium | high | critical",
  "importance_rationale": "string, 1 sentence",

  "location_relevance": { "US": 0, "Europe": 0, "MEA": 0, "Other": 0 },
  "countries_mentioned": ["ISO-3166 alpha-2"],
  "industry_relevance":       { "<each key from industries.yaml>": 0 },
  "practice_area_relevance":  { "<each key from practice_areas.yaml>": 0 },

  "affected_technologies": ["vendor/product, e.g. 'Microsoft Exchange', 'Fortinet FortiOS'"],
  "cves": ["CVE-YYYY-NNNNN"],
  "threat_actors": ["names as reported, e.g. 'Salt Typhoon', 'Scattered Spider'"],

  "regulations": [{ "key": "<key from regulations.yaml>", "nature": "new | amended | enforcement | guidance | deadline", "effective_or_deadline_date": "YYYY-MM-DD or null if not stated in the source" }],

  "attack_techniques": ["T1566.001"],
  "detection_refs": [{ "type": "sigma | kql | spl | yara | snort | other", "url": "only if the source links it" }],
  "detection_coverage_note": "string, 1 sentence: how a Sentinel/Splunk/Wazuh SOC could detect this, or empty. Phrase as an assessment, not a fact.",

  "related_case_studies": ["0-2 slugs from case_studies.yaml, only when the sector, region or practice area genuinely overlaps"],
  "business_signal": { "present": false, "type": "regulatory_deadline | sector_campaign | major_incident_wave | technology_shift", "sector": "industry key", "region": "region key", "rationale": "1 sentence" },

  "recommended_action": "string, 1 sentence, or empty if none",
  "confidence": 0.0
}
```

Rules for the model, included in the system prompt:
- `industry_relevance` and `practice_area_relevance` must contain exactly the keys from config.
- Never invent detection-rule URLs, regulation dates or case-study slugs. Empty is better than guessed.
- `business_signal` is **sector-level only**: it describes demand across a sector and region (e.g. "NIS2 transposition deadline hits Dutch telecoms"). It must never name an individual breached or attacked organisation as a sales target.

---

## Scoring rubric (goes in the cached system prompt)

### Importance

| Level | Criteria (any one is sufficient) |
|---|---|
| **critical** | Active in-the-wild exploitation of a `watch_tech` product or other widely deployed enterprise technology; new CISA KEV entry for such technology; systemic supply-chain compromise (major vendor, MSP/RMM tool, popular package or CI action); major breach or outage at an organization in a target industry in the US, Europe or MEA; nation-state campaign against critical infrastructure in a target region |
| **high** | Critical or high CVE (CVSS ≥ 8.0) with a public PoC or vendor emergency patch; significant breach (millions of records or a regulated entity); new ransomware or phishing campaign hitting target industries; binding regulation with near-term effect in a target region; major law-enforcement takedown; new OT/ICS advisory for equipment common in energy or manufacturing |
| **medium** | Notable vulnerability without exploitation; breach at a mid-size or non-target-industry organization; threat research with new TTPs; proposed regulation or regulator guidance; notable vendor or security product change |
| **low** | Opinion pieces, product marketing, funding or M&A news, minor incidents outside the target scope, recap articles |

**Deterministic overrides, applied after the model call:**
- A CVE in the item that is in CISA KEV and was added in the last 7 days sets the floor at `high`. It becomes `critical` when a source-supported deployment profile establishes widespread enterprise exposure, including watch technologies and common runtimes.
- Source-reported exploitation of a `watch_tech` product or configured widespread enterprise technology sets the floor at `critical`. Predictions, negated claims and lab demonstrations do not establish active exploitation.
- Source-supported systemic software supply-chain compromise sets the floor at `critical`.
- EPSS ≥ 0.5 sets a floor of `high`; probability alone does not establish a critical incident. Older KEV entries also retain a high floor.
- Record independent sources within 24 hours as corroboration; source volume does not change severity.
- Critical vulnerability assessments without reported exploitation, recent KEV evidence or a systemic compromise are capped at `high`.
- Log every override with its reason.

### Location relevance (%), scored separately for each region

| Score | Meaning |
|---|---|
| 90–100 | Direct regional involvement, or pervasive deployment applicability such as a PHP or Node.js security issue |
| 60–89 | Strong applicability: globally distributed enterprise/specialist technology, or a campaign targeting the region |
| 30–59 | Applicable general lesson, with limited evidence of direct exposure |
| 1–29 | Mostly elsewhere, with only indirect relevance |
| 0 | No connection |

Percentages are independent applicability assessments, not attack probabilities or victim shares. Globally deployed software issues use the same configured relevance in all regions; a publisher, vendor headquarters or advisory issuer does not determine impact geography. Apply the priority-country bonus at most once per region for nonglobal events. Source-supported deployment profiles and cross-industry floors live in `scoring.yaml`.

### Industry and practice-area relevance (%)

Same anchors for both: 90–100 means the story directly involves that sector or discipline; 60–89 means a sector-specific threat, technology or regulation, or a story that changes how that practice is done; 30–59 means common enterprise technology or a generic issue that clearly applies; 1–29 means indirect; 0 means none.

Cross-industry rule: a vulnerability in technology used everywhere (e.g. Windows, Exchange, VPN appliances) gives every industry at least 40%. Industries known to be heavily exposed to that technology get a higher score.

### Priority score (for sorting)

```
importance_points = {critical: 100, high: 75, medium: 45, low: 15}
weighted = 0.60 * importance_points
         + 0.15 * max(location_relevance.*)
         + 0.10 * max(industry_relevance.*)
         + 0.15 * max(practice_area_relevance.*)
priority = clamp(weighted, severity_band)
severity_bands = {critical: [85, 100], high: [65, 84.99], medium: [35, 64.99], low: [0, 34.99]}
```
Keep weights, bands, deployment profiles and participating regions in `config/scoring.yaml`. All four regions, including `Other`, participate by default. Preserve the original classification and record weighted components, evidence URLs and adjustments in the report.

---

## Daily digest

- Window: the last 24 hours, ending at the run time. Timezone comes from config, default `Europe/Amsterdam`.
- Inclusion filter (configurable): `importance >= medium` OR `max(location) >= 60` OR `max(industry) >= 60` OR `max(practice_area) >= 60`. Everything else goes to the "Other" section with headlines only (in the attachment; the email body shows only its count).

The structure below is the full report. The email body carries the subset described under **Outputs and delivery**.

**Structure:**
1. **Header**: date, item counts by importance, number of new KEV entries, number of `watch_tech` hits.
2. **🔴 Critical / 🟠 High: act now.** For each item:
   - headline and 2–3 sentence summary
   - tag line: `Importance · US 85% · EU 70% · MEA 40% · Retail banking 90% · Vuln mgmt 95%`
   - why it matters and recommended action
   - CVEs with KEV/EPSS/CVSS badges; ATT&CK technique IDs linked to attack.mitre.org
   - detection references and the detection-coverage note, labelled as an assessment
   - **Relevant to your work**: linked case-study titles, if any
   - all source links
3. **Full table** sorted by priority: `Importance | Headline | US% | EU% | MEA% | Top 2 industries (%) | Top 2 practice areas (%) | CVEs | KEV | Case study | Sources`
4. **Vulnerability watch**: new KEV additions, plus all `watch_tech` hits grouped by vendor.
5. **Regulation and policy**: items with a `regulations` entry, grouped by region (US, Europe, MEA).
6. **Other**: low-priority headlines only.

## Weekly digest

- Window: the last 7 days (Monday 00:00 to Sunday 23:59, configurable). The weekly digest reuses stored classifications and does not reclassify.

**Structure:**
1. **Executive summary**: 5 bullets, written by Sonnet from the week's top 25 clusters.
2. **Top 10 stories of the week**, by priority.
3. **Industry heatmap**: 10 industries × 4 importance levels, count plus average relevance.
4. **Practice-area heatmap**: 11 practice areas × 4 importance levels, count plus average relevance.
5. **Regional split**: top items for US, Europe and MEA, each broken down by country; priority countries listed first.
6. **Trends**: most-exploited technologies (highlighting `watch_tech`), active threat actors, top ATT&CK techniques, attack categories, and week-over-week deltas against the previous week's stored data.
7. **CVE table**: all CVEs mentioned, with CVSS/EPSS/KEV, `watch_tech` match, and the count of mentioning sources.
8. **Regulatory calendar**: every regulation touched this week with nature and dates as reported, plus the next 90 days of known milestones from `regulations.yaml`, plus a list of entries still marked `needs_dates`.
9. **Detection engineering corner**: the week's techniques with published detection rules, and high or critical items that had no detection reference (possible coverage gaps).
10. **Case-study relevance**: for each case study matched this week, the stories that relate to it. Useful for client conversations.
11. **Business signals** (only when `business_signals.enabled: true` in config, default `false`): sector-level signals grouped by industry and region, each with its rationale. Never list individual victim organisations here.
12. **Content ideas**: 2–3 outlines for a LinkedIn post or an article, written by Sonnet. Each outline has a working title, the angle, 3–4 bullet points, which of the week's stories it builds on, and which case study or published article it can link to. Outlines only, not finished posts; plain, practitioner tone, no hype.
13. **Watchlist for next week**: unpatched exploited issues, announced patch dates, upcoming regulatory milestones.

---

## Outputs and delivery

**Email is the primary delivery channel.** Every daily and weekly run ends with an email. Files are written as well, as an archive and as attachments.

### Follow the pattern of my existing tracker
Model the delivery and scheduling on my repository https://github.com/Banzaaaaai/flex-gateway-release-tracker (read `scraper.py` and `.github/workflows/tracker.yml` first). Keep its conventions:
- Gmail over SMTP with an app password: `smtplib.SMTP(host, port, timeout=30)` → `ehlo()` → `starttls()` → `login()` → send.
- The same environment variable and secret names: `SMTP_HOST` (`smtp.gmail.com`), `SMTP_PORT` (`587`), `SMTP_USER`, `SMTP_PASSWORD` (Gmail app password), `EMAIL_TO` (comma-separated, trimmed, empties dropped). Add `ANTHROPIC_API_KEY`.
- GitHub Actions with `workflow_dispatch` plus a `force_send` input, `contents: write`, Python 3.12 with pip caching, and a commit-back step by `github-actions[bot]` that commits only when files changed.
- A `run_log.json` (last 365 runs) and a Shields.io `badge.json`, both written in a `finally` block so every run is recorded.
- A failure alert email when a run crashes, sent from a wrapper that catches its own exceptions so the alert can never crash the run; the job then exits with code 1.
- Table-based HTML email with all CSS inline in `style` attributes, a centred 680 px container, and colour-coded badges.

### Improve on the tracker where it has known gaps
- **Add a plain-text part.** Build `multipart/mixed` → `multipart/alternative` (`text/plain` first, then `text/html`) → attachments. The tracker sends HTML only.
- **Escape all feed-derived text** with `html.escape` before it goes into the HTML, and allow only `http`/`https` links. The tracker inserts parsed content unescaped.
- Pass `ssl.create_default_context()` to `starttls()`.
- Retry sending 3 times with exponential backoff on transient SMTP errors; never retry on authentication errors.
- **Record every alert type in `run_log.json`** (`email_type: daily | weekly | failure | source_health`, `email_sent: true/false`) so silence windows work. The tracker's staleness silence window checks a flag that the staleness email never sets, so it likely re-alerts on every run; do not copy that.
- Set `From` to `SecDigest <SMTP_USER>`, plus `Date` and `Message-ID` headers, and a custom `X-SecDigest: daily|weekly` header so I can build a Gmail filter.

### Emails sent

| Email | When | Subject format |
|---|---|---|
| Daily digest | Every day at 07:00 Europe/Amsterdam | `[SecDigest] 🔴 2 critical · 🟠 5 high — Daily 2026-10-18` (counts omitted when zero; `Quiet day` when there is nothing above medium) |
| Weekly digest | Mondays at 08:00 Europe/Amsterdam | `[SecDigest] Weekly 2026-W42 — <top story headline, shortened>` |
| Failure alert | Any unhandled exception | `[SecDigest] ⚠️ Run failed — <stage>`; body has the stage, a trimmed traceback with no secrets or environment values, and the run duration |
| Source health | More than 30% of enabled feeds fail, or zero new items in 24 h | `[SecDigest] 🟡 Source health — <n> feeds failing`; at most once every 3 days (configurable silence window) |

`send_when_empty: true` (default) still sends a short daily email on quiet days, so silence always means something is broken.

### Email body versus attachments
Gmail clips messages larger than about 102 KB, so keep each HTML body **under 90 KB** and enforce it in code: if the body is too large, cut the lowest-priority rows and add a line saying how many were moved to the attachment.

| | Email body | Attachments |
|---|---|---|
| **Daily** | Header counts; all critical and high items in full; the top 20 rows of the priority table; vulnerability watch; regulation items; a one-line count of "Other" items | `secdigest-daily-YYYY-MM-DD.html` (full report), `secdigest-daily-YYYY-MM-DD.csv` (all items, all scores) |
| **Weekly** | Executive summary, top 10, both heatmaps, regulatory calendar, content ideas, watchlist | `secdigest-weekly-YYYY-Www.html` (all 13 sections), `.csv`, and `.md` |

Email HTML rules: table-based layout, inline CSS only, no `<style>` dependence, no JavaScript, no external images or fonts, system font stack, readable at 375 px width. Add `<meta name="color-scheme" content="light dark">` and choose colours that stay readable when Gmail or Outlook forces dark mode. Importance badges use text as well as colour (`CRITICAL`, `HIGH`), never colour alone. Heatmap cells show the number as well as the shade.

The attached full HTML report may use a `<style>` block, collapsible sections and proper dark mode, since it opens in a browser.

### Archive
Also write `output/daily/YYYY-MM-DD.{md,html,json,csv}` and `output/weekly/YYYY-Www.{md,html,json,csv}`. The CSV has one row per cluster with every score as its own column (all regions, industries and practice areas), plus importance, overrides applied, CVEs, KEV flag, `watch_tech` matches, ATT&CK IDs, regulation keys, case-study slugs and source URLs. Keep 90 days of daily output and all weekly output; prune older files.

### CLI
```
secdigest ingest
secdigest classify
secdigest daily  [--date YYYY-MM-DD] [--send | --no-send] [--preview]
secdigest weekly [--week YYYY-Www]  [--send | --no-send] [--preview]
secdigest run-daily  [--force-send]   # ingest + classify + daily + email
secdigest run-weekly [--force-send]   # weekly from stored data + email
secdigest email test                  # sends a short test email to EMAIL_TO
secdigest feeds check                 # validate all feed URLs
secdigest config check                # validate all taxonomy files and cross-references
secdigest --dry-run                   # no API calls, fixture classifications, no email
```
`--preview` writes the exact message as `output/preview/<name>.eml` without sending, so I can open it in a mail client before going live.

### Scheduling (GitHub Actions)
- `.github/workflows/daily.yml` and `.github/workflows/weekly.yml`, mirroring `tracker.yml` (checkout, Python 3.12 with pip cache, install, run, commit-back), each with `workflow_dispatch` inputs `force_send` and an optional `date` or `week`.
- **Daylight saving without a PAT**: instead of my tracker's separate cron-patching workflow, schedule two crons per job, one for summer and one for winter UTC offset (daily: `0 5 * * *` and `0 6 * * *`; weekly on Mondays: `0 6 * * 1` and `0 7 * * 1`). The first step checks the current hour in `Europe/Amsterdam` and exits successfully unless it is the target hour (07 daily, 08 weekly). A manual dispatch skips the check. Add jittered minutes if you prefer, as long as the guard still matches.
- Commit back `data/secdigest.sqlite` (pruned to 120 days), `output/`, `run_log.json` and `badge.json` when they change. If the database grows past 50 MB, switch it to `actions/cache` and tell me.
- Concurrency group per workflow so two runs never overlap.
- Also provide equivalent crontab lines for running on a server instead.

---

## Content and legal constraints

- Summaries must be written in the model's own words and kept to 3 sentences at most. Never reproduce article paragraphs. Always link to the original sources.
- Content ideas are outlines in the consultant's own framing; they must not copy source wording.
- Case studies are anonymised. Never add client names, and never suggest that a news item involves one of the consultant's clients.
- Respect robots.txt and rate limits. Cache aggressively.
- Do not send personal data anywhere other than `EMAIL_TO`. Never put secrets, environment values or full API responses in an email, log or commit.

---

## Testing and acceptance criteria

- Unit tests for URL canonicalization, CVE and ATT&CK extraction, clustering, every override rule, the priority-country bonus, the priority score, `watch_tech` matching with aliases, and schema validation, including an invalid model output that triggers a retry.
- A test that adding a new key to `industries.yaml` or `practice_areas.yaml` changes the generated schema without code changes.
- Validation tests: unknown ATT&CK IDs, invented case-study slugs and unlinked detection URLs are dropped.
- A test that `business_signal` output naming a specific organisation is rejected or stripped.
- Fixture feeds (10–15 sample items covering each importance level, each region, an OT advisory, a regulation item and an AI/MCP item) and golden-file tests for the rendered daily and weekly digests in `--dry-run` mode.
- Email tests, with SMTP mocked: the message is `multipart/mixed` containing `multipart/alternative` (plain text, then HTML) plus the attachments; subject formats for all four email types; `EMAIL_TO` parsing; feed text containing `<script>` or `<a href="javascript:…">` comes out escaped or dropped; the HTML body stays under 90 KB with 200 fixture items; a failing send triggers retries, and an authentication error does not.
- A test that a failure inside `send_failure_email` is logged and does not raise.
- A test that the source-health silence window suppresses a repeat alert within 3 days, using `run_log.json`.
- A test of the daylight-saving guard: it passes at 07:00 Amsterdam time in both January and July and exits early otherwise.
- `secdigest email test` delivers a real message through Gmail once secrets are set; do this before enabling the schedules.
- `secdigest run-daily` on live feeds finishes in under 5 minutes and logs counts, failures, tokens and cost.
- Re-running for the same day is idempotent: no duplicate clusters and no reclassification unless `--reclassify` is passed.
- `README.md` documents setup, every config file, how to tune the rubric and weights, how to add a case study, and the cost estimate per day and per week.

When you finish each phase, show me a sample rendered daily digest from fixtures before you connect to live feeds. Before enabling the schedules, generate `--preview` `.eml` files for a daily and a weekly digest so I can check how they look in Gmail on desktop and phone.
