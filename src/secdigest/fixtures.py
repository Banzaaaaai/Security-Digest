"""Synthetic demonstration data, never used for a live run."""

from datetime import UTC, datetime, timedelta

FIXTURE_NOW = datetime(2026, 10, 17, 8, tzinfo=UTC)

# References are configuration keys, not runtime taxonomy definitions.
STORIES = [
    (
        "Enterprise VPN exploitation requires urgent triage",
        "exploitation_in_the_wild",
        "high",
        "US",
        "US",
        "global_it_services",
        "vuln_exposure_mgmt",
        "Fortinet FortiOS",
        "CVE-2026-99001",
    ),
    (
        "Dutch carrier strengthens identity monitoring",
        "apt_nation_state",
        "critical",
        "Europe",
        "NL",
        "telecommunications",
        "siem_detection",
        "Cisco IOS XE",
        "",
    ),
    (
        "UAE energy operator reviews industrial gateway patch",
        "vulnerability",
        "high",
        "MEA",
        "AE",
        "energy_services",
        "ot_ics",
        "Industrial gateway",
        "CVE-2026-99002",
    ),
    (
        "Swiss private banks examine privileged access controls",
        "research",
        "medium",
        "Europe",
        "CH",
        "private_banking",
        "iam_pam",
        "Entra ID",
        "",
    ),
    (
        "Irish banks receive operational resilience guidance",
        "regulation_policy",
        "medium",
        "Europe",
        "IE",
        "retail_banking",
        "grc_audit",
        "",
        "",
    ),
    (
        "Research demonstrates prompt injection in MCP tools",
        "research",
        "medium",
        "Other",
        "IN",
        "global_it_services",
        "ai_governance",
        "Model Context Protocol (MCP)",
        "",
    ),
    (
        "Build pipeline package compromise affects suppliers",
        "supply_chain",
        "critical",
        "US",
        "US",
        "automotive",
        "devsecops",
        "GitHub Actions",
        "CVE-2026-99003",
    ),
    (
        "Investment managers review email fraud safeguards",
        "fraud_phishing",
        "high",
        "US",
        "US",
        "investment_management",
        "email_phishing",
        "Microsoft 365",
        "",
    ),
    (
        "Logistics teams test a data exposure response plan",
        "data_breach",
        "medium",
        "MEA",
        "AE",
        "logistics",
        "data_protection_dlp",
        "Azure",
        "",
    ),
    (
        "Manufacturing SOC publishes industrial detection notes",
        "research",
        "medium",
        "Other",
        "KZ",
        "industrial_manufacturing",
        "siem_detection",
        "Wazuh",
        "",
    ),
    (
        "Government teams automate exposure reporting",
        "research",
        "medium",
        "MEA",
        "SA",
        "government",
        "security_automation",
        "Qualys",
        "",
    ),
    (
        "Cloud vendors announce a minor dashboard refresh",
        "vendor_product",
        "low",
        "Other",
        "JP",
        "global_it_services",
        "zero_trust_cloud",
        "AWS",
        "",
    ),
]


def seed(config, store):
    from .schemas import classification_model

    model = classification_model(config)
    for index, (title, category, importance, region, country, industry, practice, tech, cve) in enumerate(
        STORIES
    ):
        ident = f"fixture-{index:02}"
        published = FIXTURE_NOW - timedelta(hours=index + 1)
        summary = "Synthetic training scenario for testing digest presentation. It does not describe a real incident."
        if index == 0:
            summary += " Fictional source evidence: attackers are actively exploiting Fortinet FortiOS."
        source_count = 3 if index == 1 else 1
        for source in range(source_count):
            article = {
                "title": title,
                "summary": summary + (f" Reference {cve}." if cve else ""),
                "url": f"https://source{source}.example.test/story/{index}",
                "source": f"Fixture source {source + 1}",
                "published": published.isoformat(),
                "fetched": FIXTURE_NOW.isoformat(),
                "date_inferred": False,
                "cves": [cve] if cve else [],
                "attack_techniques": [],
                "links": [],
                "independence_key": f"fixture-publisher-{source}",
            }
            store.add_article(article, ident)
        low = importance == "low"
        item = {
            "cluster_id": ident,
            "headline": title,
            "summary": summary,
            "category": category,
            "importance": importance,
            "importance_rationale": "Synthetic classification for acceptance testing.",
            "location_relevance": {k: 95 if k == region and not low else 15 for k in config.regions},
            "countries_mentioned": [country],
            "industry_relevance": {k: 95 if k == industry and not low else 10 for k in config.industries},
            "practice_area_relevance": {
                k: 95 if k == practice and not low else 5 for k in config.practice_areas
            },
            "affected_technologies": [tech] if tech else [],
            "cves": [cve] if cve else [],
            "threat_actors": [],
            "regulations": [],
            "attack_techniques": [],
            "detection_refs": [],
            "detection_coverage_note": "Assessment: validate the relevant telemetry and escalation procedure in a controlled exercise.",
            "related_case_studies": [
                slug
                for slug, case in config.case_studies.items()
                if case["industry"] == industry or practice in case["practice_areas"]
            ][:2],
            "business_signal": {
                "present": False,
                "type": "technology_shift",
                "sector": industry,
                "region": region,
                "rationale": "",
            },
            "recommended_action": "Use this synthetic item to check report layout and routing.",
            "confidence": 1.0,
        }
        if index == 4:
            key = next(key for key, r in config.regulations.items() if r["name"] == "DORA")
            item["regulations"] = [{"key": key, "nature": "guidance", "effective_or_deadline_date": None}]
        store.classify(
            ident, model.model_validate(item).model_dump(mode="json"), config.fingerprint, "fixture"
        )
    store.put(
        "kev",
        {
            "CVE-2026-99001": {
                "dateAdded": "2026-10-16",
                "vendorProject": "Fortinet",
                "product": "FortiOS",
                "requiredAction": "Synthetic patch instruction",
            }
        },
    )
    store.put("epss", {"CVE-2026-99002": 0.6})
    store.put("fixture", True)


def foundation_sample(config, store):
    path = config.output / "samples" / "phase-1-daily.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        "# SecDigest daily — synthetic preview",
        "",
        "Fixture data only; these are not real news reports.",
        "",
        "| Importance | Headline |",
        "|---|---|",
    ]
    rows.extend(
        f"| {c['classification']['importance'].upper()} | {c['classification']['headline']} |"
        for c in store.clusters()
    )
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path
