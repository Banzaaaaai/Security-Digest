"""One-time import of the original specification into standalone YAML configuration.

Refuses to overwrite existing configuration. The application does not use this script.
"""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = (ROOT / "security-digest-prompt.md").read_text(encoding="utf-8")
DEST = ROOT / "config"


def section(name):
    return SPEC.split(f"### `config/{name}.yaml`", 1)[1].split("\n### ", 1)[0].split("\n---", 1)[0]


def table(text):
    rows = [line for line in text.splitlines() if line.startswith("|")]
    return [[cell.strip().strip("`") for cell in row.strip("|").split("|")] for row in rows[2:]]


def write(name, data):
    path = DEST / f"{name}.yaml"
    if path.exists():
        raise SystemExit(f"Refusing to overwrite {path}")
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def main():
    DEST.mkdir(exist_ok=True)
    regions = {r[0]: {"description": r[1]} for r in table(section("regions"))}
    countries = {
        "US": "US",
        "NL": "Europe",
        "IE": "Europe",
        "CH": "Europe",
        "GB": "Europe",
        "AE": "MEA",
        "SA": "MEA",
    }
    write(
        "regions",
        {
            "regions": regions,
            "priority_countries": countries,
            "country_aliases": {"UK": "GB", "UAE": "AE"},
            "country_bonus": 10,
        },
    )
    for kind in ("industries", "practice_areas"):
        write(kind, {kind: {r[0]: {"name": r[1], "signals": r[2]} for r in table(section(kind))}})
    tech = yaml.safe_load(re.search(r"```yaml\n(.*?)```", section("watch_tech"), re.S)[1])["watch_tech"]
    aliases = {
        "Entra ID": ["Azure AD", "Microsoft Entra"],
        "Exchange": ["Microsoft Exchange", "Exchange Server"],
        "Fortinet FortiOS": ["FortiOS"],
        "FortiGate": ["Fortinet FortiGate"],
        "Palo Alto PAN-OS": ["PAN-OS"],
        "Citrix NetScaler": ["NetScaler", "Citrix ADC"],
        "Microsoft 365": ["Office 365", "M365"],
        "Model Context Protocol (MCP)": ["Model Context Protocol", "MCP"],
        "Windows Server": ["Microsoft Windows Server"],
        "Google Cloud": ["GCP"],
        "AWS": ["Amazon Web Services"],
    }
    write(
        "watch_tech",
        {
            "watch_tech": {
                vendor: [
                    {
                        "name": t,
                        "aliases": aliases.get(t, []),
                        "cross_industry": t
                        in {
                            "Windows Server",
                            "Exchange",
                            "Fortinet FortiOS",
                            "FortiGate",
                            "Citrix NetScaler",
                            "Microsoft 365",
                        },
                    }
                    for t in ts
                ]
                for vendor, ts in tech.items()
            }
        },
    )
    sectors = {r[1]: r[0] for r in table(section("industries"))}
    cases = {
        r[0]: {
            "title": r[0].replace("-", " ").capitalize(),
            "industry": sectors[r[1]],
            "country": {"UK": "GB", "UAE": "AE"}.get(r[2], r[2]),
            "practice_areas": r[3].split(", "),
            "url": f"https://brusiantsou.com/stories/{r[0]}/",
        }
        for r in table(section("case_studies"))
    }
    write("case_studies", {"case_studies": cases})
    write(
        "writing",
        {
            "writing": {
                slug: {
                    "title": slug.replace("-", " ").capitalize(),
                    "url": f"https://brusiantsou.com/writing/{slug}/",
                    "tags": tags,
                }
                for slug, tags in {
                    "from-log-feeds-to-detections": ["siem_detection"],
                    "discovery-before-the-roadmap": ["grc_audit", "vuln_exposure_mgmt"],
                    "privacy-and-security-in-private-banking": ["private_banking", "data_protection_dlp"],
                }.items()
            }
        },
    )
    regulations = {}
    for jurisdiction, names in table(section("regulations")):
        # Commas in parentheses belong to a single regulation label.
        for name in re.split(r", (?![^()]*\))", names):
            key = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
            region = (
                "US"
                if jurisdiction == "US"
                else "MEA"
                if jurisdiction in {"UAE", "KSA"}
                else "Europe"
                if jurisdiction not in {"Global / standards", "Sector"}
                else "all"
            )
            regulations[key] = {
                "name": name,
                "jurisdiction": jurisdiction,
                "region": region,
                "industries": "all",
                "milestones": [],
                "needs_dates": True,
            }
    write("regulations", {"regulations": regulations})
    feeds = yaml.safe_load(re.search(r"```yaml\n(.*?)```", SPEC, re.S)[1])
    sites = [
        "scworld.com",
        "csoonline.com",
        "securityboulevard.com",
        "welivesecurity.com",
        "unit42.paloaltonetworks.com",
        "blog.talosintelligence.com",
        "news.sophos.com",
        "wiz.io/blog",
        "sec.okta.com",
        "proofpoint.com/us/blog/threat-insight",
        "abnormal.ai/blog",
        "cofense.com/blog",
        "cisa.gov/news-events/ics-advisories",
        "dragos.com/blog",
        "claroty.com/team82/research",
        "nozominetworks.com/blog",
        "sans.org/blog",
        "genai.owasp.org",
        "embracethered.com/blog",
        "simonwillison.net",
        "socket.dev/blog",
        "stepsecurity.io/blog",
        "ncsc.nl",
        "ncsc.gov.uk",
        "enisa.europa.eu",
        "security.nl",
        "ncsc.gov.ie",
        "centralbank.ie/news-media",
        "ncsc.admin.ch",
        "finma.ch/en/news",
        "csc.gov.ae",
        "nca.gov.sa",
        "gulfbusiness.com",
        "itp.net",
    ]
    site_iter = iter(sites)
    for feed in feeds["feeds"]:
        pending = feed["url"] == "TODO_VERIFY"
        feed["site"] = "https://" + next(site_iter) if pending else feed["url"]
        feed.update({"enabled": not pending, "type": "rss", "verified": False})
    feeds["enrichment"]["mitre_attack_stix"] = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    )
    write("feeds", feeds)
    write(
        "settings",
        {
            "timezone": "Europe/Amsterdam",
            "database": "data/secdigest.sqlite",
            "output": "output",
            "http": {
                "timeout": 15,
                "concurrency": 8,
                "user_agent": "SecDigest/0.1 (+https://brusiantsou.com)",
                "max_bytes": 20000000,
            },
            "models": {
                "classification": "gpt-5.4-mini",
                "synthesis": "gpt-5.4",
                "batch_size": 5,
                "max_tokens": 16000,
                "prices_per_million": {},
            },
            "enrichment": {"epss": False, "nvd": False, "github": False},
            "business_signals": {"enabled": False},
            "weekly": {"window": "calendar", "heatmap_min_relevance": 30},
            "email": {
                "send_when_empty": True,
                "max_html_bytes": 90000,
                "table_rows": 20,
                "retry_count": 3,
                "source_health_silence_days": 3,
            },
            "retention": {"daily_days": 90, "database_days": 120},
            "scheduling": {"enabled": False, "daily_hour": 7, "weekly_hour": 8},
        },
    )
    rubric = SPEC.split("### Importance\n", 1)[1].split("**Deterministic overrides", 1)[0].strip()
    write(
        "scoring",
        {
            "importance_points": {"critical": 100, "high": 75, "medium": 45, "low": 15},
            "weights": {"importance": 0.4, "location": 0.2, "industry": 0.2, "practice": 0.2},
            "priority_regions": ["US", "Europe", "MEA"],
            "categories": [
                "vulnerability",
                "exploitation_in_the_wild",
                "data_breach",
                "ransomware",
                "apt_nation_state",
                "supply_chain",
                "fraud_phishing",
                "regulation_policy",
                "law_enforcement",
                "research",
                "vendor_product",
                "other",
            ],
            "rubric": rubric,
            "title_similarity": 85,
            "cve_title_similarity": 55,
            "cluster_days": 7,
            "epss_threshold": 0.5,
            "independent_sources": 3,
            "inclusion": {"min_importance": "medium", "relevance": 60},
            "cross_industry_floor": 40,
        },
    )


if __name__ == "__main__":
    main()
