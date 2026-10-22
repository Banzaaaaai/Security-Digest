"""Conservative risk signals from source text, never generated recommendations.

These are reported observations, not independent confirmation of exploitation.
Unknown signals stay false; a PoC or a prediction is not an observed attack.
"""

import re


def mentions(text, aliases):
    return any(re.search(r"(?<!\w)" + re.escape(alias) + r"(?!\w)", text, re.I) for alias in aliases)


def source_signals(articles):
    patterns = {
        "exploitation_reported": (
            r"(?:actively|already)\s+(?:being\s+)?exploit(?:ed|ing)|"
            r"exploit(?:ed|ation|ing)\s+in.the.wild|"
            r"(?:observed|detected|saw|confirmed)\b.{0,100}\b(?:exploit|attack)\s*(?:ation\s*)?attempt|"
            r"(?:observed|detected|saw)\b.{0,30}attempt to exploit|"
            r"(?:reports? of|observed|detected|first|early)\s+exploitation attempts|"
            r"exploit attempts (?:emerge|observed|detected)|"
            r"exploitation (?:attempts? )?(?:(?:has|have|was|were) )?(?:detected|observed|started|began|begins)|"
            r"(?:observe|observed|detect|detected)\b.{0,60}evidence of exploitation|"
            r"exploitation attempts hit sensors|"
            r"aanvalspogingen.{0,60}waargenomen|misbruik van.{0,60}gemeld"
        ),
        "rce": r"\bRCE\b|remote code execution|execute arbitrary code|run code.{0,40}without",
        "critical_flaw": r"\bcritical\b|\bkritiek\w*\b|CVSS\s*(?:score\s*(?:of\s*)?)?(?:9\.|10\.0)",
        "emergency_patch": r"emergency (?:security )?(?:patch|fix|update)|\bnoodpatch|take.{0,50}offline",
        "public_poc": r"\bPoCs?\b|proof.of.concept|working exploits?",
        "supply_chain_compromise": (
            r"supply.chain (?:attack|compromise)|release pipeline was compromised|"
            r"malicious (?:version|package|release)|\bbesmette versie\b"
        ),
        "certificate_compromise": (
            r"compromised.{0,40}(?:certificates|signing keys|private keys)|"
            r"private keys.{0,60}(?:compromised|recoverable)|"
            r"gecompromitteerde keys|keys.{0,80}gecompromitteerd"
        ),
        "worldwide": r"\bworldwide\b|\bglobally\b|\bglobal campaign\b|\bwereldwijd\b",
    }
    evidence = {key: [] for key in patterns}
    for article in articles:
        text = article["title"] + ". " + article["summary"]
        sentences = re.split(r"(?<=[.!?])\s+|\n+", text)
        for key, pattern in patterns.items():
            for sentence in sentences:
                if key in {
                    "exploitation_reported",
                    "supply_chain_compromise",
                    "certificate_compromise",
                } and re.search(
                    r"\b(?:no|not|never|without|unconfirmed|unverified|geen)\b.{0,90}"
                    r"(?:exploit|attack|misbruik|compromis|malicious)|"
                    r"(?:could|may|might|would|expected to|likely to)\b.{0,60}(?:exploit|compromise|supply.chain)|"
                    r"\b(?:lab|laboratory|simulation|simulated|hypothetical)\b",
                    sentence,
                    re.I,
                ):
                    continue
                if re.search(pattern, sentence, re.I):
                    evidence[key].append(article["url"])
                    break
    return {key: sorted(set(urls)) for key, urls in evidence.items()}


def exposure_profile(config, item, articles, signals):
    """Apply deployment scope to product security issues, not individual victims."""
    category = item["category"]
    vulnerability = category in {"vulnerability", "exploitation_in_the_wild"}
    product_security = category == "vendor_product" and any(
        signals[key] for key in ("critical_flaw", "emergency_patch", "certificate_compromise")
    )
    supply_chain = category == "supply_chain" or (
        category == "apt_nation_state" and signals["supply_chain_compromise"]
    )
    certificate = (
        category in {"other", "vendor_product", "vulnerability"} and signals["certificate_compromise"]
    )
    if not (vulnerability or product_security or supply_chain or certificate):
        if category in {"ransomware", "apt_nation_state", "fraud_phishing"} and signals["worldwide"]:
            return {"name": "Worldwide campaign", **config.scoring["exposure"]["worldwide_campaign"]}
        return None
    if certificate:
        return {"name": "Certificate trust infrastructure", **config.scoring["exposure"]["watch_default"]}
    # Require the technology in an affected field AND the original source.
    # A classifier hallucination or an incidental title keyword is insufficient.
    affected = " ".join(item["affected_technologies"])
    source = " ".join(a["title"] + " " + a["summary"] for a in articles)
    profiles = []
    for profile in config.scoring["exposure"]["profiles"]:
        if any(
            mentions(affected, aliases) and mentions(source, aliases)
            for alias in profile["aliases"]
            for aliases in [[alias, *config.scoring["exposure"].get("technology_aliases", {}).get(alias, [])]]
        ):
            profiles.append(profile)
    if profiles:
        return max(profiles, key=lambda profile: profile["location_floor"])
    # The watch list describes deployment relevance, not evidence of compromise.
    aliases = [
        alias
        for products in config.watch_tech.values()
        for p in products
        for alias in [p["name"], *p["aliases"]]
    ]
    if any(
        mentions(affected, equivalent) and mentions(source, equivalent)
        for alias in aliases
        for equivalent in [[alias, *config.scoring["exposure"].get("technology_aliases", {}).get(alias, [])]]
    ):
        return {"name": "Globally deployed watch technology", **config.scoring["exposure"]["watch_default"]}
    return None
