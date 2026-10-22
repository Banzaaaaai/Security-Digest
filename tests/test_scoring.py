from copy import deepcopy
from datetime import timedelta

import pytest

from secdigest.fixtures import FIXTURE_NOW
from secdigest.reporting import report_items
from secdigest.scoring import score


@pytest.fixture
def news(populated):
    def make(title, summary="", technology="PHP", category="vulnerability", importance="high"):
        cluster = deepcopy(populated.clusters()[0])
        item = cluster["classification"]
        item.update(
            headline=title,
            summary=summary or title,
            category=category,
            importance=importance,
            cves=[],
            affected_technologies=[technology] if technology else [],
            countries_mentioned=[],
            location_relevance={r: 20 for r in item["location_relevance"]},
            industry_relevance={k: 40 for k in item["industry_relevance"]},
            practice_area_relevance={k: 40 for k in item["practice_area_relevance"]},
        )
        cluster["articles"][0].update(title=title, summary=summary, cves=[])
        return cluster

    return make


def test_global_php_exploitation_ranks_above_local_news_and_specialist_software(config, populated, news):
    php = news("PHP critical RCE flaws", "Attackers are already exploiting PHP in the wild.")
    php["classification"]["practice_area_relevance"]["vuln_exposure_mgmt"] = 95
    plex = news(
        "Plex Media Server flaws",
        "Attackers are actively exploiting Plex Media Server.",
        technology="Plex Media Server",
        importance="critical",
    )
    local = news("UAE launches government AI", category="vendor_product", importance="medium")
    for field in ("location_relevance", "industry_relevance", "practice_area_relevance"):
        local["classification"][field] = dict.fromkeys(local["classification"][field], 100)
    a, b, c = (score(config, value, populated, FIXTURE_NOW) for value in (php, plex, local))
    assert a["importance"] == "critical"
    assert set(a["location_relevance"].values()) == {95}
    assert a["priority"] > b["priority"] > c["priority"]
    assert c["priority"] < 65


@pytest.mark.parametrize(
    "text",
    [
        "No evidence that PHP is actively exploited.",
        "PHP may be actively exploited after disclosure.",
        "Researchers demonstrated active exploitation of PHP in a lab.",
        "PHP has a working PoC; mass exploitation is expected.",
        "PHP is not being actively exploited in the wild.",
    ],
)
def test_predictions_negation_and_lab_work_do_not_establish_active_attacks(config, populated, news, text):
    cluster = news("Critical PHP RCE patch", text, importance="critical")
    result = score(config, cluster, populated, FIXTURE_NOW)
    assert result["importance"] == "high"
    assert not result["risk_evidence"]["exploitation_reported"]


@pytest.mark.parametrize(
    "text",
    [
        "Amazon detected an attempt to exploit PHP2Shell against a honeypot.",
        "Several firms saw exploitation attempts before PHP released patches.",
        "Reports of exploitation attempts against PHP2Shell.",
        "Misbruik van PHP2Shell-lek gemeld.",
        "PHP2Shell exploitation attempt detected by researchers.",
        "PHP2Shell exploitation started before patch rollout.",
        "Analysts now observe large-scale evidence of exploitation of PHP.",
    ],
)
def test_source_reported_attempts_trigger_urgency_without_claiming_success(config, populated, news, text):
    cluster = news("PHP2Shell security update", text)
    result = score(config, cluster, populated, FIXTURE_NOW)
    assert result["importance"] == "critical"
    assert result["summary"] == text
    assert set(result["location_relevance"].values()) == {95}
    assert result["risk_evidence"]["exploitation_reported"] == [cluster["articles"][0]["url"]]


def test_model_prose_is_not_exploitation_evidence(config, populated, news):
    cluster = news("PHP update available", "PHP has a security fix.")
    cluster["classification"].update(
        summary="Attackers are actively exploiting PHP.", recommended_action="Hunt for active exploitation."
    )
    assert score(config, cluster, populated, FIXTURE_NOW)["importance"] == "high"


def test_systemic_compromise_is_critical_but_vendor_word_alone_is_not(config, populated, news):
    cluster = news(
        "LiteLLM supply-chain compromise",
        "A malicious version of LiteLLM steals credentials.",
        technology="LiteLLM",
        category="supply_chain",
    )
    result = score(config, cluster, populated, FIXTURE_NOW)
    assert result["importance"] == "critical"
    assert set(result["location_relevance"].values()) == {85}
    cluster["classification"]["category"] = "research"
    assert score(config, cluster, populated, FIXTURE_NOW)["importance"] == "high"
    cluster = news(
        "LiteLLM release",
        "A future supply-chain attack could compromise LiteLLM.",
        technology="LiteLLM",
        category="supply_chain",
    )
    assert score(config, cluster, populated, FIXTURE_NOW)["importance"] == "high"


@pytest.mark.parametrize("category", ["data_breach", "regulation_policy", "research", "vendor_product"])
def test_local_events_and_research_are_not_globalized_by_product_mentions(config, populated, news, category):
    cluster = news(
        "Dutch organization uses PHP",
        "One Dutch organization reviewed PHP.",
        category=category,
        importance="medium",
    )
    cluster["classification"]["countries_mentioned"] = ["NL", "GB", "UK", "IE"]
    result = score(config, cluster, populated, FIXTURE_NOW)
    assert result["location_relevance"] == {"US": 20, "Europe": 30, "MEA": 20, "Other": 20}


def test_missing_or_hallucinated_technology_does_not_establish_global_scope(config, populated, news):
    cluster = news("Unidentified software flaw", "A vendor released a fix.")
    assert score(config, cluster, populated, FIXTURE_NOW)["location_relevance"]["US"] == 20
    cluster["articles"][0]["summary"] = "Node.js released a fix."
    assert score(config, cluster, populated, FIXTURE_NOW)["location_relevance"]["US"] == 20


def test_issuer_location_does_not_bias_global_software_scores(config, populated, news):
    cluster = news("CISA warns of PHP flaws", "The US agency recommends a PHP security update.")
    cluster["classification"]["countries_mentioned"] = ["US"]
    cluster["classification"]["location_relevance"]["US"] = 100
    result = score(config, cluster, populated, FIXTURE_NOW)
    assert set(result["location_relevance"].values()) == {95}


def test_old_kev_and_high_epss_do_not_turn_lab_research_into_current_exploitation(config, populated, news):
    cluster = news("PHP local privilege escalation analysis", "A laboratory demonstration in PHP.")
    cluster["classification"]["cves"] = ["CVE-2026-99001"]
    populated.put(
        "kev", {"CVE-2026-99001": {"dateAdded": (FIXTURE_NOW - timedelta(days=30)).date().isoformat()}}
    )
    populated.put("epss", {"CVE-2026-99001": 0.99})
    result = score(config, cluster, populated, FIXTURE_NOW)
    assert result["importance"] == "high"
    assert result["category"] == "vulnerability"


def test_new_kev_covers_widespread_technology_outside_watch_list(config, populated, news):
    cluster = news("PHP security update", "PHP has a critical flaw.")
    cluster["classification"]["cves"] = ["CVE-2026-99001"]
    assert score(config, cluster, populated, FIXTURE_NOW)["importance"] == "critical"
    populated.put(
        "kev", {"CVE-2026-99001": {"dateAdded": (FIXTURE_NOW + timedelta(days=1)).date().isoformat()}}
    )
    cluster["classification"]["importance"] = "medium"
    assert score(config, cluster, populated, FIXTURE_NOW)["importance"] == "medium"


def test_source_count_affects_corroboration_only(config, populated, news):
    cluster = news("Research result", category="research", importance="low")
    cluster["articles"] = [
        {**cluster["articles"][0], "url": f"https://source{x}.test", "independence_key": str(x)}
        for x in range(6)
    ]
    result = score(config, cluster, populated, FIXTURE_NOW)
    assert result["importance"] == "low"
    assert result["independent_sources_24h"] == 6


def test_other_region_receives_equal_priority_weight(config, populated, news):
    cluster = news("Regional incident", category="data_breach")
    cluster["classification"]["location_relevance"] = dict.fromkeys(config.regions, 0)
    cluster["classification"]["location_relevance"]["Other"] = 90
    first = score(config, cluster, populated, FIXTURE_NOW)
    cluster["classification"]["location_relevance"].update(Other=0, US=90)
    assert score(config, cluster, populated, FIXTURE_NOW)["priority"] == first["priority"]


def test_exact_cve_coverage_shares_exploitation_without_merging_roundups(config, populated, news):
    left = news("PHP critical RCE disclosure", "PHP patches CVE-2026-12345.")
    right = news(
        "Attack sensors detect attempts", "Firms observed exploitation attempts against PHP CVE-2026-12345."
    )
    for ident, cluster in enumerate((left, right)):
        cluster["id"] = cluster["classification"]["cluster_id"] = str(ident)
        cluster["classification"]["cves"] = ["CVE-2026-12345"]
    original = deepcopy([left, right])
    merged, items = report_items(config, [left, right], populated, FIXTURE_NOW)
    assert len(merged) == 1
    assert items[0]["importance"] == "critical"
    assert [left, right] == original
    right["classification"]["cves"].append("CVE-2026-12346")
    assert len(report_items(config, [left, right], populated, FIXTURE_NOW)[0]) == 2


def test_exact_cve_dedup_preserves_distinct_actors(config, populated, news):
    a = news("PHP exploitation", "PHP was actively exploited.")
    b = deepcopy(a)
    b["id"] = b["classification"]["cluster_id"] = "b"
    for cluster, actor in ((a, "Actor A"), (b, "Actor B")):
        cluster["classification"].update(cves=["CVE-2026-12345"], threat_actors=[actor])
    assert len(report_items(config, [a, b], populated, FIXTURE_NOW)[0]) == 2


def test_denied_certificate_compromise_does_not_raise_severity(config, populated, news):
    cluster = news(
        "Certificate investigation",
        "No private keys were compromised.",
        category="vendor_product",
        importance="medium",
    )
    result = score(config, cluster, populated, FIXTURE_NOW)
    assert result["importance"] == "medium"
    assert not result["risk_evidence"]["certificate_compromise"]


def test_invalid_bands_and_floors_are_rejected(config):
    config.scoring["priority_bands"]["medium"] = [35, 90]
    with pytest.raises(ValueError, match="nonoverlapping"):
        config.validate()
    config.scoring["priority_bands"]["medium"] = [35, 64.99]
    config.scoring["exposure"]["profiles"][0]["location_floor"] = 101
    with pytest.raises(ValueError, match="floors"):
        config.validate()
