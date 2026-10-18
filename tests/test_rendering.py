from copy import deepcopy
from pathlib import Path

from secdigest.fixtures import FIXTURE_NOW
from secdigest.rendering import archive, csv_text, render_html, render_markdown
from secdigest.reporting import build_report


def test_daily_and_weekly_reports(config, populated, tmp_path):
    config.settings["output"] = str(tmp_path)
    for kind, period in (("daily", None), ("weekly", "2026-W42")):
        report = build_report(config, populated, kind, period, FIXTURE_NOW, dry_run=True)
        assert len(report["items"]) == 12
        paths = archive(config, report)
        assert set(paths) == {"md", "html", "json", "csv"}
        assert "SYNTHETIC PREVIEW" in paths["html"].read_text(encoding="utf-8")
        if kind == "weekly":
            assert len(report["industry_heatmap"]) == 10
            assert len(report["practice_heatmap"]) == 11
            assert report["deltas"] is None
            assert report["business_signals"] is None
            assert len(report["synthesis"]["content_ideas"]) == 2


def test_live_reports_disclose_cisa_coverage_gap(config, populated):
    report = build_report(config, populated, "daily", now=FIXTURE_NOW)
    for rendered in (
        render_markdown(config, report),
        render_html(config, report),
        render_html(config, report, email=True),
    ):
        assert "GovDelivery email announcements are not collected" in rendered
    assert "kev_provenance" in report


def test_html_escapes_source_and_rejects_link_schemes(config, populated):
    report = build_report(config, populated, "daily", now=FIXTURE_NOW, dry_run=True)
    item = report["items"][0]
    item["headline"] = '<script>alert(1)</script><a href="javascript:alert(1)">bad</a>'
    item["sources"][0]["url"] = "javascript:alert(1)"
    rendered = render_html(config, report, email=True)
    assert "<script>" not in rendered
    assert 'href="javascript:' not in rendered
    assert "&lt;script&gt;" in rendered
    assert "<style>" not in rendered


def test_email_200_items_under_limit_and_full_archive_keeps_everything(config, populated):
    report = build_report(config, populated, "daily", now=FIXTURE_NOW, dry_run=True)
    original = report["items"][0]
    report["items"] = [deepcopy(original) for _ in range(200)]
    for i, item in enumerate(report["items"]):
        item["cluster_id"] = f"test-{i}"
        item["summary"] = "Synthetic unicode story. " + "é" * 1500
    email = render_html(config, report, email=True)
    assert len(email.encode()) < 90000
    assert "moved to the attachment" in email
    assert render_html(config, report).count("Synthetic unicode story") == 200


def test_csv_all_scores_and_formula_protection(config, populated):
    report = build_report(config, populated, "daily", now=FIXTURE_NOW, dry_run=True)
    report["items"][0]["headline"] = "=DANGEROUS()"
    data = csv_text(config, report)
    assert "'=DANGEROUS()" in data
    for key in config.industries:
        assert f"industry_relevance.{key}" in data
    for key in config.practice_areas:
        assert f"practice_area_relevance.{key}" in data


def test_golden_digests(config, populated):
    for kind, period in (("daily", None), ("weekly", "2026-W42")):
        report = build_report(config, populated, kind, period, FIXTURE_NOW, dry_run=True)
        actual = render_markdown(config, report)
        expected = (Path(__file__).parent / "golden" / f"{kind}.md").read_text(encoding="utf-8")
        assert actual == expected
