"""Shared report sections, escaped templates, archives and bounded email bodies."""

from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .normalize import safe_url

COLORS = {"critical": "#991b1b", "high": "#92400e", "medium": "#1e40af", "low": "#475569"}


def link(text, url):
    return {"text": str(text), "url": safe_url(url)}


def relevance_fields(config, item):
    fields = [
        {
            "label": "Location relevance",
            "text": " · ".join(f"{k} {v}%" for k, v in item["location_relevance"].items()),
        }
    ]
    # Technology relevance displays the existing technical practice-area scores.
    for label, field, taxonomy in (
        ("Industry relevance", "industry_relevance", config.industries),
        ("Technology relevance", "practice_area_relevance", config.practice_areas),
    ):
        values = [
            f"{taxonomy[k]['name']} {v}%" for k, v in sorted(item[field].items(), key=lambda p: -p[1])[:2]
        ]
        fields.append({"label": label, "text": " · ".join(values)})
    return fields


def top_tags(config, item):
    return " · ".join(field["text"] for field in relevance_fields(config, item))


def details(config, item):
    cves = []
    for cve, facts in item["cve_details"].items():
        cves.append(
            f"{cve} | KEV {'yes' if facts['kev'] else 'not listed'} | EPSS {facts['epss'] if facts['epss'] is not None else 'unknown'} | CVSS {facts['cvss'] if facts['cvss'] is not None else 'unknown'}"
        )
    return {
        "kind": "story",
        "item": item,
        "tags": top_tags(config, item),
        "relevance": relevance_fields(config, item),
        "cves": cves,
        "techniques": [
            link(t, "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/")
            for t in item["attack_techniques"]
        ],
        "detection": [link(r["type"].upper(), r["url"]) for r in item["detection_refs"]],
        "cases": [
            link(config.case_studies[s]["title"], config.case_studies[s]["url"])
            for s in item["related_case_studies"]
        ],
        "sources": [link(s["source"], s["url"]) for s in item["sources"]],
    }


def sections(config, report, email=False, item_limit=None, compact=False):
    blocks = []
    all_items = report["items"]
    visible = all_items if item_limit is None else all_items[:item_limit]
    lookup = {i["cluster_id"]: i for i in all_items}

    def heading(text):
        blocks.append({"kind": "heading", "text": text})

    def paragraph(text):
        blocks.append({"kind": "paragraph", "text": text})

    def table(headers, rows):
        blocks.append({"kind": "table", "headers": headers, "rows": rows})

    def bullet(values):
        blocks.append({"kind": "list", "values": values or ["None recorded for this window."]})

    def story_ref(ident):
        item = lookup[ident]
        return link(item["headline"], item["sources"][0]["url"])

    def regulation_section():
        for region, entries in report["regulations"].items():
            paragraph(region)
            table(
                ["Regulation", "Nature", "Reported date", "Sources"],
                [
                    [
                        r["name"],
                        r["nature"],
                        r["effective_or_deadline_date"] or "Not stated",
                        [link(s["source"], s["url"]) for s in r["sources"]],
                    ]
                    for r in entries
                ],
            )
        if not report["regulations"]:
            paragraph("No regulation or policy items in this window.")

    def heatmap(title, rows):
        heading(title)
        paragraph(
            f"Count / average relevance; includes scores ≥ {config.settings['weekly']['heatmap_min_relevance']}%."
        )
        blocks.append({"kind": "heatmap", "rows": rows, "levels": list(config.scoring["importance_points"])})

    if report["synthetic"]:
        paragraph("SYNTHETIC PREVIEW — these fixture stories are not real news or incidents.")
    paragraph(
        f"Window: {report['start']} to {report['end']} (end exclusive). Display timezone: {report['timezone']}."
    )
    paragraph(
        " · ".join(f"{level.upper()} {count}" for level, count in report["counts"].items())
        + f" · New KEV entries {len(report['new_kev'])} · Watch technology hits {report['watch_hits']}"
    )
    if report["unclassified"]:
        paragraph(f"Coverage incomplete: {report['unclassified']} clusters have no validated classification.")
    if report["source_health"]:
        health = report["source_health"]
        paragraph(
            f"Source health: {health['enabled']} enabled feeds; {health['failures']} failures; {health['new']} new articles at last ingestion."
        )
    for warning in report["enrichment_warnings"]:
        paragraph("Enrichment coverage: " + warning)
    if report["kind"] == "daily":
        heading("Critical / High: act now")
        important = [i for i in visible if i["importance"] in {"critical", "high"}]
        if compact:
            bullet([link(i["headline"], i["sources"][0]["url"]) for i in important])
        else:
            blocks.extend(details(config, i) for i in important)
            if not important:
                paragraph("No critical or high items in this view.")
        heading("Priority table")
        rows = [i for i in visible if i["included"]]
        if email:
            rows = rows[: config.settings["email"]["table_rows"]]
            table(
                ["Importance", "Headline and relevance", "Priority"],
                [
                    [
                        i["importance"].upper(),
                        [link(i["headline"], i["sources"][0]["url"]), *relevance_fields(config, i)],
                        i["priority"],
                    ]
                    for i in rows
                ],
            )
        else:
            headers = [
                "Importance",
                "Headline",
                *[f"{r}%" for r in config.regions],
                "Top 2 industries",
                "Top 2 practice areas",
                "CVEs",
                "KEV",
                "Case study",
                "Sources",
            ]
            table(
                headers,
                [
                    [
                        i["importance"].upper(),
                        i["headline"],
                        *i["location_relevance"].values(),
                        "; ".join(
                            f"{config.industries[k]['name']} {v}%"
                            for k, v in sorted(i["industry_relevance"].items(), key=lambda p: -p[1])[:2]
                        ),
                        "; ".join(
                            f"{config.practice_areas[k]['name']} {v}%"
                            for k, v in sorted(i["practice_area_relevance"].items(), key=lambda p: -p[1])[:2]
                        ),
                        ", ".join(i["cves"]),
                        "Yes" if any(d["kev"] for d in i["cve_details"].values()) else "No",
                        [
                            link(config.case_studies[s]["title"], config.case_studies[s]["url"])
                            for s in i["related_case_studies"]
                        ],
                        [link(s["source"], s["url"]) for s in i["sources"]],
                    ]
                    for i in rows
                ],
            )
        heading("Vulnerability watch")
        if not compact:
            table(
                ["New KEV", "Vendor / product", "Added", "Due"],
                [
                    [
                        link(k["cve"], "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
                        f"{k.get('vendorProject', '')} / {k.get('product', '')}",
                        k["dateAdded"],
                        k.get("dueDate") or "Not stated",
                    ]
                    for k in report["new_kev"]
                ],
            )
            for vendor, entries in report["watch"].items():
                paragraph(vendor)
                bullet(
                    [
                        [entry["technology"], story_ref(entry["cluster_id"])]
                        for entry in entries
                        if entry["cluster_id"] in {i["cluster_id"] for i in visible}
                    ]
                )
        else:
            paragraph("Complete vulnerability watch is in the attached report.")
        heading("Regulation and policy")
        regulation_section() if not compact else paragraph("See the attached report for all policy items.")
        heading("Other")
        if email:
            paragraph(f"{report['other_count']} lower-priority headlines in the attachment.")
        else:
            bullet([story_ref(i["cluster_id"]) for i in all_items if not i["included"]])
    else:
        heading("Executive summary")
        bullet(report["synthesis"]["executive_summary"])
        heading("Top 10 stories of the week")
        if compact:
            bullet([story_ref(i["cluster_id"]) for i in visible[:10]])
        else:
            blocks.extend(details(config, i) for i in visible[:10])
        heatmap("Industry heatmap", report["industry_heatmap"])
        heatmap("Practice-area heatmap", report["practice_heatmap"])
        if not email:
            heading("Regional split")
            for region, countries in report["regional"].items():
                paragraph(region)
                for country, ids in countries.items():
                    paragraph(country)
                    bullet([story_ref(ident) for ident in ids[:5]])
            heading("Trends")
            paragraph(report["synthesis"]["trend_narrative"])
            if report["deltas"] is None:
                paragraph("Previous-week data unavailable; no week-over-week comparison is claimed.")
            for name, values in report["trends"].items():
                table(
                    [name.replace("_", " ").capitalize(), "Clusters", "Week-over-week delta"],
                    [
                        [key, value, report["deltas"][name].get(key) if report["deltas"] else "Unavailable"]
                        for key, value in sorted(values.items(), key=lambda p: -p[1])
                    ],
                )
            heading("CVE table")
            table(
                ["CVE", "CVSS", "EPSS", "KEV", "Watch technology", "Mentioning sources"],
                [
                    [
                        key,
                        row["cvss"] if row["cvss"] is not None else "Unknown",
                        row["epss"] if row["epss"] is not None else "Unknown",
                        "Yes" if row["kev"] else "No",
                        ", ".join(row["watch_tech"]),
                        len(row["sources"]),
                    ]
                    for key, row in report["cve_table"].items()
                ],
            )
        heading("Regulatory calendar")
        if not compact:
            regulation_section()
            table(
                ["Next 90 days", "Date", "Milestone"],
                [[m["name"], str(m["date"]), m.get("description", "")] for m in report["calendar"]],
            )
            paragraph("Dates still needed: " + "; ".join(report["needs_dates"]))
        else:
            paragraph("Complete reported dates, milestones and missing-date list are in the attachment.")
        if not email:
            heading("Detection engineering corner")
            table(
                ["Story", "ATT&CK techniques", "Published rules"],
                [
                    [
                        story_ref(i["cluster_id"]),
                        i["attack_techniques"],
                        [link(r["type"], r["url"]) for r in i["detection_refs"]],
                    ]
                    for i in all_items
                    if i["detection_refs"]
                ],
            )
            paragraph(
                "Possible coverage gaps: high/critical stories without a published detection reference. Absence of a link does not establish absence of detection coverage."
            )
            bullet([story_ref(ident) for ident in report["detection_gaps"]])
            heading("Case-study relevance")
            for slug, ids in report["cases"].items():
                bullet(
                    [
                        link(config.case_studies[slug]["title"], config.case_studies[slug]["url"]),
                        *[story_ref(ident) for ident in ids],
                    ]
                )
            if report["business_signals"] is not None:
                heading("Business signals")
                grouped = sorted(report["business_signals"], key=lambda x: (x["sector"], x["region"]))
                bullet([s["rationale"] for s in grouped])
        heading("Content ideas")
        for idea in report["synthesis"]["content_ideas"]:
            paragraph(idea["title"] + " — " + idea["angle"])
            bullet(idea["bullets"])
            bullet(
                [story_ref(i) for i in idea["story_ids"] if i in lookup]
                + [link("Related work", url) for url in idea["related_links"]]
            )
        heading("Watchlist for next week")
        bullet([[w["headline"], w["action"], w["status"]] for w in report["watchlist"]])
        bullet(
            [
                f"{m['date']}: {m['name']} — {m.get('description', '')}"
                for m in report["calendar"]
                if date_within_week(m["date"], report["end"])
            ]
        )
    return blocks


def date_within_week(day, end):
    from datetime import date, datetime, timedelta

    return date.fromisoformat(str(day)) <= datetime.fromisoformat(end).date() + timedelta(days=7)


def environment():
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.filters["safe_url"] = safe_url
    return env


def render_html(config, report, email=False):
    template = environment().get_template("report.html")
    limit, compact = len(report["items"]), False
    while True:
        moved = len(report["items"]) - limit
        result = template.render(
            report=report,
            blocks=sections(config, report, email, limit, compact),
            colors=COLORS,
            email=email,
            moved=moved,
            compact=compact,
        )
        if not email or len(result.encode("utf-8")) < config.settings["email"]["max_html_bytes"]:
            return result
        if limit:
            limit -= 1
        elif not compact:
            compact = True
        else:
            # Even user-edited taxonomy labels can be arbitrarily large. Guarantee
            # the cap while preserving the full attachment and explicit moved count.
            return f'<!doctype html><html><head><meta name="color-scheme" content="light dark"></head><body><p>SecDigest {html.escape(report["kind"])} {html.escape(report["period"])}</p><p>{len(report["items"])} stories moved to the attached complete report to keep this email below the size limit.</p></body></html>'


def md_value(value):
    if isinstance(value, dict):
        text = md_value(value["text"])
        url = safe_url(value["url"])
        return f"[{text}]({url.replace('(', '%28').replace(')', '%29')})" if url else text
    if isinstance(value, list):
        return "; ".join(md_value(v) for v in value)
    return (
        html.escape(str(value))
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("\n", " ")
    )


def render_markdown(config, report, email=False):
    lines = [f"# SecDigest {report['kind']} — {report['period']}", ""]
    for block in sections(config, report):
        kind = block["kind"]
        if kind == "heading":
            lines.append("## " + block["text"])
        elif kind == "paragraph":
            lines.append(md_value(block["text"]))
        elif kind == "list":
            lines.extend("- " + md_value(v) for v in block["values"])
        elif kind == "story":
            i = block["item"]
            metadata = f"**{i['importance'].upper()}** · Priority {i['priority']}"
            relevance = (
                [metadata, "", *[f"**{r['label']}:** {md_value(r['text'])}" for r in block["relevance"]]]
                if email
                else [metadata + " · " + md_value(block["tags"])]
            )
            lines.extend(
                [
                    "### " + md_value(i["headline"]),
                    "",
                    *relevance,
                    "",
                    md_value(i["summary"]),
                    "",
                    "Why it matters: " + md_value(i["importance_rationale"]),
                    "",
                    "Action: " + md_value(i["recommended_action"]),
                    "",
                    md_value(block["cves"]),
                    "",
                    "ATT&CK: " + md_value(block["techniques"]),
                    "",
                    "Detection references: " + md_value(block["detection"]),
                    "",
                    "Detection assessment: " + md_value(i["detection_coverage_note"]),
                    "",
                    "Relevant to your work: " + md_value(block["cases"]),
                    "",
                    "Sources: " + md_value(block["sources"]),
                ]
            )
        elif kind in {"table", "heatmap"}:
            if kind == "heatmap":
                headers = ["Area", *[v.upper() for v in block["levels"]]]
                rows = [
                    [
                        r["name"],
                        *[f"{r['cells'][v]['count']} / {r['cells'][v]['average']}%" for v in block["levels"]],
                    ]
                    for r in block["rows"]
                ]
            else:
                headers, rows = block["headers"], block["rows"]
            lines.extend(
                [
                    "| " + " | ".join(map(md_value, headers)) + " |",
                    "| " + " | ".join("---" for _ in headers) + " |",
                ]
            )
            lines.extend("| " + " | ".join(map(md_value, row)) + " |" for row in rows)
        lines.append("")
    return "\n".join(lines)


def csv_text(config, report):
    output = io.StringIO(newline="")
    rows = []
    for item in report["items"]:
        row = {
            k: item[k] for k in ("cluster_id", "headline", "summary", "importance", "priority", "category")
        }
        for field in ("location_relevance", "industry_relevance", "practice_area_relevance"):
            row.update({f"{field}.{k}": v for k, v in item[field].items()})
        row.update(
            overrides="; ".join(item["overrides"]),
            cves="; ".join(item["cves"]),
            kev=any(d["kev"] for d in item["cve_details"].values()),
            watch_tech="; ".join(t["name"] for t in item["watch_tech"]),
            attack_ids="; ".join(item["attack_techniques"]),
            regulations="; ".join(r["key"] for r in item["regulations"]),
            case_studies="; ".join(item["related_case_studies"]),
            source_urls="; ".join(s["url"] for s in item["sources"]),
            cve_details=json.dumps(item["cve_details"]),
        )
        rows.append(
            {
                k: "'" + value
                if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))
                else value
                for k, value in row.items()
            }
        )
    fields = (
        list(rows[0])
        if rows
        else [
            "cluster_id",
            "headline",
            "summary",
            "importance",
            "priority",
            "category",
            *[
                f"{f}.{key}"
                for f, taxonomy in (
                    ("location_relevance", config.regions),
                    ("industry_relevance", config.industries),
                    ("practice_area_relevance", config.practice_areas),
                )
                for key in taxonomy
            ],
            "overrides",
            "cves",
            "kev",
            "watch_tech",
            "attack_ids",
            "regulations",
            "case_studies",
            "source_urls",
            "cve_details",
        ]
    )
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def archive(config, report):
    target = config.output / report["kind"]
    target.mkdir(parents=True, exist_ok=True)
    data = {
        "md": render_markdown(config, report),
        "html": render_html(config, report),
        "json": json.dumps(report, ensure_ascii=False, indent=2, default=str),
        "csv": csv_text(config, report),
    }
    paths = {}
    for extension, text in data.items():
        path = target / f"{report['period']}.{extension}"
        path.write_text(text, encoding="utf-8", newline="")
        paths[extension] = path
    return paths
