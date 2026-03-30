from __future__ import annotations

import json
from collections import Counter
from typing import Any


def build_report(job_id: int, lookback_hours: int, findings: list[dict[str, Any]], total_alerts: int, relevant_alerts: int) -> tuple[str, str]:
    severity_counts = Counter(item.get("ai_severity") or item.get("local_severity") or "low" for item in findings)
    platform_counts = Counter(item.get("platform") or "other" for item in findings)
    top_hosts = build_top_hosts(findings)
    top_findings = sorted(findings, key=lambda item: (item.get("local_score", 0), item.get("count", 0)), reverse=True)[:10]

    markdown_lines = [
        "# Wazuh AI Analysis Report",
        "",
        f"- Job ID: {job_id}",
        f"- Lookback Window: {lookback_hours}h",
        f"- Total Alerts: {total_alerts}",
        f"- Relevant Alerts: {relevant_alerts}",
        "",
        "## Severity Distribution",
    ]
    markdown_lines.extend([f"- {severity.title()}: {count}" for severity, count in severity_counts.items()])
    markdown_lines.append("")
    markdown_lines.append("## Platforms")
    markdown_lines.extend([f"- {platform.title()}: {count}" for platform, count in platform_counts.items()])
    markdown_lines.append("")
    markdown_lines.append("## Top Hosts")
    markdown_lines.extend(
        [f"- {item['host']}: score {item['top_score']}, findings {item['findings_count']}, alerts {item['alert_count']}" for item in top_hosts]
    )
    markdown_lines.append("")
    markdown_lines.append("## Top Findings")
    for item in top_findings:
        markdown_lines.extend(
            [
                f"### {item['host']} | {item['platform']} | {item.get('event_id') or item.get('rule_id') or 'n/a'}",
                f"- Count: {item['count']}",
                f"- Severity: {item.get('ai_severity') or item.get('local_severity')}",
                f"- Confidence: {item.get('confidence')}",
                f"- Reason: {item.get('reason') or item.get('local_reason') or 'n/a'}",
                f"- Checks: {', '.join(item.get('recommended_checks', []))}",
                "",
            ]
        )

    report_json = json.dumps(
        {
            "job_id": job_id,
            "lookback_hours": lookback_hours,
            "total_alerts": total_alerts,
            "relevant_alerts": relevant_alerts,
            "severity_distribution": dict(severity_counts),
            "platform_distribution": dict(platform_counts),
            "top_hosts": top_hosts,
            "findings": top_findings,
        },
        indent=2,
    )
    return "\n".join(markdown_lines), report_json


def build_top_hosts(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}
    for finding in findings:
        host = finding["host"]
        current = hosts.setdefault(
            host,
            {
                "host": host,
                "findings_count": 0,
                "alert_count": 0,
                "top_score": 0,
            },
        )
        current["findings_count"] += 1
        current["alert_count"] += int(finding.get("count", 0))
        current["top_score"] = max(current["top_score"], int(finding.get("local_score", 0)))
    return sorted(hosts.values(), key=lambda item: (item["top_score"], item["alert_count"]), reverse=True)[:10]
