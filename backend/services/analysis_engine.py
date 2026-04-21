from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from db.database import save_finding_groups
from schemas.types import AnalysisRunRequest
from services.grouping import group_alerts, is_relevant
from services.ollama_client import assess_group
from services.reporting import build_report
from services.scoring import score_group
from services.wazuh_indexer import fetch_alerts, fetch_vulnerabilities, normalize_alert


def run_analysis_job(job_id: int, connection: dict[str, Any], request: AnalysisRunRequest) -> dict[str, Any]:
    raw_alerts = fetch_alerts(
        connection=connection,
        lookback_hours=request.lookback_hours,
        query_size=request.query_size,
        host_filter=request.host_filter,
    )
    vulnerabilities = fetch_vulnerabilities(connection=connection, query_size=500, host_filter=request.host_filter)
    normalized_alerts = [normalize_alert(item) for item in raw_alerts]

    if request.platform_filter:
        normalized_alerts = [
            item for item in normalized_alerts if item["platform"] == request.platform_filter.lower()
        ]

    windows_event_ids = {item.strip() for item in (request.event_ids or []) if item and item.strip()}
    relevant_alerts = [
        item
        for item in normalized_alerts
        if is_relevant(
            item,
            include_noise=request.include_noise,
            windows_event_ids=windows_event_ids or None,
            min_rule_level=int(request.min_rule_level or 0),
        )
    ]

    if request.max_events_per_host and request.max_events_per_host > 0:
        per_host_counter: dict[str, int] = {}
        limited_alerts: list[dict[str, Any]] = []
        for item in relevant_alerts:
            host = str(item.get("host") or "unknown-host")
            used = per_host_counter.get(host, 0)
            if used >= int(request.max_events_per_host):
                continue
            per_host_counter[host] = used + 1
            limited_alerts.append(item)
        relevant_alerts = limited_alerts
    grouped = group_alerts(relevant_alerts)

    findings: list[dict[str, Any]] = []
    for group in grouped:
        scoring = score_group(group)
        finding = {
            **group,
            **scoring,
            "recommended_checks": [],
            "ai_severity": scoring["local_severity"],
            "reason": scoring["local_reason"],
        }
        if request.severity_filter and finding["local_severity"] != request.severity_filter.lower():
            continue
        if request.run_ai:
            assessment = assess_group(connection, finding)
            finding["suspicious"] = assessment.suspicious
            finding["ai_severity"] = assessment.severity
            finding["reason"] = assessment.reason
            finding["recommended_checks"] = assessment.recommended_checks
        findings.append(strip_alert_bucket(finding))

    if request.max_findings and request.max_findings > 0:
        findings = findings[: int(request.max_findings)]

    save_finding_groups(job_id, findings)
    report_markdown, report_json = build_report(
        job_id=job_id,
        lookback_hours=request.lookback_hours,
        findings=findings,
        total_alerts=len(raw_alerts),
        relevant_alerts=len(relevant_alerts),
        vulnerabilities=vulnerabilities,
    )
    return {
        "total_alerts": len(raw_alerts),
        "relevant_alerts": len(relevant_alerts),
        "vulnerabilities_total": len(vulnerabilities),
        "findings": findings,
        "report_markdown": report_markdown,
        "report_json": report_json,
        "completed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


def strip_alert_bucket(finding: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(finding)
    sanitized.pop("alerts", None)
    sanitized["sample"] = {
        key: value
        for key, value in sanitized.get("sample", {}).items()
        if key in {"host", "platform", "event_id", "rule_id", "rule_description", "target_user", "logon_type", "process", "groups", "location"}
    }
    return sanitized
