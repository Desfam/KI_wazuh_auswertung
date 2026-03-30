from __future__ import annotations

from collections import defaultdict
from typing import Any

RELEVANT_WINDOWS_EVENT_IDS = {"4625", "4688", "7045", "4720", "4728", "4732", "1102"}
RELEVANT_LINUX_KEYWORDS = {
    "sshd",
    "authentication_failed",
    "invalid_login",
    "sudo",
    "pam",
    "useradd",
    "usermod",
    "groupadd",
    "cron",
}

BENIGN_WINDOWS_PATTERNS = {
    ("4625", "local service", "5", "svchost.exe"),
}


def is_relevant(
    alert: dict[str, Any],
    include_noise: bool = False,
    windows_event_ids: set[str] | None = None,
    min_rule_level: int = 0,
) -> bool:
    if int(alert.get("rule_level") or 0) < int(min_rule_level or 0):
        return False

    effective_windows_event_ids = windows_event_ids or RELEVANT_WINDOWS_EVENT_IDS

    if include_noise:
        return alert["platform"] in {"windows", "linux"}

    if alert["platform"] == "windows":
        if alert.get("event_id") not in effective_windows_event_ids:
            return False
        signature = (
            (alert.get("event_id") or "").lower(),
            (alert.get("target_user") or "").lower(),
            (alert.get("logon_type") or "").lower(),
            (alert.get("process") or "").lower(),
        )
        return signature not in BENIGN_WINDOWS_PATTERNS

    if alert["platform"] == "linux":
        searchable = " ".join(
            [
                *(alert.get("groups") or []),
                str(alert.get("decoder") or ""),
                str(alert.get("rule_description") or ""),
                str(alert.get("location") or ""),
                str(alert.get("linux_type") or ""),
            ]
        ).lower()
        return any(keyword in searchable for keyword in RELEVANT_LINUX_KEYWORDS)

    return False


def group_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        buckets[build_group_key(alert)].append(alert)

    groups: list[dict[str, Any]] = []
    for group_key, bucket in buckets.items():
        first = bucket[0]
        timestamps = [item.get("timestamp") for item in bucket if item.get("timestamp")]
        groups.append(
            {
                "host": first["host"],
                "platform": first["platform"],
                "event_id": first.get("event_id"),
                "rule_id": first.get("rule_id"),
                "rule_description": first.get("rule_description"),
                "count": len(bucket),
                "group_key": group_key,
                "first_seen": min(timestamps) if timestamps else None,
                "last_seen": max(timestamps) if timestamps else None,
                "sample": first,
                "alerts": bucket,
            }
        )
    return sorted(groups, key=lambda item: item["count"], reverse=True)


def build_group_key(alert: dict[str, Any]) -> str:
    if alert["platform"] == "windows":
        parts = [
            alert.get("host") or "unknown-host",
            alert.get("event_id") or "unknown-event",
            alert.get("rule_id") or "unknown-rule",
            alert.get("target_user") or "unknown-user",
            alert.get("logon_type") or "unknown-logon",
            alert.get("process") or "unknown-process",
        ]
        return "|".join(parts)

    if alert["platform"] == "linux":
        parts = [
            alert.get("host") or "unknown-host",
            alert.get("rule_id") or "unknown-rule",
            ",".join(alert.get("groups") or []),
            alert.get("location") or "unknown-location",
        ]
        return "|".join(parts)

    return "|".join(
        [
            alert.get("host") or "unknown-host",
            alert.get("platform") or "unknown-platform",
            alert.get("rule_id") or "unknown-rule",
        ]
    )
