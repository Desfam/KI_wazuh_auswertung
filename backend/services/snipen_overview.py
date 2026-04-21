"""Host overview builder for Snipen threat hunting."""
from __future__ import annotations

from collections import Counter

from schemas.types import SnipenEvent, SnipenHostOverview
from services.snipen_timeline import build_timeline


def build_host_overview(
    host: str,
    hours: int,
    events: list[SnipenEvent],
    num_timeline_buckets: int = 24,
) -> SnipenHostOverview:
    """
    Aggregate a flat list of SnipenEvents into a structured host overview
    including severity distribution, top counters and a timeline.
    No DB, no I/O – pure computation.
    """
    if not events:
        return SnipenHostOverview(
            host=host,
            hours=hours,
            total_events=0,
            high_alerts=0,
            critical_alerts=0,
            timeline=build_timeline([], hours=hours, num_buckets=num_timeline_buckets),
        )

    event_id_counter: Counter[str] = Counter()
    rule_id_counter: Counter[str] = Counter()
    process_counter: Counter[str] = Counter()
    user_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    desc_counter: Counter[str] = Counter()

    severity_distribution: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    high_alerts = 0
    critical_alerts = 0
    last_activity: str | None = None

    for ev in events:
        s = ev.smart
        level = s.rule_level or 0

        # Severity bucketing: mirrors the thresholds used in the UI
        if level >= 15:
            critical_alerts += 1
            severity_distribution["critical"] += 1
        elif level >= 12:
            high_alerts += 1
            severity_distribution["high"] += 1
        elif level >= 7:
            severity_distribution["medium"] += 1
        else:
            severity_distribution["low"] += 1

        if s.event_id:
            event_id_counter[s.event_id] += 1
        if s.rule_id:
            rule_id_counter[s.rule_id] += 1
        if s.process and s.process not in ("-", ""):
            basename = s.process.replace("\\", "/").split("/")[-1]
            if basename:
                process_counter[basename] += 1
        if s.user and s.user not in ("-", ""):
            user_counter[s.user] += 1
        if s.ip_address and s.ip_address not in ("-", "::1", "127.0.0.1", ""):
            ip_counter[s.ip_address] += 1
        if s.rule_description:
            desc_counter[s.rule_description] += 1

        # Track latest event timestamp
        if s.timestamp and (last_activity is None or s.timestamp > last_activity):
            last_activity = s.timestamp

    timeline = build_timeline(events, hours=hours, num_buckets=num_timeline_buckets)

    return SnipenHostOverview(
        host=host,
        hours=hours,
        total_events=len(events),
        high_alerts=high_alerts,
        critical_alerts=critical_alerts,
        last_activity=last_activity,
        top_event_ids=[eid for eid, _ in event_id_counter.most_common(10)],
        top_rule_ids=[rid for rid, _ in rule_id_counter.most_common(10)],
        top_processes=[p for p, _ in process_counter.most_common(10)],
        top_users=[u for u, _ in user_counter.most_common(10)],
        top_ips=[ip for ip, _ in ip_counter.most_common(10)],
        top_rule_descriptions=[d for d, _ in desc_counter.most_common(15)],
        severity_distribution=severity_distribution,
        timeline=timeline,
    )
