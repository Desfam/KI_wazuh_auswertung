"""Host Baseline Service – compute, store and query host behavior baselines.

Architecture:
  host_baseline_snapshots  – Top-N aggregated view per host per time window.
  host_baseline_features   – Per-feature frequency tracker (upserted each run).
  host_baseline_deviations – New / anomalous features detected during computation.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from db.database import get_connection, utc_now_iso
from schemas.types import (
    BaselineDeviation,
    BaselineDiff,
    BaselineFeature,
    BaselineFeatureItem,
    BaselineSnapshot,
    BaselineSummary,
)
from services.snipen_profiles import get_profile_for_host
from services.behavior_analyzer import analyze_behavior, BehaviorResult
from services.classification_engine import classify_from_details, classify_deviation


# ── Constants ─────────────────────────────────────────────────────────────────

_TOP_N = 15          # how many items per top-N list
_SPIKE_RATIO = 3.0   # count must be >3× previous to trigger volume_spike
_MIN_SEEN = 3        # minimum count before stability matters for spike detection

# ── Known-Good / Noise Filter ─────────────────────────────────────────────────

# Core Windows processes that are never "new" or suspicious by themselves
_KNOWN_SYSTEM_PROCESSES: frozenset[str] = frozenset({
    "lsass.exe", "svchost.exe", "winlogon.exe", "explorer.exe",
    "services.exe", "smss.exe", "csrss.exe", "wininit.exe",
    "spoolsv.exe", "taskhostw.exe", "dwm.exe", "fontdrvhost.exe",
    "runtimebroker.exe", "searchindexer.exe", "wmiprvse.exe",
    "audiodg.exe", "conhost.exe", "dllhost.exe", "msdtc.exe",
    "ntoskrnl.exe", "system", "registry", "memory compression",
    "securityhealthsystray.exe", "sihost.exe", "ctfmon.exe",
    "taskmgr.exe", "sdelete.exe", "vssvc.exe", "msiexec.exe",
    "wuauclt.exe", "trustedinstaller.exe",
})

# System accounts / virtual users that are never "new users"
_KNOWN_SYSTEM_USER_PREFIXES: tuple[str, ...] = (
    "dwm-", "umfd-", "window manager\\dwm-", "font driver host\\umfd-",
)
_KNOWN_SYSTEM_USERS: frozenset[str] = frozenset({
    "system", "local service", "network service",
    "anonymous logon", "iis apppool", "window manager",
    "font driver host", "nt authority\\system",
    "nt authority\\local service", "nt authority\\network service",
})

# Event IDs that are pure operational noise — never worth flagging
_NOISE_EVENT_IDS: frozenset[str] = frozenset({
    "16384",   # Microsoft-Windows-Security-SPP (software licensing)
    "10016",   # DCOM DistributedCOM permission warning (harmless by design)
    "4608",    # Windows starting up
    "4609",    # Windows shutting down
    "4800",    # Workstation locked
    "4801",    # Workstation unlocked
    "6005",    # Event log service started
    "6006",    # Event log service stopped
    "6013",    # System uptime
    "6008",    # Unexpected shutdown (informational)
    "41",      # System rebooted without clean shutdown — operational, not threat
    "1074",    # System shutdown / restart
    "7036",    # Service state change (running/stopped) — too noisy
})


def _is_known_system_process(name: str) -> bool:
    return name.lower() in _KNOWN_SYSTEM_PROCESSES


def _is_known_system_user(name: str) -> bool:
    lo = name.lower()
    if lo in _KNOWN_SYSTEM_USERS:
        return True
    return any(lo.startswith(prefix) for prefix in _KNOWN_SYSTEM_USER_PREFIXES)


def _is_noise_event(event_id: str) -> bool:
    return str(event_id) in _NOISE_EVENT_IDS


# ── Internal helpers ──────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _to_items(counter: Counter, top_n: int = _TOP_N) -> list[BaselineFeatureItem]:
    return [BaselineFeatureItem(key=k, count=v) for k, v in counter.most_common(top_n)]


def _items_to_json(items: list[BaselineFeatureItem]) -> str:
    return json.dumps([{"key": i.key, "count": i.count} for i in items], ensure_ascii=False)


def _json_to_items(raw: str | None) -> list[BaselineFeatureItem]:
    if not raw:
        return []
    try:
        return [BaselineFeatureItem(**d) for d in json.loads(raw)]
    except Exception:
        return []


def _hour_bucket(ts_str: str | None) -> str | None:
    """Return ISO hour string like '2026-04-14T15' from an event timestamp."""
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H")
    except Exception:
        return None


# ── Risk Scoring ──────────────────────────────────────────────────────────────

# High-risk processes: regardless of profile, these raise the bar
_HIGH_RISK_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "psexec.exe", "nc.exe", "ncat.exe",
    "netcat.exe", "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "cmstp.exe", "installutil.exe",
}

# Profile: which processes are *expected* per risk_tolerance
_EXPECTED_BY_TOLERANCE: dict[str, set[str]] = {
    "high":   {"powershell.exe", "cmd.exe", "python.exe", "ssh.exe", "git.exe", "code.exe", "docker.exe"},
    "medium": {"cmd.exe"},
    "low":    set(),
}

# Event IDs that are always high risk
_HIGH_RISK_EVENT_IDS = {"7045", "1102", "4697", "4719", "4698", "4702"}
_MEDIUM_RISK_EVENT_IDS = {"4625", "4648", "4672", "4720", "4726", "4728", "4732", "4740"}

# Deviation type base scores
_DEVIATION_BASE_SCORE: dict[str, int] = {
    "new_service":          60,
    "new_process":          35,
    "new_user":             40,
    "new_ip":               20,
    "new_event_id":         15,
    "new_event_family":     10,
    "volume_spike":         30,
    "suspicious_behavior":  50,   # known entity, abnormal execution
}

_RISK_LEVEL_THRESHOLDS = [
    (75, "critical"),
    (55, "high"),
    (35, "medium"),
    (15, "low"),
    (0,  "info"),
]


def _risk_level(score: int) -> str:
    for threshold, level in _RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "info"


def _score_deviation(
    deviation_type: str,
    feature_type: str,
    feature_key: str,
    profile_risk_tolerance: str | None,
    details: dict[str, Any],
    behavior_ctx: dict[str, Any] | None = None,
) -> tuple[int, str, float, list[str]]:
    """
    Return (risk_score 0-100, reason, confidence, behavior_flags).
    Combines: deviation base + profile context + key-specific rules + behavior analysis.
    """
    score = _DEVIATION_BASE_SCORE.get(deviation_type, 10)
    reasons: list[str] = []
    confidence = 0.65

    key_lower = feature_key.lower()

    # ── Process-specific scoring ──────────────────────────
    if feature_type == "process":
        if key_lower in _HIGH_RISK_PROCESSES:
            score += 40
            reasons.append(f"{feature_key} is a known high-risk tool")
            confidence = 0.92
        elif key_lower in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"):
            tol = profile_risk_tolerance or "medium"
            if key_lower not in _EXPECTED_BY_TOLERANCE.get(tol, set()):
                score += 25
                reasons.append(f"{feature_key} is unexpected for profile risk tolerance '{tol}'")
                confidence = 0.82
            else:
                score -= 10
                reasons.append(f"{feature_key} expected for this profile")
                confidence = 0.55

    # ── Event-ID–specific scoring ─────────────────────────
    elif feature_type == "event_id":
        if feature_key in _HIGH_RISK_EVENT_IDS:
            score += 30
            reasons.append(f"Event ID {feature_key} is security-critical")
            confidence = 0.88
        elif feature_key in _MEDIUM_RISK_EVENT_IDS:
            score += 10
            reasons.append(f"Event ID {feature_key} is notable")
            confidence = 0.72

    # ── Service scoring ───────────────────────────────────
    elif feature_type == "service_name":
        if any(x in key_lower for x in ("svc", "update", "install", "agent", "remote", "rdp", "vnc")):
            score += 15
            reasons.append(f"New service '{feature_key}' matches suspicious pattern")
            confidence = 0.75
        else:
            score += 5

    # ── Volume spike ──────────────────────────────────────
    elif deviation_type == "volume_spike":
        ratio = details.get("ratio", 1.0)
        if ratio >= 10:
            score += 25
            reasons.append(f"Volume {ratio:.1f}× baseline – extreme spike")
            confidence = 0.90
        elif ratio >= 5:
            score += 15
            reasons.append(f"Volume {ratio:.1f}× baseline – large spike")
            confidence = 0.80
        else:
            reasons.append(f"Volume {ratio:.1f}× baseline")
            confidence = 0.70

    # ── Profile risk-tolerance modifier ──────────────────
    if profile_risk_tolerance == "low":
        score += 10   # strict profile = any deviation is more concerning
    elif profile_risk_tolerance == "high":
        score -= 8    # permissive profile = slightly less alarming

    # ── Behavior context boost ────────────────────────────────────────────────
    behavior_flags: list[str] = []
    if behavior_ctx and feature_type == "process":
        bres: BehaviorResult = analyze_behavior(
            process=feature_key,
            command_line=behavior_ctx.get("cmd"),
            parent_process=behavior_ctx.get("parent"),
        )
        if bres.is_suspicious:
            score += bres.score_delta
            behavior_flags = bres.flags
            reasons.append(f"suspicious execution: {'; '.join(bres.flags[:2])}")
            confidence = max(confidence, 0.80)

    score = max(0, min(100, score))
    reason = "; ".join(reasons) if reasons else f"New {feature_type}: {feature_key}"
    return score, reason, round(confidence, 2), behavior_flags


# ── DB row converters ─────────────────────────────────────────────────────────

def _row_to_snapshot(row: Any) -> BaselineSnapshot:
    keys = set(row.keys())
    return BaselineSnapshot(
        id=row["id"],
        host=row["host"],
        computed_at=row["computed_at"],
        window_hours=row["window_hours"],
        profile_id=row["profile_id"],
        total_events=row["total_events"],
        high_alerts=row["high_alerts"],
        critical_alerts=row["critical_alerts"],
        top_event_ids=_json_to_items(row["top_event_ids_json"]),
        top_rule_ids=_json_to_items(row["top_rule_ids_json"]),
        top_processes=_json_to_items(row["top_processes_json"]),
        top_users=_json_to_items(row["top_users_json"]),
        top_ips=_json_to_items(row["top_ips_json"]),
        top_event_families=_json_to_items(row["top_event_families_json"]),
        event_volume_per_hour=json.loads(row["event_volume_per_hour_json"] or "{}"),
        notes=json.loads(row["notes_json"] or "[]"),
        deviation_count=row["deviation_count"] if "deviation_count" in keys else 0,
    )


def _row_to_feature(row: Any) -> BaselineFeature:
    return BaselineFeature(
        id=row["id"],
        host=row["host"],
        feature_type=row["feature_type"],
        feature_key=row["feature_key"],
        count_seen=row["count_seen"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        stability_score=row["stability_score"],
        is_expected=bool(row["is_expected"]),
        notes=row["notes"],
    )


def _row_to_deviation(row: Any) -> BaselineDeviation:
    keys = set(row.keys())
    return BaselineDeviation(
        id=row["id"],
        host=row["host"],
        detected_at=row["detected_at"],
        feature_type=row["feature_type"],
        feature_key=row["feature_key"],
        deviation_type=row["deviation_type"],
        severity_hint=row["severity_hint"],
        risk_score=row["risk_score"] if "risk_score" in keys else 0,
        risk_level=row["risk_level"] if "risk_level" in keys else "info",
        reason=row["reason"] if "reason" in keys else "",
        confidence=row["confidence"] if "confidence" in keys else 0.0,
        details=json.loads(row["details_json"] or "{}"),
        resolved=bool(row["resolved"]),
        resolved_at=row["resolved_at"],
        final_classification=row["final_classification"] if "final_classification" in keys else "unknown",
    )


# ── Public read helpers ───────────────────────────────────────────────────────

def get_latest_snapshot(host: str) -> BaselineSnapshot | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM host_baseline_snapshots WHERE host = ? ORDER BY computed_at DESC LIMIT 1",
            (host,),
        ).fetchone()
    return _row_to_snapshot(row) if row else None


def list_snapshots(host: str, limit: int = 10) -> list[BaselineSnapshot]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT s.*,
                   (SELECT COUNT(*) FROM host_baseline_deviations d
                    WHERE d.host = s.host AND d.detected_at = s.computed_at) AS deviation_count
            FROM host_baseline_snapshots s
            WHERE s.host = ?
            ORDER BY s.computed_at DESC
            LIMIT ?
            """,
            (host, limit),
        ).fetchall()
    return [_row_to_snapshot(r) for r in rows]


def get_features(host: str, feature_type: str | None = None) -> list[BaselineFeature]:
    with get_connection() as conn:
        if feature_type:
            rows = conn.execute(
                "SELECT * FROM host_baseline_features WHERE host = ? AND feature_type = ? ORDER BY count_seen DESC",
                (host, feature_type),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM host_baseline_features WHERE host = ? ORDER BY feature_type, count_seen DESC",
                (host,),
            ).fetchall()
    return [_row_to_feature(r) for r in rows]


def get_deviations(host: str, unresolved_only: bool = True) -> list[BaselineDeviation]:
    with get_connection() as conn:
        if unresolved_only:
            rows = conn.execute(
                "SELECT * FROM host_baseline_deviations WHERE host = ? AND resolved = 0 ORDER BY risk_score DESC, detected_at DESC",
                (host,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM host_baseline_deviations WHERE host = ? ORDER BY detected_at DESC LIMIT 200",
                (host,),
            ).fetchall()
    return [_row_to_deviation(r) for r in rows]


def resolve_deviation(deviation_id: int) -> bool:
    now = _utc_now()
    with get_connection() as conn:
        result = conn.execute(
            "UPDATE host_baseline_deviations SET resolved = 1, resolved_at = ? WHERE id = ?",
            (now, deviation_id),
        )
    return bool(result.rowcount)


def get_baseline_summary(host: str) -> BaselineSummary | None:
    """Return a compact summary suitable for AI prompts and UI cards."""
    snap = get_latest_snapshot(host)
    if snap is None:
        return None
    deviations = get_deviations(host, unresolved_only=True)
    days = max(snap.window_hours / 24.0, 1)
    top_devs = sorted(deviations, key=lambda d: -d.risk_score)[:5]
    return BaselineSummary(
        host=host,
        computed_at=snap.computed_at,
        window_hours=snap.window_hours,
        total_events=snap.total_events,
        daily_avg_events=round(snap.total_events / days, 1),
        high_alerts=snap.high_alerts,
        critical_alerts=snap.critical_alerts,
        top_processes=[i.key for i in snap.top_processes[:8]],
        top_event_ids=[i.key for i in snap.top_event_ids[:8]],
        top_users=[i.key for i in snap.top_users[:6]],
        top_event_families=[i.key for i in snap.top_event_families[:6]],
        open_deviations=len(deviations),
        deviation_types=list({d.deviation_type for d in deviations}),
        top_deviations=[
            {
                "type": d.deviation_type,
                "key": d.feature_key,
                "risk_score": d.risk_score,
                "risk_level": d.risk_level,
                "reason": d.reason,
            }
            for d in top_devs
        ],
    )


def get_baseline_diff(host: str) -> BaselineDiff:
    """
    Compare stored baseline features against the latest snapshot counts to
    produce a human-readable diff (new features, volume spike, open deviations).
    """
    now = _utc_now()
    snap = get_latest_snapshot(host)
    deviations = get_deviations(host, unresolved_only=True)

    deviation_by_type: dict[str, list[str]] = {}
    for d in deviations:
        deviation_by_type.setdefault(d.deviation_type, []).append(d.feature_key)

    # Volume spike: check if latest snapshot has a high event count relative to previous
    volume_spike = False
    volume_ratio = 0.0
    snaps = list_snapshots(host, limit=3)
    if len(snaps) >= 2:
        latest_vol = snaps[0].total_events
        prev_vol = snaps[1].total_events
        if prev_vol > 0:
            volume_ratio = round(latest_vol / prev_vol, 2)
            if volume_ratio >= _SPIKE_RATIO:
                volume_spike = True

    top_risk = sorted(deviations, key=lambda d: -d.risk_score)[:5]

    return BaselineDiff(
        host=host,
        computed_at=snap.computed_at if snap else now,
        new_processes=deviation_by_type.get("new_process", []),
        new_users=deviation_by_type.get("new_user", []),
        new_services=deviation_by_type.get("new_service", []),
        new_ips=deviation_by_type.get("new_ip", []),
        new_event_ids=deviation_by_type.get("new_event_id", []),
        new_event_families=deviation_by_type.get("new_event_family", []),
        volume_spike=volume_spike,
        volume_ratio=volume_ratio,
        open_deviations=len(deviations),
        top_risk_deviations=[
            {
                "type": d.deviation_type,
                "key": d.feature_key,
                "risk_score": d.risk_score,
                "risk_level": d.risk_level,
                "reason": d.reason,
                "confidence": d.confidence,
            }
            for d in top_risk
        ],
    )


# ── Deviation detection ───────────────────────────────────────────────────────

_DEVIATION_SEVERITY: dict[str, str] = {
    "new_process":          "medium",
    "new_user":             "medium",
    "new_service":          "high",
    "new_event_id":         "info",
    "new_ip":               "info",
    "new_event_family":     "info",
    "volume_spike":         "medium",
    "suspicious_behavior":  "high",
}


def _maybe_log_deviation(
    conn: Any,
    host: str,
    feature_type: str,
    feature_key: str,
    deviation_type: str,
    details: dict[str, Any],
    now: str,
    profile_risk_tolerance: str | None = None,
    behavior_ctx: dict[str, Any] | None = None,
) -> None:
    """Insert a deviation (with risk score) only if one doesn't already exist unresolved."""
    existing = conn.execute(
        """
        SELECT id FROM host_baseline_deviations
        WHERE host = ? AND feature_type = ? AND feature_key = ?
          AND deviation_type = ? AND resolved = 0
        """,
        (host, feature_type, feature_key, deviation_type),
    ).fetchone()
    if existing:
        return

    severity = _DEVIATION_SEVERITY.get(deviation_type, "info")
    risk_score, reason, confidence, behavior_flags = _score_deviation(
        deviation_type, feature_type, feature_key, profile_risk_tolerance, details,
        behavior_ctx=behavior_ctx,
    )
    risk_lv = _risk_level(risk_score)

    stored_details = {
        **details,
        "is_known": False,   # this is a NEW entity deviation
    }
    if behavior_flags:
        stored_details["behavior_flags"] = behavior_flags

    final_cls = classify_from_details(
        deviation_type=deviation_type,
        risk_score=risk_score,
        is_resolved=False,
        details=stored_details,
        feature_key=feature_key,
    )

    conn.execute(
        """
        INSERT INTO host_baseline_deviations
            (host, detected_at, feature_type, feature_key, deviation_type,
             severity_hint, risk_score, risk_level, reason, confidence, details_json,
             final_classification)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            host, now, feature_type, feature_key, deviation_type,
            severity, risk_score, risk_lv, reason, confidence,
            json.dumps(stored_details, ensure_ascii=False),
            final_cls,
        ),
    )


def _maybe_log_behavior_deviation(
    conn: Any,
    host: str,
    feature_type: str,
    feature_key: str,
    behavior_flags: list[str],
    behavior_score_delta: int,
    now: str,
    profile_risk_tolerance: str | None = None,
) -> None:
    """Log a suspicious_behavior deviation for a KNOWN (baseline) entity with bad execution context.

    This fires even when the entity itself is not new — implementing the core principle:
        Baseline ≠ whitelist.  Known entity + suspicious execution = alert.
    """
    existing = conn.execute(
        """
        SELECT id FROM host_baseline_deviations
        WHERE host = ? AND feature_type = ? AND feature_key = ?
          AND deviation_type = 'suspicious_behavior' AND resolved = 0
        """,
        (host, feature_type, feature_key),
    ).fetchone()
    if existing:
        return

    base = _DEVIATION_BASE_SCORE.get("suspicious_behavior", 50)
    score = max(0, min(100, base + behavior_score_delta))
    if profile_risk_tolerance == "low":
        score = min(100, score + 10)
    elif profile_risk_tolerance == "high":
        score = max(0, score - 8)

    risk_lv = _risk_level(score)
    reason = f"Known {feature_type} with suspicious execution: {'; '.join(behavior_flags[:3])}"

    conn.execute(
        """
        INSERT INTO host_baseline_deviations
            (host, detected_at, feature_type, feature_key, deviation_type,
             severity_hint, risk_score, risk_level, reason, confidence, details_json,
             final_classification)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            host, now, feature_type, feature_key, "suspicious_behavior",
            "high", score, risk_lv, reason, 0.75,
            json.dumps({
                "is_known": True,
                "behavior_flags": behavior_flags,
                "behavior_score_delta": behavior_score_delta,
            }, ensure_ascii=False),
            "known_but_suspicious",   # always known_but_suspicious for behavior deviations
        ),
    )


def _upsert_feature_and_detect(
    conn: Any,
    host: str,
    feature_type: str,
    feature_key: str,
    new_count: int,
    now: str,
    profile_risk_tolerance: str | None = None,
    behavior_ctx: dict[str, Any] | None = None,
) -> None:
    """Upsert a baseline feature. If it's new, also log a scored deviation.
    For KNOWN entities: check if execution behavior is suspicious and log separately.
    """
    existing = conn.execute(
        "SELECT * FROM host_baseline_features WHERE host = ? AND feature_type = ? AND feature_key = ?",
        (host, feature_type, feature_key),
    ).fetchone()

    if existing is None:
        conn.execute(
            """
            INSERT INTO host_baseline_features
                (host, feature_type, feature_key, count_seen, first_seen, last_seen, stability_score)
            VALUES (?, ?, ?, ?, ?, ?, 0.0)
            """,
            (host, feature_type, feature_key, new_count, now, now),
        )
        # Skip deviation logging for known-good / noise items
        if feature_type == "process" and _is_known_system_process(feature_key):
            return
        if feature_type == "user" and _is_known_system_user(feature_key):
            return
        if feature_type == "event_id" and _is_noise_event(feature_key):
            return
        if feature_type in {"process", "user", "service_name", "event_id", "ip", "event_family"}:
            deviation_map = {
                "process":       "new_process",
                "user":          "new_user",
                "service_name":  "new_service",
                "event_id":      "new_event_id",
                "ip":            "new_ip",
                "event_family":  "new_event_family",
            }
            _maybe_log_deviation(
                conn, host, feature_type, feature_key,
                deviation_map[feature_type],
                {"count": new_count, "first_seen": now},
                now,
                profile_risk_tolerance,
                behavior_ctx=behavior_ctx if feature_type == "process" else None,
            )
    else:
        prev_count = existing["count_seen"]
        new_total = prev_count + new_count
        stability = min(1.0, new_total / 50.0)
        conn.execute(
            """
            UPDATE host_baseline_features
               SET count_seen = ?, last_seen = ?, stability_score = ?
             WHERE host = ? AND feature_type = ? AND feature_key = ?
            """,
            (new_total, now, stability, host, feature_type, feature_key),
        )
        # Volume spike detection
        if feature_type in {"event_id", "process"} and prev_count > _MIN_SEEN:
            if new_count > prev_count * _SPIKE_RATIO:
                _maybe_log_deviation(
                    conn, host, feature_type, feature_key,
                    "volume_spike",
                    {"previous_count": prev_count, "new_count": new_count, "ratio": round(new_count / max(prev_count, 1), 1)},
                    now,
                    profile_risk_tolerance,
                )
        # Behavior anomaly on KNOWN entity (Baseline ≠ whitelist)
        if feature_type == "process" and behavior_ctx:
            bres: BehaviorResult = analyze_behavior(
                process=feature_key,
                command_line=behavior_ctx.get("cmd"),
                parent_process=behavior_ctx.get("parent"),
            )
            if bres.is_suspicious:
                _maybe_log_behavior_deviation(
                    conn, host, feature_type, feature_key,
                    bres.flags, bres.score_delta,
                    now, profile_risk_tolerance,
                )


# ── Core computation ──────────────────────────────────────────────────────────

def compute_baseline(
    host: str,
    connection: dict[str, Any],
    window_hours: int = 168,
) -> BaselineSnapshot:
    """
    Fetch events for `host`, aggregate Top-N counters, persist snapshot + features,
    detect deviations with risk scores, and return the new snapshot.
    """
    from services.snipen_service import get_host_events  # local to avoid circular import

    events = get_host_events(connection, host, hours=window_hours, limit=5000)
    now = _utc_now()

    # Aggregate counters
    event_id_c: Counter = Counter()
    rule_id_c: Counter = Counter()
    process_c: Counter = Counter()
    user_c: Counter = Counter()
    ip_c: Counter = Counter()
    family_c: Counter = Counter()
    service_c: Counter = Counter()
    hourly_c: Counter = Counter()

    # Behavior context per process: track first non-empty cmd/parent seen
    process_behavior_ctx: dict[str, dict[str, str | None]] = {}

    total = len(events)
    high_alerts = 0
    critical_alerts = 0

    for evt in events:
        s = evt.smart
        if s.event_id:
            if not _is_noise_event(s.event_id):
                event_id_c[s.event_id] += 1
        if s.rule_id:
            rule_id_c[s.rule_id] += 1
        if s.process and not _is_known_system_process(s.process):
            proc_key = s.process.lower()
            process_c[proc_key] += 1
            # Collect behavior context (keep any non-empty cmd/parent for later analysis)
            if s.command_line or s.parent_process:
                ctx = process_behavior_ctx.setdefault(proc_key, {"cmd": None, "parent": None})
                if s.command_line and not ctx["cmd"]:
                    ctx["cmd"] = s.command_line
                if s.parent_process and not ctx["parent"]:
                    ctx["parent"] = s.parent_process
        if s.user and not _is_known_system_user(s.user):
            user_c[s.user] += 1
        if s.ip_address:
            ip_c[s.ip_address] += 1
        for grp in (s.groups or []):
            family_c[grp] += 1
        if s.service_name:
            service_c[s.service_name.lower()] += 1
        level = s.rule_level or 0
        if level >= 12:
            critical_alerts += 1
        elif level >= 9:
            high_alerts += 1
        bucket = _hour_bucket(s.timestamp)
        if bucket:
            hourly_c[bucket] += 1

    top_event_ids = _to_items(event_id_c)
    top_rule_ids = _to_items(rule_id_c)
    top_processes = _to_items(process_c)
    top_users = _to_items(user_c)
    top_ips = _to_items(ip_c)
    top_families = _to_items(family_c)

    profile = get_profile_for_host(host)
    profile_id = profile.id if profile else None
    risk_tolerance = profile.risk_tolerance if profile else None

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO host_baseline_snapshots (
                host, computed_at, window_hours, profile_id,
                total_events, high_alerts, critical_alerts,
                top_event_ids_json, top_rule_ids_json, top_processes_json,
                top_users_json, top_ips_json, top_event_families_json,
                event_volume_per_hour_json, notes_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                host, now, window_hours, profile_id,
                total, high_alerts, critical_alerts,
                _items_to_json(top_event_ids),
                _items_to_json(top_rule_ids),
                _items_to_json(top_processes),
                _items_to_json(top_users),
                _items_to_json(top_ips),
                _items_to_json(top_families),
                json.dumps(dict(hourly_c), ensure_ascii=False),
                "[]",
            ),
        )
        snapshot_id = cursor.lastrowid

        for eid, cnt in event_id_c.items():
            _upsert_feature_and_detect(conn, host, "event_id", eid, cnt, now, risk_tolerance)
        for proc, cnt in process_c.items():
            _upsert_feature_and_detect(
                conn, host, "process", proc, cnt, now, risk_tolerance,
                behavior_ctx=process_behavior_ctx.get(proc),
            )
        for usr, cnt in user_c.items():
            _upsert_feature_and_detect(conn, host, "user", usr, cnt, now, risk_tolerance)
        for ip, cnt in ip_c.items():
            _upsert_feature_and_detect(conn, host, "ip", ip, cnt, now, risk_tolerance)
        for svc, cnt in service_c.items():
            _upsert_feature_and_detect(conn, host, "service_name", svc, cnt, now, risk_tolerance)
        for fam, cnt in family_c.items():
            _upsert_feature_and_detect(conn, host, "event_family", fam, cnt, now, risk_tolerance)

    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM host_baseline_snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
    return _row_to_snapshot(row)

