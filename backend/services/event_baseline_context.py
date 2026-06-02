"""
Event Baseline Context Bridge
==============================
Given a normalised Wazuh event + an optional base knowledge evaluation,
enrich it with host baseline context sourced from the existing
baseline_service (host_baseline_snapshots / host_baseline_features /
host_baseline_deviations).

This module is the bridge between the Event Evaluation Engine and the
Host Baseline Service.  It does NOT duplicate baseline storage tables.

Usage::

    from services.event_baseline_context import get_event_baseline_context

    ctx = get_event_baseline_context(event, base_evaluation)

Output shape — see _EMPTY_CONTEXT for all keys.
"""
from __future__ import annotations

from typing import Any

# ── High-risk event IDs that must NEVER have risk reduced ────────────────────
_HIGH_RISK_EIDS: frozenset[str] = frozenset({
    "7045", "1102", "4697", "4719", "4698", "4702",
})

# ── Rare threshold — feature seen fewer times than this is considered rare ────
_RARE_THRESHOLD = 3


# ── Empty context skeleton ────────────────────────────────────────────────────

def _empty_ctx(host: str | None, warning: str | None = None) -> dict[str, Any]:
    return {
        "host":                   host,
        "baseline_available":     False,
        "snapshot": {
            "computed_at":    None,
            "window_hours":   None,
            "total_events":   None,
            "high_alerts":    None,
            "critical_alerts": None,
        },
        "known_features": {
            "event_id":     None,
            "process":      None,
            "user":         None,
            "ip":           None,
            "service_name": None,
            "event_family": None,
        },
        "feature_counts": {
            "event_id":     None,
            "process":      None,
            "user":         None,
            "ip":           None,
            "service_name": None,
            "event_family": None,
        },
        "new_features":            [],
        "rare_features":           [],
        "open_deviations":         0,
        "top_risk_deviations":     [],
        "baseline_candidate":      False,
        "baseline_candidate_reason": None,
        "host_risk_modifier":      1.0,
        "host_context_reason":     "No baseline available for this host.",
        "warnings":                [warning] if warning else [],
    }


# ── Event field extraction ────────────────────────────────────────────────────

def _extract_event_fields(event: dict[str, Any]) -> dict[str, str | None]:
    """Pull the fields we want to compare against baseline features."""
    data   = event.get("data") or {}
    win    = data.get("win") or {}
    # Handle both lowercase 'eventdata' and camelCase 'eventData'
    evtd   = win.get("eventdata") or win.get("eventData") or {}
    system = win.get("system") or {}
    rule   = event.get("rule") or {}
    agent  = event.get("agent") or {}

    # event_id
    event_id: str | None = None
    for path in (
        system.get("eventID"), system.get("eventId"),
        data.get("eventid"), data.get("event_id"),
    ):
        if path:
            event_id = str(path)
            break

    # process
    process: str | None = None
    candidates = [
        evtd.get("processName"), evtd.get("newProcessName"),
        evtd.get("image"), data.get("process"), data.get("command"),
    ]
    for c in candidates:
        if c:
            raw = str(c).strip().replace("/", "\\")
            process = (raw.rsplit("\\", 1)[-1] if "\\" in raw else raw).lower() or None
            break

    # user
    user: str | None = None
    for u in (
        data.get("dstuser"), data.get("srcuser"), data.get("user"),
        evtd.get("targetUserName"), evtd.get("subjectUserName"),
    ):
        if u and str(u).upper() not in (
            "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "-", ""
        ):
            user = str(u).lower()
            break

    # ip
    src_ip: str | None = None
    for ip in (
        data.get("srcip"), data.get("src_ip"),
        evtd.get("ipAddress"), evtd.get("sourceNetworkAddress"),
    ):
        if ip and ip not in ("::1", "127.0.0.1", "-", ""):
            src_ip = str(ip)
            break

    # service_name
    service_name: str | None = None
    for sn in (
        evtd.get("serviceName"), data.get("service_name"), data.get("service"),
    ):
        if sn:
            service_name = str(sn).lower()
            break

    # event_family (Wazuh groups / mitre tactic)
    event_family: str | None = None
    groups = rule.get("groups") or []
    if isinstance(groups, list) and groups:
        event_family = str(groups[0])
    elif isinstance(groups, str) and groups:
        event_family = groups
    if not event_family:
        tactics = (rule.get("mitre") or {}).get("tactic") or []
        if isinstance(tactics, list) and tactics:
            event_family = str(tactics[0])
        elif isinstance(tactics, str) and tactics:
            event_family = tactics

    # host
    host: str | None = agent.get("name") or None

    return {
        "host":         host,
        "event_id":     event_id,
        "process":      process,
        "user":         user,
        "ip":           src_ip,
        "service_name": service_name,
        "event_family": event_family,
    }


# ── Baseline feature lookup helpers ──────────────────────────────────────────

def _features_by_type(host: str) -> dict[str, dict[str, int]]:
    """
    Returns {feature_type: {feature_key_lower: count_seen}} for this host.
    Gracefully returns empty dict if baseline service is unavailable.
    """
    try:
        from services.baseline_service import get_features as _gf  # type: ignore[import]
        rows = _gf(host)
        result: dict[str, dict[str, int]] = {}
        for r in rows:
            ftype = r.feature_type
            fkey  = str(r.feature_key).lower()
            cnt   = r.count_seen
            result.setdefault(ftype, {})[fkey] = cnt
        return result
    except Exception:
        return {}


def _get_open_deviations(host: str) -> list[dict[str, Any]]:
    try:
        from services.baseline_service import get_deviations as _gd  # type: ignore[import]
        devs = _gd(host, unresolved_only=True)
        return [
            {
                "type":       d.deviation_type,
                "key":        d.feature_key,
                "risk_score": d.risk_score,
                "risk_level": d.risk_level,
                "reason":     d.reason,
                "confidence": d.confidence,
            }
            for d in devs
        ]
    except Exception:
        return []


def _get_snapshot_info(host: str) -> dict[str, Any] | None:
    try:
        from services.baseline_service import get_latest_snapshot as _gs  # type: ignore[import]
        snap = _gs(host)
        if snap is None:
            return None
        return {
            "computed_at":     snap.computed_at,
            "window_hours":    snap.window_hours,
            "total_events":    snap.total_events,
            "high_alerts":     snap.high_alerts,
            "critical_alerts": snap.critical_alerts,
        }
    except Exception:
        return None


# ── Risk modifier ─────────────────────────────────────────────────────────────

def _compute_modifier(
    fields: dict[str, str | None],
    known: dict[str, bool | None],
    open_devs: list[dict[str, Any]],
    base_evaluation: dict[str, Any] | None,
) -> tuple[float, str]:
    """
    Returns (host_risk_modifier, reason_string).
    Modifier is a multiplier: 1.0 = no change, >1 = more risky, <1 = less risky.
    """
    modifier = 1.0
    reasons: list[str] = []

    event_id     = fields.get("event_id")
    is_high_risk = event_id in _HIGH_RISK_EIDS if event_id else False
    base_verdict = (base_evaluation or {}).get("verdict", "monitor")

    # ── Risk increases ─────────────────────────────────────────────────────────
    # New high-risk event ID on this host
    if is_high_risk and known.get("event_id") is False:
        modifier += 2.0
        reasons.append(f"High-risk event ID {event_id} is new on this host")

    # New process + base says review/investigate
    if known.get("process") is False and base_verdict in ("review", "investigate", "incident_candidate"):
        modifier += 1.5
        reasons.append(f"Process '{fields.get('process')}' is new on this host")

    # New user or new IP
    if known.get("user") is False:
        modifier += 1.0
        reasons.append(f"User '{fields.get('user')}' is new on this host")
    if known.get("ip") is False:
        modifier += 1.0
        reasons.append(f"Source IP {fields.get('ip')} is new on this host")

    # Open high-risk deviations
    high_risk_devs = [d for d in open_devs if d.get("risk_level") in ("high", "critical")]
    if high_risk_devs:
        modifier += 1.0
        reasons.append(f"{len(high_risk_devs)} open high-risk deviation(s) on host")

    # ── Risk decreases ─────────────────────────────────────────────────────────
    # Do NOT reduce risk for high-risk events
    if not is_high_risk:
        all_known = all(
            v is True
            for v in [known.get("event_id"), known.get("process"), known.get("user")]
            if v is not None
        )
        if all_known and base_verdict in ("monitor", "ignore"):
            modifier -= 1.0
            reasons.append("All checked features are common on this host")

    modifier = round(max(0.2, modifier), 2)
    reason   = "; ".join(reasons) if reasons else "Baseline context nominal."
    return modifier, reason


# ── Public API ────────────────────────────────────────────────────────────────

def get_event_baseline_context(
    event: dict[str, Any],
    base_evaluation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Enrich a Wazuh event with host baseline context.

    Parameters
    ----------
    event:
        Raw Wazuh event document.
    base_evaluation:
        Optional base evaluation dict from resolve_event_knowledge / final_event_evaluator.
        Used to adjust risk modifier direction.

    Returns
    -------
    dict — see _empty_ctx() for full schema.
    """
    warnings: list[str] = []

    fields = _extract_event_fields(event)
    host   = fields.get("host")

    if not host:
        return _empty_ctx(None, "No agent.name in event — cannot query baseline.")

    # ── Snapshot ──────────────────────────────────────────────────────────────
    snap_info = _get_snapshot_info(host)
    if snap_info is None:
        return {
            **_empty_ctx(host, f"No baseline snapshot for host '{host}'. Run baseline computation first."),
            "warnings": [f"No baseline snapshot for host '{host}'. Run baseline computation first."],
        }

    # ── Feature lookup ────────────────────────────────────────────────────────
    feature_map = _features_by_type(host)

    feature_types = {
        "event_id":     fields.get("event_id"),
        "process":      fields.get("process"),
        "user":         fields.get("user"),
        "ip":           fields.get("ip"),
        "service_name": fields.get("service_name"),
        "event_family": fields.get("event_family"),
    }

    known:    dict[str, bool | None] = {}
    counts:   dict[str, int | None]  = {}
    new_features:  list[str] = []
    rare_features: list[str] = []

    for ftype, fvalue in feature_types.items():
        if fvalue is None:
            known[ftype]  = None
            counts[ftype] = None
            continue
        type_map = feature_map.get(ftype, {})
        cnt = type_map.get(fvalue.lower())
        if cnt is None:
            known[ftype]  = False
            counts[ftype] = 0
            new_features.append(f"{ftype}:{fvalue}")
        else:
            known[ftype]  = True
            counts[ftype] = cnt
            if cnt < _RARE_THRESHOLD:
                rare_features.append(f"{ftype}:{fvalue} (seen {cnt}×)")

    # ── Deviations ────────────────────────────────────────────────────────────
    open_devs = _get_open_deviations(host)
    top_devs  = sorted(open_devs, key=lambda d: -d.get("risk_score", 0))[:5]

    # ── Risk modifier ─────────────────────────────────────────────────────────
    modifier, mod_reason = _compute_modifier(fields, known, open_devs, base_evaluation)

    # ── Baseline candidate check ──────────────────────────────────────────────
    base_verdict    = (base_evaluation or {}).get("verdict", "monitor")
    base_risk_score = float((base_evaluation or {}).get("risk_score", 5.0))
    rule_level      = int((event.get("rule") or {}).get("level", 0))
    event_id        = fields.get("event_id") or ""
    is_high_risk    = event_id in _HIGH_RISK_EIDS

    baseline_candidate = False
    bc_reason: str | None = None

    if (
        base_verdict in ("ignore", "monitor")
        and not is_high_risk
        and rule_level < 10
        and not any(
            d.get("risk_level") in ("high", "critical") for d in open_devs
        )
        and known.get("event_id") is True
        and (known.get("process") is not False)
        and not new_features
    ):
        baseline_candidate = True
        bc_reason = "Event and features are common on this host; low rule level; no high-risk deviations."
    elif is_high_risk and baseline_candidate:
        baseline_candidate = False
        bc_reason = f"High-risk event ID {event_id} cannot be a baseline candidate."

    return {
        "host":               host,
        "baseline_available": True,
        "snapshot":           snap_info,
        "known_features":     known,
        "feature_counts":     counts,
        "new_features":       new_features,
        "rare_features":      rare_features,
        "open_deviations":    len(open_devs),
        "top_risk_deviations": top_devs,
        "baseline_candidate":  baseline_candidate,
        "baseline_candidate_reason": bc_reason,
        "host_risk_modifier":  modifier,
        "host_context_reason": mod_reason,
        "warnings":            warnings,
    }
