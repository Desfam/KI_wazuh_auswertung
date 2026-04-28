"""Event / deviation classification engine.

Maps detection signals → a single ``final_classification`` label that
answers the analyst's core question: *what does this deviation mean?*

Classification values (checked in priority order):
    accepted_baseline    – analyst resolved/accepted the deviation
    escalated            – risk >= 75, immediate action required
    known_but_suspicious – entity IS in baseline, but behavior/volume changed
    expected_for_profile – entity is new, but host profile explicitly allows it
    needs_investigation  – new deviation with medium risk (35–74)
    known_benign         – entity known, no anomalies found
    false_positive       – reserved for analyst-driven dismissal
    unknown              – no baseline context available

Core principle: Baseline is *context*, not a whitelist.
    known entity + normal behavior   → known_benign
    known entity + suspicious exec   → known_but_suspicious  ← NOT safe!
    known entity + volume spike      → known_but_suspicious
"""
from __future__ import annotations

import fnmatch
from typing import Any

# ── Thresholds ────────────────────────────────────────────────────────────────

_ESCALATED_THRESHOLD   = 75  # risk_score >= this → escalated
_INVESTIGATE_THRESHOLD = 35  # risk_score >= this → needs_investigation


# ── Core classifier ───────────────────────────────────────────────────────────

def classify_deviation(
    deviation_type: str,
    risk_score: int,
    is_known: bool,
    behavior_flags: list[str],
    is_resolved: bool,
    profile_expected: bool = False,
    volume_anomaly: bool = False,
) -> str:
    """Return a ``final_classification`` string for this deviation.

    Parameters
    ----------
    deviation_type:
        The deviation type key (new_process, suspicious_behavior, …).
    risk_score:
        Computed 0–100 risk score.
    is_known:
        Whether the entity (feature_key) was already in the baseline.
    behavior_flags:
        Suspicious-execution flags detected by behavior_analyzer.
    is_resolved:
        Whether the deviation has been resolved/accepted by an analyst.
    profile_expected:
        Whether the host's profile explicitly allows/expects this entity.
    volume_anomaly:
        Whether this is a volume-spike type deviation.
    """

    # 1. Analyst resolution takes priority — whatever the score
    if is_resolved:
        return "accepted_baseline"

    # 2. Critical risk → escalate regardless of known status
    if risk_score >= _ESCALATED_THRESHOLD:
        return "escalated"

    # 3. Known entity with suspicious execution or volume change
    #    "suspicious_behavior" type only fires for known entities,
    #    so it always maps to known_but_suspicious.
    if deviation_type == "suspicious_behavior":
        return "known_but_suspicious"
    if is_known and (behavior_flags or volume_anomaly):
        return "known_but_suspicious"

    # 4. New entity, but host profile explicitly allows it
    if not is_known and profile_expected:
        return "expected_for_profile"

    # 5. Any deviation with medium+ risk → needs analyst attention
    if risk_score >= _INVESTIGATE_THRESHOLD:
        return "needs_investigation"

    # 6. Low-risk new entity — still worth tracking but not urgent
    if not is_known:
        return "needs_investigation"

    # 7. Known entity, no anomalies — baseline matched
    if is_known:
        return "known_benign"

    return "unknown"


# ── Convenience wrapper ───────────────────────────────────────────────────────

def classify_from_details(
    deviation_type: str,
    risk_score: int,
    is_resolved: bool,
    details: dict[str, Any],
    profile_allowed_patterns: list[str] | None = None,
    feature_key: str = "",
) -> str:
    """Classify a deviation using its stored ``details`` dict.

    Reads ``is_known`` and ``behavior_flags`` from details and optionally
    checks ``feature_key`` against profile ``allowed_process_patterns``.
    """
    is_known: bool = bool(details.get("is_known", False))
    behavior_flags: list[str] = list(details.get("behavior_flags") or [])
    volume_anomaly: bool = deviation_type == "volume_spike"

    profile_expected = False
    if profile_allowed_patterns and feature_key:
        key_lower = feature_key.lower()
        profile_expected = any(
            fnmatch.fnmatch(key_lower, pat.lower())
            for pat in profile_allowed_patterns
        )

    return classify_deviation(
        deviation_type=deviation_type,
        risk_score=risk_score,
        is_known=is_known,
        behavior_flags=behavior_flags,
        is_resolved=is_resolved,
        profile_expected=profile_expected,
        volume_anomaly=volume_anomaly,
    )
