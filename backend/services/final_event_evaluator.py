"""
Final Event Evaluator
======================
Combines:
  1. Base KB evaluation  (from knowledge.event_knowledge_resolver)
  2. Host baseline context  (from services.event_baseline_context)

into a single final evaluation that accounts for both what an event
means in general AND how unusual it is on this specific host.

Usage::

    from services.final_event_evaluator import evaluate_event_with_baseline

    result = evaluate_event_with_baseline(event)
    # Returns {"base_evaluation", "baseline_context", "final_evaluation"}
"""
from __future__ import annotations

from typing import Any

# ── High-risk event IDs — never downgraded ────────────────────────────────────
_HIGH_RISK_EIDS: frozenset[str] = frozenset({
    "7045", "1102", "4697", "4719", "4698", "4702",
})

# ── Verdict ladder ────────────────────────────────────────────────────────────
_VERDICT_RANK: dict[str, int] = {
    "ignore":             0,
    "monitor":            1,
    "review":             2,
    "investigate":        3,
    "incident_candidate": 4,
}
_RANK_VERDICT: dict[int, str] = {v: k for k, v in _VERDICT_RANK.items()}

# ── Severity to base risk score (0–10 scale) ──────────────────────────────────
_SEV_RISK: dict[str, float] = {
    "info":     1.0,
    "low":      2.5,
    "medium":   5.0,
    "high":     7.5,
    "critical": 9.5,
}

# ── Severity to base verdict ──────────────────────────────────────────────────
_SEV_VERDICT: dict[str, str] = {
    "info":     "monitor",
    "low":      "monitor",
    "medium":   "review",
    "high":     "investigate",
    "critical": "investigate",
}

# ── Confidence strings from knowledge_level ───────────────────────────────────
_LEVEL_CONFIDENCE: dict[str, str] = {
    "deep":    "high",
    "pattern": "medium",
    "basic":   "medium",
    "generic": "low",
    "unknown": "low",
}

# ── Risk score → verdict / severity mapping ────────────────────────────────────

def _score_to_verdict(score: float) -> str:
    if score >= 8.5:
        return "incident_candidate"
    if score >= 6.5:
        return "investigate"
    if score >= 4.0:
        return "review"
    if score >= 1.5:
        return "monitor"
    return "ignore"


def _score_to_severity(score: float) -> str:
    if score >= 8.5:
        return "critical"
    if score >= 6.5:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.5:
        return "low"
    return "info"


# ── Base evaluation (from KB resolver) ───────────────────────────────────────

def _build_base_evaluation(event: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw resolve_event_knowledge result into a structured base evaluation."""
    try:
        from knowledge.event_knowledge_resolver import resolve_event_knowledge  # type: ignore[import]
        kb = resolve_event_knowledge(event) or {}
    except Exception:
        kb = {}

    default_sev: str   = kb.get("default_severity", "info")
    knowledge_level    = kb.get("knowledge_level", "unknown")
    risk_score: float  = _SEV_RISK.get(default_sev, 1.0)

    # Rule level adjustment (Wazuh level 0–15)
    try:
        rule_level = int((event.get("rule") or {}).get("level", 0))
    except (TypeError, ValueError):
        rule_level = 0

    if rule_level >= 12:
        risk_score = max(risk_score, 7.5)
    elif rule_level >= 10:
        risk_score = max(risk_score, 5.0)
    elif rule_level >= 7:
        risk_score = max(risk_score, 3.5)
    elif rule_level < 4:
        risk_score = min(risk_score, 2.5)

    verdict    = _score_to_verdict(risk_score)
    severity   = _score_to_severity(risk_score)
    confidence = _LEVEL_CONFIDENCE.get(knowledge_level, "low")

    # what_to_do: pull from KB recommended actions or generic
    what_to_do: list[str] = kb.get("recommended_actions") or kb.get("analyst_actions") or []
    if not what_to_do:
        if default_sev in ("critical", "high"):
            what_to_do = ["Open investigation timeline", "Review host context", "Correlate with baseline"]
        elif default_sev in ("medium",):
            what_to_do = ["Correlate with baseline", "Check nearby events on same host"]
        else:
            what_to_do = ["Monitor for escalation or repeated pattern"]

    return {
        "verdict":    verdict,
        "severity":   severity,
        "risk_score": round(risk_score, 2),
        "confidence": confidence,
        "reason":     kb.get("summary") or f"Event {kb.get('key','?')}: {default_sev} severity.",
        "what_to_do": what_to_do[:6],
        "knowledge":  kb,
    }


# ── Final merge ───────────────────────────────────────────────────────────────

def evaluate_event_with_baseline(event: dict[str, Any]) -> dict[str, Any]:
    """
    Perform full event evaluation:
      1. Base KB evaluation
      2. Host baseline context
      3. Merged final evaluation

    Parameters
    ----------
    event : dict
        Raw Wazuh event document.

    Returns
    -------
    dict with keys:
        base_evaluation, baseline_context, final_evaluation
    """
    # ── Step 1: base evaluation ───────────────────────────────────────────────
    base = _build_base_evaluation(event)

    # ── Step 2: baseline context ──────────────────────────────────────────────
    try:
        from services.event_baseline_context import get_event_baseline_context  # type: ignore[import]
        ctx = get_event_baseline_context(event, base)
    except Exception as exc:
        ctx = {
            "host": None, "baseline_available": False,
            "host_risk_modifier": 1.0, "host_context_reason": f"Error: {exc}",
            "warnings": [str(exc)], "open_deviations": 0,
            "top_risk_deviations": [], "new_features": [], "rare_features": [],
            "baseline_candidate": False, "baseline_candidate_reason": None,
        }

    # ── Step 3: merge ─────────────────────────────────────────────────────────
    base_score:   float = base["risk_score"]
    modifier:     float = ctx.get("host_risk_modifier", 1.0)
    final_score:  float = round(min(10.0, max(0.0, base_score * modifier)), 2)

    # Never downgrade high-risk event IDs
    event_id = None
    try:
        system = (event.get("data") or {}).get("win", {}).get("system", {})
        event_id = str(
            system.get("eventID") or system.get("eventId") or
            (event.get("data") or {}).get("eventid") or ""
        ) or None
    except (AttributeError, TypeError):
        pass

    if event_id in _HIGH_RISK_EIDS:
        final_score = max(final_score, base_score)

    final_verdict   = _score_to_verdict(final_score)
    final_severity  = _score_to_severity(final_score)

    # Clamp verdict to at least base_verdict (never downgrade)
    base_rank  = _VERDICT_RANK.get(base["verdict"], 1)
    final_rank = _VERDICT_RANK.get(final_verdict, 1)
    final_rank = max(base_rank, final_rank)
    final_verdict = _RANK_VERDICT.get(final_rank, final_verdict)

    # Build final reason
    final_reason = base["reason"]
    ctx_reason = ctx.get("host_context_reason", "")
    if ctx_reason and ctx_reason != "Baseline context nominal." and ctx_reason != "No baseline available for this host.":
        final_reason = f"{final_reason} | Host context: {ctx_reason}"

    # manual_review_required when verdict is investigate+
    manual_review = final_rank >= _VERDICT_RANK["investigate"]

    # safe_to_baseline
    safe_to_baseline = (
        ctx.get("baseline_candidate", False)
        and final_verdict in ("ignore", "monitor")
        and not manual_review
    )

    # warnings
    final_warnings: list[str] = list(ctx.get("warnings") or [])
    if not ctx.get("baseline_available"):
        final_warnings.append("Host baseline unavailable — evaluation based on KB only.")
    if ctx.get("open_deviations", 0) > 0:
        final_warnings.append(
            f"Host has {ctx['open_deviations']} unresolved deviation(s). Review before baselining."
        )

    return {
        "base_evaluation": {
            "verdict":    base["verdict"],
            "severity":   base["severity"],
            "risk_score": base["risk_score"],
            "confidence": base["confidence"],
            "reason":     base["reason"],
            "what_to_do": base["what_to_do"],
        },
        "baseline_context": ctx,
        "final_evaluation": {
            "verdict":               final_verdict,
            "severity":              final_severity,
            "risk_score":            final_score,
            "confidence":            base["confidence"],
            "reason":                final_reason,
            "what_to_do":            base["what_to_do"],
            "safe_to_baseline":      safe_to_baseline,
            "manual_review_required": manual_review,
            "warnings":              final_warnings,
        },
    }
