"""Snipen explanation adapter.

This module converts the unified deterministic event evaluation into the
legacy ``SnipenExplainResult`` shape consumed by the Investigation UI.

Why this exists:
- Snipen's original explain path can call the local LLM and produce generic or
  too-alarmist wording.
- The Event Map / Unified Evaluation pipeline already contains deterministic
  profiles and guardrails.
- Investigation explanations should therefore be rendered from the same source
  of truth first, with AI only as an optional wording layer elsewhere.
"""
from __future__ import annotations

import json
from typing import Any

from schemas.types import SnipenExplainResult


def explain_event_structured(event_raw: dict[str, Any]) -> SnipenExplainResult:
    """Explain one event using the unified deterministic evaluator."""
    return _result_from_unified_event(event_raw)


def explain_event_with_context_structured(
    connection: dict[str, Any],
    event_raw: dict[str, Any],
) -> SnipenExplainResult:
    """Explain one event using unified evaluation plus a ±15 min context window.

    The context window is serialized into ``previous_output`` because existing
    event profiles, including Schannel 36871, can read nearby event IDs from that
    field without coupling themselves to the indexer.
    """
    enriched_event = dict(event_raw or {})
    try:
        from services.snipen_service import get_event_context_window  # type: ignore[import]

        ctx = get_event_context_window(connection, event_raw, window_minutes=15, max_events=10)
        context_events = list(ctx.get("before") or []) + list(ctx.get("after") or [])
        if context_events:
            enriched_event["previous_output"] = "\n".join(
                json.dumps(getattr(ev, "raw", {}) or {}, ensure_ascii=False, default=str)
                for ev in context_events
            )
    except Exception:
        # Context enrich is best-effort. The single-event explanation still works.
        pass
    return _result_from_unified_event(enriched_event)


def _result_from_unified_event(event_raw: dict[str, Any]) -> SnipenExplainResult:
    try:
        from services.unified_event_evaluator import evaluate_unified_event  # type: ignore[import]

        unified = evaluate_unified_event(event_raw)
        explanation = unified.get("explanation") or {}
        final_eval = unified.get("final_evaluation") or {}

        severity = str(
            explanation.get("severity")
            or final_eval.get("severity")
            or "medium"
        ).lower()
        risk_score = _safe_float(
            explanation.get("risk_score"),
            _safe_float(final_eval.get("risk_score"), None),
        )
        confidence = str(
            explanation.get("confidence")
            or final_eval.get("confidence")
            or "medium"
        ).lower()

        why_suspicious = _join_text(explanation.get("why_suspicious"))
        against_it = _join_text(explanation.get("why_likely_benign"))

        important_fields = explanation.get("important_fields") or []
        suspicious_fields = _field_names(important_fields)

        unusual_behavior = _as_list(explanation.get("why_visible"))
        if not unusual_behavior:
            unusual_behavior = _as_list(explanation.get("not_enough_evidence"))

        deviations = _as_list(explanation.get("baseline_notes"))
        if not deviations:
            deviations = _as_list(explanation.get("related_events"))
        if not deviations:
            deviations = _as_list(explanation.get("escalation_conditions"))[:3]

        return SnipenExplainResult(
            summary=str(explanation.get("summary") or final_eval.get("reason") or "No explanation returned."),
            why_suspicious=why_suspicious or None,
            against_it=against_it or None,
            severity=severity,
            risk_score=risk_score,
            confidence=confidence,
            mitre_techniques=[],
            remediation=_as_list(explanation.get("recommended_checks")),
            next_checks=_as_list(explanation.get("recommended_checks")),
            unusual_behavior=unusual_behavior,
            deviations=deviations,
            suspicious_fields=suspicious_fields,
            ran_ai=False,
        )
    except Exception as exc:
        return SnipenExplainResult(
            summary=f"Deterministic event explanation failed: {exc}",
            severity="medium",
            risk_score=5.0,
            confidence="low",
            ran_ai=False,
        )


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if str(x).strip()]
    if isinstance(value, tuple):
        return [str(x) for x in value if str(x).strip()]
    text = str(value).strip()
    return [text] if text else []


def _join_text(value: Any) -> str:
    return " ".join(_as_list(value)).strip()


def _safe_float(value: Any, fallback: float | None = 0.0) -> float | None:
    try:
        if value is None:
            return fallback
        return float(value)
    except Exception:
        return fallback


def _field_names(fields: Any) -> list[str]:
    names: list[str] = []
    if isinstance(fields, list):
        for item in fields:
            if isinstance(item, dict):
                name = item.get("field")
                if name:
                    names.append(str(name))
            elif item:
                names.append(str(item))
    return list(dict.fromkeys(names))
