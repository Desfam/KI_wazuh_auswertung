"""Unified Event Evaluator
==========================
Single entry point for ALL event evaluation in the app.

All views (Event Map, Investigation Summary, Timeline, Full Scan, Reports)
must consume the result of this function — they must NOT compute their own
risk score, severity, or explanation.

Pipeline
--------
1. evaluate_event_with_baseline  → base KB eval + host baseline context + final evaluation
2. build_event_explanation       → deterministic structured text (no AI)

Return schema
-------------
{
  event_id, rule_id, title, category, platform,
  base_evaluation, baseline_context,
  final_evaluation: { verdict, severity, risk_score, confidence,
                       reason, manual_review_required, safe_to_baseline, warnings },
  explanation:      { title, subtitle, summary, why_visible, why_suspicious,
                       why_likely_benign, not_enough_evidence, important_fields,
                       recommended_checks, escalation_conditions,
                       baseline_notes, wording_warnings },
  trust:            { source, confidence, matched_by, missing_fields, warnings },
}

The function never crashes.  Unknown events return a safe fallback with
confidence=low and manual_review_required=True.
"""
from __future__ import annotations

import os
from typing import Any

# ── Event-ID → category label ─────────────────────────────────────────────────
_EID_CATEGORY: dict[str, str] = {
    "1014": "network",
    "1102": "anti_forensics",
    "4624": "authentication",
    "4625": "authentication",
    "4634": "authentication",
    "4648": "authentication",
    "4656": "object_access",
    "4663": "object_access",
    "4672": "privilege",
    "4688": "process",
    "4697": "persistence",
    "4698": "persistence",
    "4702": "persistence",
    "4719": "policy_change",
    "4720": "account_management",
    "4726": "account_management",
    "4728": "account_management",
    "4732": "account_management",
    "7040": "service",
    "7045": "persistence",
}


# ── Public API ────────────────────────────────────────────────────────────────

def evaluate_unified_event(event: dict[str, Any]) -> dict[str, Any]:
    """Run the full deterministic evaluation pipeline for one raw Wazuh event.

    Never raises.  Unknown / incomplete events get a safe fallback.
    """
    event_id = _extract_event_id(event)
    rule_id  = str((event.get("rule") or {}).get("id") or "") or None
    platform = _detect_platform(event)

    # ── Step 1: Full evaluation (KB + host baseline context) ─────────────────
    try:
        from services.final_event_evaluator import evaluate_event_with_baseline  # type: ignore[import]
        eval_result = evaluate_event_with_baseline(event)
    except Exception as exc:
        eval_result = _fallback_eval_result(event, str(exc))

    base_eval    = eval_result.get("base_evaluation") or {}
    baseline_ctx = eval_result.get("baseline_context") or {}
    final_eval   = eval_result.get("final_evaluation") or {}

    # ── Step 2: Deterministic explanation ────────────────────────────────────
    try:
        from services.event_explanation_builder import build_event_explanation  # type: ignore[import]
        knowledge = base_eval.get("knowledge") or {}
        explanation = build_event_explanation(
            event=event,
            evaluation=eval_result,
            knowledge=knowledge or None,
        )
    except Exception as exc:
        explanation = _fallback_explanation(event, str(exc))

    # ── Step 2b: Merge deterministic risk into final_evaluation ──────────────
    # The explanation builder has deeper per-event context (process paths, cmdline,
    # service binary paths, etc.) than the generic decision engine.  If the
    # deterministic analysis computed a higher risk, promote the final_evaluation
    # so every consumer sees a consistent result.
    expl_risk = explanation.get("risk_score")
    if expl_risk is not None and isinstance(final_eval, dict):
        ext_risk = float(final_eval.get("risk_score") or 0)
        if float(expl_risk) > ext_risk:
            final_eval = {**final_eval}  # don't mutate the original dict
            final_eval["risk_score"] = float(expl_risk)
            if explanation.get("severity"):
                final_eval["severity"] = explanation["severity"]
            if explanation.get("verdict"):
                final_eval["verdict"] = explanation["verdict"]
            # Only adopt explanation confidence when it is more certain
            if explanation.get("confidence") in ("high", "medium") and \
                    final_eval.get("confidence") == "low":
                final_eval["confidence"] = explanation["confidence"]
            # Unknown/generic events: mark as needing manual review
            if explanation.get("explanation_source") == "fallback":
                final_eval["manual_review_required"] = True
    # Unknown events with no event-id should always require manual review
    if not event_id:
        final_eval = {**final_eval} if final_eval else {}
        final_eval["manual_review_required"] = True

    # ── Step 3: Trust metadata ────────────────────────────────────────────────
    matched_by: list[str] = []
    kb = base_eval.get("knowledge") or {}
    kl = kb.get("knowledge_level", "unknown")
    if kl not in ("generic", "unknown", ""):
        matched_by.append(f"KB:{kb.get('key', '?')} [{kl}]")
    if baseline_ctx.get("baseline_available"):
        matched_by.append("host_baseline")
    if not matched_by:
        matched_by.append("fallback")

    missing_fields: list[str] = []
    if not event_id:
        missing_fields.append("event_id")
    data = event.get("data") or {}
    win  = data.get("win") or {}
    if not win and platform == "windows":
        missing_fields.append("win_eventdata")

    trust = {
        "source":         "unified_event_evaluator",
        "confidence":     final_eval.get("confidence", "low"),
        "matched_by":     matched_by,
        "missing_fields": missing_fields,
        "warnings":       list(final_eval.get("warnings") or []),
    }

    title    = explanation.get("title") or kb.get("title") or f"Event {event_id or '?'}"
    category = _EID_CATEGORY.get(event_id or "", _detect_category(event, platform))

    return {
        "event_id":        event_id,
        "rule_id":         rule_id,
        "title":           title,
        "category":        category,
        "platform":        platform,
        "base_evaluation": base_eval,
        "baseline_context": baseline_ctx or None,
        "final_evaluation": final_eval,
        "explanation":     explanation,
        "trust":           trust,
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_event_id(event: dict[str, Any]) -> str | None:
    try:
        from services.wazuh_field_mapper import get_field
        eid = get_field(event,
            "data.win.system.eventID",
            "data.win.system.eventId",
            "data.win.system.eventid",
            "data.eventid",
            "data.event_id",
        )
        return str(eid).strip() if eid else None
    except Exception:
        data    = event.get("data") or {}
        win_sys = (data.get("win") or {}).get("system") or {}
        eid = (
            win_sys.get("eventID") or win_sys.get("eventId")
            or data.get("eventid") or data.get("event_id")
        )
        return str(eid).strip() if eid else None


def _detect_platform(event: dict[str, Any]) -> str:
    data = event.get("data") or {}
    if data.get("win"):
        return "windows"
    decoder = (event.get("decoder") or {}).get("name") or ""
    rule_groups: list[str] = list(
        (event.get("rule") or {}).get("groups") or []
    )
    groups_str = " ".join(rule_groups).lower()
    if "linux" in groups_str or decoder in ("sshd", "auditd", "syscheck"):
        return "linux"
    # Default guess from manager/agent context
    agent_os = str((event.get("agent") or {}).get("os", {}) or "").lower()
    if "windows" in agent_os:
        return "windows"
    if "linux" in agent_os or "ubuntu" in agent_os or "centos" in agent_os:
        return "linux"
    return "unknown"


def _detect_category(event: dict[str, Any], platform: str) -> str:
    rule_groups: list[str] = list(
        (event.get("rule") or {}).get("groups") or []
    )
    groups_str = " ".join(rule_groups).lower()
    if "authentication" in groups_str or "login" in groups_str:
        return "authentication"
    if "syscheck" in groups_str or "fim" in groups_str:
        return "fim"
    if "process" in groups_str or "execve" in groups_str:
        return "process"
    if "service" in groups_str:
        return "service"
    if "network" in groups_str or "firewall" in groups_str:
        return "network"
    if "vulnerability" in groups_str:
        return "vulnerability"
    if "sca" in groups_str:
        return "compliance"
    return "general"


def _fallback_eval_result(event: dict[str, Any], err: str) -> dict[str, Any]:
    rule_level = max(0, int((event.get("rule") or {}).get("level", 0) or 0))
    if rule_level >= 10:
        risk = 5.0; severity = "medium"; verdict = "review"
    elif rule_level >= 7:
        risk = 3.5; severity = "low"; verdict = "monitor"
    else:
        risk = 2.0; severity = "low"; verdict = "monitor"
    return {
        "base_evaluation": {
            "verdict": verdict, "severity": severity,
            "risk_score": risk, "confidence": "low",
            "reason": f"Fallback evaluation (evaluator unavailable: {err[:80]})",
            "what_to_do": ["Manual review required"],
        },
        "baseline_context": {"baseline_available": False},
        "final_evaluation": {
            "verdict": verdict, "severity": severity,
            "risk_score": risk, "confidence": "low",
            "reason": f"Fallback evaluation (evaluator unavailable: {err[:80]})",
            "what_to_do": ["Manual review required"],
            "safe_to_baseline": False,
            "manual_review_required": True,
            "warnings": [f"Evaluator error: {err[:120]}"],
        },
    }


def _fallback_explanation(event: dict[str, Any], err: str) -> dict[str, Any]:
    event_id = _extract_event_id(event)
    rule_desc = str((event.get("rule") or {}).get("description") or "")
    return {
        "title":                 f"Event {event_id or '?'}",
        "subtitle":              rule_desc[:80],
        "verdict":               "monitor",
        "severity":              "low",
        "risk_score":            2.0,
        "confidence":            "low",
        "explanation_source":    "fallback",
        "summary":               (
            f"{rule_desc or 'This event'} was recorded. "
            "Generic fallback explanation used — the explanation builder was unavailable. "
            "Manual review required."
        ),
        "why_visible":           ["Event meets the monitoring threshold."],
        "why_suspicious":        [],
        "why_likely_benign":     [],
        "not_enough_evidence":   [f"Explanation builder error: {err[:120]}"],
        "important_fields":      [],
        "recommended_checks":    ["Review the raw event data manually."],
        "escalation_conditions": [],
        "baseline_notes":        [],
        "wording_warnings":      [
            "Generic fallback used — explanation may be incomplete.",
        ],
    }
