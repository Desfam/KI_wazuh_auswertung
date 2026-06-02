"""Deterministic explanation overrides for selected Windows events.

Small, conservative post-processing helpers for the unified evaluator.
"""
from __future__ import annotations

import json
from typing import Any


_REVIEW_CONTEXT_EIDS: set[str] = {"1102", "7045", "4697", "4672", "4688"}
_OPERATIONAL_CONTEXT_EIDS: set[str] = {"1129", "5719", "7000", "7009"}


def apply_event_explanation_overrides(
    event: dict[str, Any],
    explanation: dict[str, Any],
    final_evaluation: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Apply deterministic overrides and return new explanation/final dicts."""
    event_id = _extract_event_id(event)
    final = dict(final_evaluation or {})
    if event_id == "36871" and _is_schannel_36871(event):
        return _override_schannel_36871(event, explanation, final)
    return dict(explanation or {}), final


def _override_schannel_36871(
    event: dict[str, Any],
    explanation: dict[str, Any],
    final: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    data = event.get("data") or {}
    win = data.get("win") or {}
    system = win.get("system") or {}
    eventdata = win.get("eventdata") or win.get("eventData") or {}

    host = (event.get("agent") or {}).get("name") or system.get("computer") or "unknown host"
    provider = str(system.get("providerName") or "Schannel")
    error_state = str(eventdata.get("errorState") or "") or None
    caller_process = str(eventdata.get("callerProcessImageName") or "svchost")
    caller_pid = str(eventdata.get("callerProcessId") or system.get("processID") or "") or None

    nearby_ids = _extract_nearby_event_ids(event)
    has_operational_context = bool(nearby_ids & _OPERATIONAL_CONTEXT_EIDS)
    has_review_context = bool(nearby_ids & _REVIEW_CONTEXT_EIDS)

    if has_review_context:
        risk_score = 6.2
        severity = "medium"
        verdict = "investigate"
        confidence = "medium"
    elif has_operational_context:
        risk_score = 4.2
        severity = "medium"
        verdict = "review"
        confidence = "medium-high"
    else:
        risk_score = 4.6
        severity = "medium"
        verdict = "review"
        confidence = "medium"

    why_visible = [
        "Schannel reported a TLS client credential creation failure.",
        "TLS/SSPI errors can indicate certificate, DNS, network, domain-controller, proxy, or service communication problems.",
    ]
    if has_operational_context:
        why_visible.append(
            "Nearby NETLOGON, GroupPolicy, or Service Control Manager errors point toward network/DC/service availability context."
        )

    why_suspicious = [
        "Security-relevant only if the Schannel error is sustained, affects many hosts, or correlates with suspicious logon, process, service, audit-log, or certificate events."
    ]
    if has_review_context:
        why_suspicious.append(
            "A nearby high-signal Windows event is present; review the timeline before treating this as a pure operational issue."
        )

    why_likely_benign = [
        "svchost is a normal Windows service host and is not suspicious by itself.",
        "Schannel 36871 is commonly caused by TLS, certificate, DNS, proxy, domain-controller, or service communication issues.",
        "This event alone does not show a new process, new service, suspicious logon, or host takeover indicator.",
    ]
    if has_operational_context:
        why_likely_benign.append(
            "The nearby 1129/5719/7000/7009 context supports a likely operational network/DC/service issue."
        )

    important_fields = [
        {"field": "event_id", "value": "36871", "reason": "Schannel TLS client credential error"},
        {"field": "provider", "value": provider, "reason": "Windows TLS/Schannel provider"},
        {"field": "error_state", "value": error_state or "n/a", "reason": "Internal Schannel error state"},
        {"field": "caller_process", "value": caller_process, "reason": "SSPI client process; svchost is normal for Windows services"},
        {"field": "caller_pid", "value": caller_pid or "n/a", "reason": "Process ID from eventdata/system context"},
        {"field": "host", "value": str(host), "reason": "Affected endpoint"},
    ]

    recommended_checks = [
        f"Check domain controller reachability from {host}.",
        "Validate DNS resolution for domain controllers and domain services.",
        "Review NETLOGON 5719 and GroupPolicy 1129 within the same time window.",
        "Review Service Control Manager 7000/7009 events for service timeout context.",
        "Search for the same 36871/errorState pattern across other hosts.",
        "Escalate only if suspicious 4624/4672/4688/7045/1102 or certificate-change events correlate.",
    ]

    escalation_conditions = [
        "Same Schannel error appears suddenly across many hosts.",
        "A security, backup, Wazuh, Tactical RMM, or domain-authentication component is affected.",
        "Correlates with suspicious logon, privilege, process creation, service install, or audit-log-clearing events.",
        "Host repeatedly loses domain-controller connectivity or authentication capability.",
        "Certificate/TLS failures correlate with unusual external destinations or recent certificate changes.",
    ]

    summary = (
        f"Event 36871 on {host} is a Schannel TLS client credential creation error "
        f"(internal error state {error_state or 'unknown'}). The SSPI client process is {caller_process}, "
        "which is normal for Windows services when svchost is involved. "
    )
    if has_operational_context:
        summary += (
            "Nearby NETLOGON/GroupPolicy/Service Control Manager errors suggest a network, DNS, "
            "domain-controller, or service availability problem rather than a direct security incident. "
        )
    summary += f"Verdict: {verdict} (risk {risk_score:.1f}/10)."

    clean = dict(explanation or {})
    clean.update({
        "title": "Schannel TLS Client Credential Error",
        "subtitle": f"TLS client credentials could not be created on {host}",
        "verdict": verdict,
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "explanation_source": "schannel_36871_profile",
        "summary": summary,
        "why_visible": why_visible,
        "why_suspicious": why_suspicious,
        "why_likely_benign": why_likely_benign,
        "not_enough_evidence": [
            "The owning Windows service behind svchost is not identified in this event alone.",
            "Raw Schannel events require correlated authentication, process, service, or certificate context for escalation.",
        ],
        "important_fields": important_fields,
        "recommended_checks": recommended_checks,
        "escalation_conditions": escalation_conditions,
        "baseline_notes": list(clean.get("baseline_notes") or []),
        "wording_warnings": [
            "Do not describe svchost as suspicious by itself for Event 36871.",
            "Do not mention missing 4688/4689 as suspicious unless supporting evidence exists.",
        ],
        "related_events": _describe_related_events(nearby_ids),
        "category": "system_health/tls/domain_connectivity",
    })

    final.update({
        "verdict": verdict,
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "reason": summary,
        "manual_review_required": verdict in ("review", "investigate"),
        "safe_to_baseline": False,
    })
    warnings = list(final.get("warnings") or [])
    if has_operational_context:
        warnings.append("36871 anchored as likely operational due to nearby 1129/5719/7000/7009 context.")
    final["warnings"] = warnings

    return clean, final


def _is_schannel_36871(event: dict[str, Any]) -> bool:
    data = event.get("data") or {}
    win = data.get("win") or {}
    system = win.get("system") or {}
    provider = str(system.get("providerName") or "").lower()
    message = str(system.get("message") or "").lower()
    return (
        _extract_event_id(event) == "36871"
        and (
            "schannel" in provider
            or "tls-client" in message
            or "tls client" in message
            or "tls-client anmelde" in message
        )
    )


def _extract_event_id(event: dict[str, Any]) -> str | None:
    data = event.get("data") or {}
    win_system = (data.get("win") or {}).get("system") or {}
    eid = win_system.get("eventID") or win_system.get("eventId") or data.get("eventid")
    return str(eid).strip() if eid is not None else None


def _extract_nearby_event_ids(event: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    eid = _extract_event_id(event)
    if eid:
        ids.add(eid)
    previous_output = str(event.get("previous_output") or "")
    if not previous_output:
        return ids
    for raw_line in previous_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except Exception:
            continue
        data = parsed.get("data") or parsed
        win_system = ((data.get("win") or {}).get("system") or {})
        line_eid = win_system.get("eventID") or win_system.get("eventId")
        if line_eid is not None:
            ids.add(str(line_eid).strip())
    return ids


def _describe_related_events(event_ids: set[str]) -> list[str]:
    mapping = {
        "1129": "GroupPolicy failed because domain-controller/network connectivity was unavailable.",
        "5719": "NETLOGON could not establish a secure session with a domain controller.",
        "7000": "Service Control Manager reported that a service failed to start.",
        "7009": "Service Control Manager reported a service start/control timeout.",
        "7045": "New service installed; high-signal persistence context if nearby.",
        "1102": "Security audit log cleared; high-signal anti-forensics context if nearby.",
        "4688": "Process creation; review only if process/command line is suspicious.",
        "4672": "Special privileges assigned; relevant when linked to unusual logon activity.",
    }
    return [f"{eid}: {mapping[eid]}" for eid in sorted(event_ids) if eid in mapping]
