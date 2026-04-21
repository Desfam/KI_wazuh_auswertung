"""Event Decision Engine — pre-AI classification and guardrail system.

Determines the event class (system / infrastructure / vulnerability / security),
derives a risk score + severity ceiling, and decides whether the AI should run at
all — plus what actions / MITRE mappings it is ALLOWED to produce.

Usage
-----
    from services.event_decision_engine import decide_event, build_decision_context_block, \
        build_static_explain_result, EventDecision

    decision = decide_event(
        event_id=smart.event_id,
        rule_level=smart.rule_level,
        rule_description=smart.rule_description,
        event_explanation=smart.event_explanation,
        groups=smart.groups or [],
        event_family=event_family,
        profile_name=host_profile.name if host_profile else None,
        has_baseline_deviation=False,
        has_ti_match=False,
    )

    if not decision.should_run_ai:
        return build_static_explain_result(smart, decision)
    # … otherwise run AI with build_decision_context_block(decision) in prompt
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# ── Constants ─────────────────────────────────────────────────────────────────

EVENT_CLASS_SYSTEM = "system"
EVENT_CLASS_INFRA = "infrastructure"
EVENT_CLASS_VULN = "vulnerability"
EVENT_CLASS_SECURITY = "security"

Severity = Literal["info", "low", "medium", "high", "critical"]

# Windows OS / licensing / maintenance events that are NEVER security-relevant
SAFE_SYSTEM_EVENT_IDS: frozenset[str] = frozenset({
    "16384",   # Software Protection Service successfully scheduled
    "16394",   # Software Protection service state
    "10016",   # DCOM: permission mismatch (common noise)
    "1001",    # Windows Error Reporting / BugCheck
    "1000",    # Application error (crash)
    "1001",    # Windows Error Reporting
    "6005",    # Event Log service started (boot)
    "6006",    # Event Log service stopped (shutdown)
    "6008",    # Unexpected shutdown
    "6013",    # System uptime
    "41",      # Kernel-Power: unexpected reboot
    "1074",    # System shutdown/restart (user-initiated)
    "7040",    # Service start type changed — handled by service_config_change family; only mark system if description is benign
    "4608",    # Windows is starting up
    "4609",    # Windows is shutting down
    "4616",    # System time changed (common on DCs)
    "4800",    # Workstation locked
    "4801",    # Workstation unlocked
    "4802",    # Screen saver invoked
    "4803",    # Screen saver dismissed
})

# Keywords that indicate infrastructure / network / DNS / connectivity issue
INFRA_KEYWORDS: frozenset[str] = frozenset({
    "dns",
    "name resolution",
    "timed out",
    "time out",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_gc._tcp",
    "domain controller",
    "dc._msdcs",
    "tailscale",
    ".ts.net",
    "vpn",
    "network unreachable",
    "dhcp",
    "ip address",
    "connectivity",
    "netlogon",
    "kdc unavailable",
    "winrm",
    "wsus",
})

# Keywords that indicate a vulnerability finding (not an incident)
VULN_KEYWORDS: frozenset[str] = frozenset({
    "cve-",
    "affects",
    "vulnerability",
    "vulnerable package",
    "package less than",
    "outdated version",
    "security advisory",
    "patch available",
    "unpatched",
    "nvd",
    "osvdb",
})

# High-signal security event IDs (near-always worth full investigation)
HIGH_SIGNAL_EVENT_IDS: frozenset[str] = frozenset({
    "1102",   # Security audit log cleared
    "517",    # (legacy) audit log cleared
    "7045",   # New service installed
    "4697",   # Service installed (Security log)
    "4698",   # Scheduled task created
    "4702",   # Scheduled task updated
    "4720",   # User account created
    "4726",   # User account deleted
    "4728",   # Member added to global group
    "4732",   # Member added to local group
    "4756",   # Member added to universal group
    "4740",   # Account locked out
})

# Medium-signal security event IDs
MEDIUM_SIGNAL_EVENT_IDS: frozenset[str] = frozenset({
    "4625",   # Failed logon
    "4648",   # Logon with explicit credentials
    "4672",   # Special privileges assigned
    "4688",   # Process create
    "4689",   # Process terminate
    "4699",   # Scheduled task deleted
    "4700",   # Scheduled task enabled
    "4701",   # Scheduled task disabled
    "4719",   # System audit policy changed
    "4768",   # Kerberos TGT request
    "4769",   # Kerberos service ticket request
    "4771",   # Kerberos pre-auth failed
    "4776",   # NTLM auth
    "5140",   # Network share accessed
    "5145",   # Network share object checked
    "5156",   # WFP permitted connection
    "5157",   # WFP blocked connection
})

# Event families that signal incoming security event (from _determine_event_family)
SECURITY_FAMILIES: frozenset[str] = frozenset({
    "process_create",
    "process_terminate",
    "logon_failure",
    "logon_success",
    "logon_explicit",
    "service_install",
    "scheduled_task",
    "account_mgmt",
    "group_mgmt",
    "log_cleared",
    "policy_change",
    "kerberos",
    "object_access",
    "registry_event",
    "privilege_use",
    "network",
    "firewall",
    # Sysmon
    "driver_load",
    "image_load",
    "create_remote_thread",
    "raw_access_read",
    "process_access",
    "wmi_filter",
    "wmi_consumer",
    "wmi_subscription",
    "process_tamper",
    "pipe_created",
    "pipe_connected",
})

INFRA_FAMILIES: frozenset[str] = frozenset({
    "dns_infra",
    "network_infra",
    "winrm_infra",
    "service_state",
    "log_service",
    "hyperv_infra",
    "powershell_infra",
    "wmi_infra",
    "bits_infra",
})

# Action template lists per recommended_action_mode
ACTION_TEMPLATES: dict[str, list[str]] = {
    "ignore_or_noise": [
        "Keine sicherheitsseitige Maßnahme erforderlich.",
        "Optional als Noise-Event markieren und in Baseline aufnehmen.",
        "Nur beobachten, falls Häufung oder Kontext-Änderung auftritt.",
    ],
    "infra_troubleshooting": [
        "DNS-/Netzwerk-/Erreichbarkeitskonfiguration prüfen.",
        "Baseline vergleichen: ist dieses Event neu oder wiederkehrend?",
        "Zeitlich benachbarte Infrastruktur-Events korrelieren.",
        "Monitoring auf Wiederholungen einrichten, falls Problem persistiert.",
        "Tailscale/VPN-DNS-Konfiguration validieren falls ts.net-Domäne beteiligt.",
    ],
    "patch_management": [
        "Betroffenes Paket/Produkt und installierte Version identifizieren.",
        "Update-/Patch-Pfad prüfen und nach Kritikalität priorisieren.",
        "Exponierung bewerten: lokal, serverseitig, internetnah?",
        "Workaround dokumentieren, falls Patch nicht sofort einspielbar.",
        "Nach Patch: erneut scannen zur Verifikation.",
    ],
    "security_investigation": [
        "Zeitlich benachbarte Security-Events auf diesem Host korrelieren.",
        "Parent/Child-Prozesskette prüfen.",
        "Benutzer-/Anmeldekontext validieren.",
        "Host-Baseline auf Abweichungen prüfen.",
        "Gleiches Muster auf anderen Hosts suchen (laterale Ausbreitung?).",
    ],
}

# Forbidden action categories per event class (used for prompt guardrails)
FORBIDDEN_ACTIONS: dict[str, frozenset[str]] = {
    EVENT_CLASS_SYSTEM: frozenset({
        "isolate_host", "reset_credentials", "check_process_tree",
        "check_hash", "check_persistence", "mitre_mapping",
    }),
    EVENT_CLASS_INFRA: frozenset({
        "isolate_host", "reset_credentials", "check_hash", "check_persistence",
    }),
    EVENT_CLASS_VULN: frozenset({
        "isolate_host", "reset_credentials", "check_process_tree", "check_parent_child",
    }),
    EVENT_CLASS_SECURITY: frozenset(),
}


# ── Data class ────────────────────────────────────────────────────────────────

@dataclass
class EventDecision:
    event_class: str
    severity: Severity
    risk_score: float
    confidence: str
    should_run_ai: bool
    allow_mitre: bool
    allow_host_isolation: bool
    allow_process_tree_actions: bool
    allow_credential_actions: bool
    reasoning: list[str] = field(default_factory=list)
    recommended_action_mode: str = "generic"


# ── Classification ────────────────────────────────────────────────────────────

def classify_event(
    event_id: str | None,
    rule_description: str | None,
    event_explanation: str | None,
    groups: list[str] | None,
    event_family: str | None,
) -> str:
    """Return one of EVENT_CLASS_* for the event.

    Priority: system → vulnerability → infrastructure → security (default).
    """
    eid = str(event_id or "").strip()

    # 1. Hard-coded system / noise event IDs (never security-relevant)
    if eid in SAFE_SYSTEM_EVENT_IDS:
        return EVENT_CLASS_SYSTEM

    # 2. Build a combined text haystack for keyword matching
    haystack = " ".join(filter(None, [
        str(rule_description or ""),
        str(event_explanation or ""),
        str(event_family or ""),
        " ".join(groups or []),
    ])).lower()

    # 3. Vulnerability finding
    if any(kw in haystack for kw in VULN_KEYWORDS):
        return EVENT_CLASS_VULN

    # 4. Infrastructure / network event
    if any(kw in haystack for kw in INFRA_KEYWORDS):
        return EVENT_CLASS_INFRA
    if event_family in INFRA_FAMILIES:
        return EVENT_CLASS_INFRA

    # 5. Known security families / event IDs
    if event_family in SECURITY_FAMILIES:
        return EVENT_CLASS_SECURITY
    if eid in HIGH_SIGNAL_EVENT_IDS or eid in MEDIUM_SIGNAL_EVENT_IDS:
        return EVENT_CLASS_SECURITY

    # Default: keep as security so unknown events stay auditable
    return EVENT_CLASS_SECURITY


# ── Decision engine ───────────────────────────────────────────────────────────

def decide_event(
    event_id: str | None,
    rule_level: int | None,
    rule_description: str | None,
    event_explanation: str | None,
    groups: list[str] | None,
    event_family: str | None,
    profile_name: str | None = None,
    has_baseline_deviation: bool = False,
    has_ti_match: bool = False,
) -> EventDecision:
    """Pre-AI risk gate.  Returns an EventDecision with guardrails for the AI."""
    eid = str(event_id or "").strip()
    rl = max(0, int(rule_level or 0))
    reasoning: list[str] = []

    event_class = classify_event(
        event_id=event_id,
        rule_description=rule_description,
        event_explanation=event_explanation,
        groups=groups,
        event_family=event_family,
    )

    # ── SYSTEM ────────────────────────────────────────────────────────────────
    if event_class == EVENT_CLASS_SYSTEM:
        reasoning.append("Bekanntes System-/Wartungsereignis – kein Sicherheitsindikator.")
        return EventDecision(
            event_class=event_class,
            severity="info",
            risk_score=1.0,
            confidence="high",
            should_run_ai=False,
            allow_mitre=False,
            allow_host_isolation=False,
            allow_process_tree_actions=False,
            allow_credential_actions=False,
            reasoning=reasoning,
            recommended_action_mode="ignore_or_noise",
        )

    # ── INFRASTRUCTURE ────────────────────────────────────────────────────────
    if event_class == EVENT_CLASS_INFRA:
        reasoning.append("Infrastruktur-/DNS-/Erreichbarkeitsproblem – kein direkter Angriffsindikator.")
        risk_score = 2.5
        severity: Severity = "low"

        if has_baseline_deviation:
            risk_score += 0.5
            reasoning.append("Event ist neu oder weicht vom Baseline-Muster ab.")
        if has_ti_match:
            risk_score += 2.0
            severity = "medium"
            reasoning.append("Zusätzlicher Threat-Intelligence-Kontext vorhanden.")
        if rl >= 10:
            risk_score += 1.0
            reasoning.append(f"Wazuh-Regel-Level {rl} erhöht Aufmerksamkeit.")

        return EventDecision(
            event_class=event_class,
            severity=severity,
            risk_score=min(risk_score, 4.5),
            confidence="medium",
            should_run_ai=True,
            allow_mitre=False,
            allow_host_isolation=False,
            allow_process_tree_actions=False,
            allow_credential_actions=False,
            reasoning=reasoning,
            recommended_action_mode="infra_troubleshooting",
        )

    # ── VULNERABILITY ─────────────────────────────────────────────────────────
    if event_class == EVENT_CLASS_VULN:
        reasoning.append("Schwachstellenhinweis (CVE/Package-Befund) – kein aktiver Incident.")
        risk_score = 7.0 if rl >= 10 else 6.0
        severity = "high" if risk_score >= 7.0 else "medium"

        if has_baseline_deviation:
            risk_score = min(risk_score + 0.5, 9.0)
            reasoning.append("Paket/Version ist neu gegenüber Baseline.")
        if has_ti_match:
            risk_score = min(risk_score + 1.0, 9.5)
            severity = "critical"
            reasoning.append("CVE hat aktive Exploit-TI-Treffer.")

        return EventDecision(
            event_class=event_class,
            severity=severity,
            risk_score=risk_score,
            confidence="high",
            should_run_ai=True,
            allow_mitre=False,
            allow_host_isolation=False,
            allow_process_tree_actions=False,
            allow_credential_actions=False,
            reasoning=reasoning,
            recommended_action_mode="patch_management",
        )

    # ── SECURITY ──────────────────────────────────────────────────────────────
    reasoning.append("Sicherheitsrelevantes Event – vollständige Analyse.")
    risk_score = 3.0

    if eid in HIGH_SIGNAL_EVENT_IDS:
        risk_score += 4.0
        reasoning.append(f"Event-ID {eid} hat hohen Signalwert (log-clear / service-install / account-mgmt).")
    elif eid in MEDIUM_SIGNAL_EVENT_IDS:
        risk_score += 2.0
        reasoning.append(f"Event-ID {eid} hat mittleren Signalwert.")

    # Rule-level contribution (capped at +2.0)
    risk_score += min(rl * 0.25, 2.0)

    if has_baseline_deviation:
        risk_score += 1.0
        reasoning.append("Baseline-Abweichung vorhanden.")
    if has_ti_match:
        risk_score += 2.0
        reasoning.append("Threat-Intelligence-Treffer vorhanden.")

    # Developer-profile discount for expected dev events
    if profile_name and "dev" in profile_name.lower() and eid in {"4688", "4624", "4634"}:
        risk_score -= 0.5
        reasoning.append("Teilweise durch Entwicklerprofil erklärbar.")

    risk_score = max(0.5, min(risk_score, 10.0))

    if risk_score >= 8.5:
        severity = "critical"
    elif risk_score >= 7.0:
        severity = "high"
    elif risk_score >= 4.0:
        severity = "medium"
    else:
        severity = "low"

    return EventDecision(
        event_class=event_class,
        severity=severity,
        risk_score=risk_score,
        confidence="medium",
        should_run_ai=True,
        allow_mitre=True,
        allow_host_isolation=severity in {"high", "critical"},
        allow_process_tree_actions=True,
        allow_credential_actions=eid in {"4625", "4648", "4672", "4771", "4776"},
        reasoning=reasoning,
        recommended_action_mode="security_investigation",
    )


# ── Prompt helpers ────────────────────────────────────────────────────────────

def build_decision_context_block(decision: EventDecision) -> str:
    """Build a structured context block to inject into AI prompts."""
    forbidden = FORBIDDEN_ACTIONS.get(decision.event_class, frozenset())
    action_mode_hints = ACTION_TEMPLATES.get(decision.recommended_action_mode, [])

    lines = [
        "── Decision Engine (VERBINDLICH – überschreibe diese Regeln NICHT) ───────",
        f"event_class            : {decision.event_class}",
        f"severity               : {decision.severity.upper()}  ← MAXIMALWERT – nicht überschreiten ohne Beweis",
        f"risk_score             : {decision.risk_score:.1f} / 10",
        f"confidence             : {decision.confidence}",
        f"MITRE-Mapping erlaubt  : {'JA' if decision.allow_mitre else 'NEIN – kein MITRE für diesen Event-Typ'}",
        f"Host-Isolation erlaubt : {'JA (nur bei eindeutiger Evidenz)' if decision.allow_host_isolation else 'NEIN – nicht angemessen für diesen Event-Typ'}",
        f"Process-Tree-Aktionen  : {'erlaubt' if decision.allow_process_tree_actions else 'VERBOTEN'}",
        f"Credential-Aktionen    : {'erlaubt' if decision.allow_credential_actions else 'VERBOTEN'}",
        f"Empfohlener Aktionsmodus: {decision.recommended_action_mode}",
        f"Engine-Begründung      : {'; '.join(decision.reasoning)}",
    ]
    if forbidden:
        lines.append(f"VERBOTENE Aktionskategorien: {', '.join(sorted(forbidden))}")
    if action_mode_hints:
        lines.append("Aktions-Template (verwende diese als Basis):")
        for hint in action_mode_hints:
            lines.append(f"  • {hint}")
    lines.append("──────────────────────────────────────────────────────────────────────────")
    return "\n".join(lines)


# ── Static result (no-AI path) ────────────────────────────────────────────────

def build_static_explain_result(smart_event: object, decision: EventDecision) -> dict:
    """Return a pre-built result dict for events where AI should not run.

    `smart_event` is a SnipenSmartEvent.  We accept `object` to avoid circular
    imports; all field accesses use getattr with defaults.
    """
    event_id = getattr(smart_event, "event_id", None) or "n/a"
    host = getattr(smart_event, "host", None) or "n/a"
    rule_desc = getattr(smart_event, "rule_description", None) or getattr(smart_event, "rule_id", None) or "n/a"

    actions = ACTION_TEMPLATES.get(decision.recommended_action_mode, [
        "Keine sicherheitsseitige Maßnahme erforderlich.",
    ])

    if decision.event_class == EVENT_CLASS_SYSTEM:
        summary = (
            f"Event-ID {event_id} auf Host {host} entspricht einem typischen "
            "System- bzw. Wartungsereignis und ist aktuell nicht sicherheitsrelevant. "
            f"Regel: {rule_desc}. "
            "Dieses Event kann für Noise-Reduktion in die Baseline aufgenommen werden."
        )
        why_suspicious = "Kein direkter Sicherheitsindikator – reines OS-/Wartungs-Event."
        against_it = (
            "Das Ereignis passt vollständig zu normalem Systemverhalten "
            f"(Event-ID {event_id} ist ein bekanntes Windows-Systemevent)."
        )
    else:
        summary = (
            f"Event-ID {event_id} auf Host {host}. Klasse: {decision.event_class}. "
            f"Regel: {rule_desc}. Risiko: {decision.severity.upper()} (Score {decision.risk_score:.1f}/10). "
            f"{'; '.join(decision.reasoning)}"
        )
        why_suspicious = "; ".join(decision.reasoning) or "Kein direkter Sicherheitsindikator."
        against_it = None

    return {
        "summary": summary,
        "severity": decision.severity,
        "risk_score": decision.risk_score,
        "confidence": decision.confidence,
        "mitre_techniques": [],
        "remediation": actions,
        "next_checks": actions,
        "why_suspicious": why_suspicious,
        "against_it": against_it,
        "unusual_behavior": [],
        "deviations": [],
        "suspicious_fields": [],
        "ran_ai": False,
    }
