"""Artifact-type-aware Action Builder for Wazuh event remediation.

Maps each event/finding to a concrete ActionPlan based on the ACTUAL evidence
type present in the event data.  Prevents generic, misleading remediation text
(e.g. "process creation" without Event 4688, "ssh usage" without ssh.exe).

Public API
----------
classify_artifact(event: dict) -> str
    Returns one of the ARTIFACT_* constants.

build_action_plan(event: dict) -> ActionPlan
    Returns a fully-populated ActionPlan for a single event.

build_action_plans_for_insights(top_event_ids, top_rule_ids, top_processes, ti_matches) -> list[ActionPlan]
    Returns a deduplicated list of ActionPlans derived from fullscan insight data.

build_guardrail_block(event: dict) -> str
    Returns a prompt-injection block listing FORBIDDEN phrases based on missing
    evidence (for use in explain_event / remediate_event AI prompts).

validate_action_list(actions: list[str], event: dict) -> list[str]
    Post-AI validation: rewrites any action item that uses forbidden phrasing
    not supported by the evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ── Artifact type constants ───────────────────────────────────────────────────

ARTIFACT_LOGON = "logon"
ARTIFACT_PROCESS = "process"
ARTIFACT_SERVICE_INSTALL = "service_install"
ARTIFACT_SERVICE_CONFIG = "service_config"
ARTIFACT_REGISTRY = "registry"
ARTIFACT_FIM = "fim"
ARTIFACT_VULNERABILITY = "vulnerability"
ARTIFACT_INFRASTRUCTURE = "infrastructure"
ARTIFACT_SYSTEM_NOISE = "system_noise"
ARTIFACT_UNKNOWN = "unknown"

# ── Classification tables ─────────────────────────────────────────────────────

_SYSTEM_NOISE_EVENT_IDS: frozenset[str] = frozenset({
    "16384",  # Software Protection Service successfully scheduled
    "16394",  # Software Protection service state
    "10016",  # DCOM: permission mismatch (harmless by design)
    "4608",   # Windows starting up
    "4609",   # Windows shutting down
    "4800",   # Workstation locked
    "4801",   # Workstation unlocked
    "4802",   # Screen saver invoked
    "4803",   # Screen saver dismissed
    "6005",   # Event Log service started (boot)
    "6006",   # Event Log service stopped (shutdown)
    "6008",   # Unexpected shutdown (informational)
    "6013",   # System uptime
    "41",     # Kernel-Power: unexpected reboot
    "1074",   # System shutdown/restart (user-initiated)
    "7036",   # Service state change (running/stopped) — too noisy for IR
})

_LOGON_EVENT_IDS: frozenset[str] = frozenset({
    "4624", "4625", "4634", "4647", "4648", "4672",
    "4768", "4769", "4771", "4776",
    "528", "529", "539", "540",  # legacy Security event IDs
})

_SERVICE_INSTALL_EVENT_IDS: frozenset[str] = frozenset({
    "7045", "4697",
})

_SERVICE_CONFIG_EVENT_IDS: frozenset[str] = frozenset({
    "7040",
})

_PROCESS_EVENT_IDS: frozenset[str] = frozenset({
    "4688", "4689",
})

# Wazuh rule IDs known to trigger on registry/FIM integrity
_REGISTRY_RULE_IDS: frozenset[str] = frozenset({
    "750", "594", "551", "553",
})

_REGISTRY_KEYWORDS: frozenset[str] = frozenset({
    "registry", "regedit", "reg.exe", "hklm", "hkcu", "hkey",
    "bam", "userassist", "amcache", "shimcache", "appcompat",
    "regkey", "registrykey",
})

_FIM_KEYWORDS: frozenset[str] = frozenset({
    "integrity checksum changed", "fim", "file integrity", "syscheck",
    "file modified", "file added", "file deleted", "checksum",
})

_VULN_KEYWORDS: frozenset[str] = frozenset({
    "cve-", "vulnerability", "vulnerable package", "patch available",
    "outdated version", "security advisory", "unpatched", "nvd",
    "affected version",
})

_INFRA_KEYWORDS: frozenset[str] = frozenset({
    "dns", "name resolution", "timed out", "time out", "domain controller",
    "tailscale", ".ts.net", "vpn", "network unreachable", "dhcp",
    "connectivity", "netlogon", "kdc unavailable", "winrm",
})

# Tools that appear in BAM/UserSettings traces — known RMM + remote-access tools
_RMM_ADMIN_TOOLS: frozenset[str] = frozenset({
    "meshagent.exe", "tacticalrmm.exe", "ninjarmm.exe",
    "screenconnect.exe", "anydesk.exe", "teamviewer.exe", "dameware.exe",
    "connectwise.exe", "splashtop.exe",
})

# Admin/shell tools that are expected in admin environments but should be noted
_ADMIN_SHELL_TOOLS: frozenset[str] = frozenset({
    "powershell.exe", "cmd.exe", "sc.exe", "reg.exe", "net.exe", "net1.exe",
    "wmic.exe", "certutil.exe", "mshta.exe", "cscript.exe", "wscript.exe",
    "regsvr32.exe", "rundll32.exe", "msiexec.exe",
})

# SSH-related process names (must be explicitly present before "ssh usage" is valid)
_SSH_PROCESSES: frozenset[str] = frozenset({
    "ssh.exe", "sshd.exe", "sshd", "ssh", "openssh",
    "plink.exe", "putty.exe",
})

# ── ActionPlan dataclass ──────────────────────────────────────────────────────

@dataclass
class ActionPlan:
    """Structured, evidence-driven action plan for a specific artifact type."""
    title: str
    artifact_type: str
    why: list[str] = field(default_factory=list)
    how: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_remediation_list(self) -> list[str]:
        """Flatten into a string list for SnipenExplainResult.remediation."""
        lines: list[str] = [f"[{self.artifact_type.upper()}] {self.title}"]
        if self.why:
            lines.append("Warum: " + "; ".join(self.why))
        lines.extend(self.how)
        return lines

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "artifact_type": self.artifact_type,
            "why": self.why,
            "how": self.how,
            "evidence": self.evidence,
        }


# ── Artifact classifier ───────────────────────────────────────────────────────

def classify_artifact(event: dict[str, Any]) -> str:
    """Return one of the ARTIFACT_* constants for the given event dict.

    Priority order: system_noise → service_install → service_config →
    logon → process → registry → fim → vulnerability → infrastructure → unknown.

    The `event` dict should contain keys like: event_id, rule_id,
    rule_description, process, user, command_line, service_name, registry_key.
    """
    eid = str(event.get("event_id") or "").strip()
    rule_id = str(event.get("rule_id") or "").strip()
    rule_desc = str(event.get("rule_description") or "").lower()
    system_msg = str(event.get("system_message") or "").lower()
    haystack = f"{rule_desc} {system_msg}"

    # 1. System noise — always highest priority, never escalate
    if eid in _SYSTEM_NOISE_EVENT_IDS:
        return ARTIFACT_SYSTEM_NOISE

    # 2. Service install (7045, 4697) — before generic logon check
    if eid in _SERVICE_INSTALL_EVENT_IDS:
        return ARTIFACT_SERVICE_INSTALL

    # 3. Service config change (7040)
    if eid in _SERVICE_CONFIG_EVENT_IDS:
        return ARTIFACT_SERVICE_CONFIG

    # 4. Logon events
    if eid in _LOGON_EVENT_IDS:
        return ARTIFACT_LOGON

    # 5. Process creation
    if eid in _PROCESS_EVENT_IDS:
        return ARTIFACT_PROCESS

    # 6. Registry / FIM by rule_id or description keywords
    if rule_id in _REGISTRY_RULE_IDS:
        return ARTIFACT_REGISTRY
    if any(kw in haystack for kw in _REGISTRY_KEYWORDS):
        return ARTIFACT_REGISTRY
    if any(kw in haystack for kw in _FIM_KEYWORDS):
        return ARTIFACT_FIM

    # 7. Vulnerability finding
    if any(kw in haystack for kw in _VULN_KEYWORDS):
        return ARTIFACT_VULNERABILITY

    # 8. Infrastructure / network
    if any(kw in haystack for kw in _INFRA_KEYWORDS):
        return ARTIFACT_INFRASTRUCTURE

    return ARTIFACT_UNKNOWN


# ── Dedicated builders ────────────────────────────────────────────────────────

def build_logon_action(event: dict[str, Any]) -> ActionPlan:
    eid = str(event.get("event_id") or "")
    user = (
        event.get("user")
        or event.get("target_user")
        or event.get("subject_user")
        or "unbekannt"
    )
    ip = event.get("ip_address") or None
    logon_type = event.get("logon_type") or None

    why: list[str] = []
    if eid == "4625":
        why.append(f"Login-Failure (4625) für Benutzer '{user}' erkannt")
    elif eid == "4624":
        why.append(f"Erfolgreiche Anmeldung (4624) für Benutzer '{user}'")
    elif eid == "4648":
        why.append(f"Anmeldung mit expliziten Credentials (4648) durch '{user}'")
    elif eid == "4672":
        why.append(f"Sonderrechte zugewiesen (4672) an '{user}'")
    elif eid in {"4768", "4769", "4771"}:
        why.append(f"Kerberos-Ereignis ({eid}) für '{user}'")
    else:
        why.append(f"Anmelde-Event (ID {eid}) für Benutzer '{user}'")

    if ip and ip not in ("-", "", "::1", "127.0.0.1"):
        why.append(f"Herkunfts-IP: {ip}")
    if logon_type:
        why.append(f"Logon-Type: {logon_type} (2=Interaktiv, 3=Netzwerk, 10=Remote)")

    how = [
        f"Logon-Type prüfen (2=Interaktiv, 3=Netzwerk, 10=Remote — aktuell: {logon_type or 'unbekannt'})",
        f"Herkunfts-IP validieren — intern, VPN, oder extern? (aktuell: {ip or 'n/a'})",
        "Maschinen-Account (endet auf $) von Benutzer-Account unterscheiden",
        "Zeitliche Häufung: mehrere 4625 gefolgt von 4624? → Brute-Force-Indikator",
        "4672 (Special Privilege) in zeitlicher Nähe? → Privilege-Escalation prüfen",
        "Arbeitszeit- und Standortkontext prüfen: Anmeldung außerhalb erwarteter Zeiten?",
    ]

    evidence = [v for v in [eid, str(user), str(ip or "")] if v and v not in ("-", "n/a")]
    return ActionPlan(
        title="Prüfe Anmelde- und Sitzungskontext",
        artifact_type=ARTIFACT_LOGON,
        why=why,
        how=how,
        evidence=evidence,
    )


def build_service_action(event: dict[str, Any]) -> ActionPlan:
    eid = str(event.get("event_id") or "")
    svc = event.get("service_name") or "unbekannt"

    if eid in _SERVICE_INSTALL_EVENT_IDS:
        return ActionPlan(
            title="Prüfe neue Dienstinstallation",
            artifact_type=ARTIFACT_SERVICE_INSTALL,
            why=[
                f"Event {eid} = neuer Windows-Service installiert: '{svc}'",
                "Service-Installationen sind ein häufiger Persistenzmechanismus (T1543.003)",
            ],
            how=[
                f'Service-Binärpfad prüfen: sc qc "{svc}"',
                "Digitale Signatur der Service-EXE validieren (Sigcheck / VirusTotal)",
                "Wer hat den Service installiert? (Account + Zeitpunkt aus Event-Kontext)",
                "War die Installation autorisiert / geplant (Deployment, Update)?",
                f'Service "{svc}" auf anderen Hosts suchen → laterale Ausbreitung?',
                "Starttyp prüfen: AUTOMATIC bei unbekanntem Service ist kritisch",
            ],
            evidence=[eid, str(svc)],
        )
    else:  # 7040 — service CONFIG change, not install
        return ActionPlan(
            title="Prüfe Service-Konfigurationsänderung",
            artifact_type=ARTIFACT_SERVICE_CONFIG,
            why=[
                f"Event 7040 = Service-Konfiguration geändert (Start-Typ oder Pfad): '{svc}'",
                "Häufig durch Windows Updates, Group Policy oder Konfigurationstools ausgelöst — kein direkter Angriffsbeweis",
            ],
            how=[
                f'Welche Eigenschaft wurde geändert (Start-Typ, Pfad, Konto)? sc qc "{svc}"',
                "Autorisierte Änderung? (Admin-Aktion, Update-Vorgang, Deployment-Tool)",
                "Event 4688 (Prozesserstellung) im selben Zeitfenster → auslösenden Prozess identifizieren",
                "Nur als verdächtig einstufen wenn Service unbekannt oder Pfad/Binary suspekt ist",
                "HINWEIS: 7040 ist KEINE Service-Installation — kein neuer Service, nur Konfigurationsänderung",
            ],
            evidence=[eid, str(svc)],
        )


def build_process_action(event: dict[str, Any]) -> ActionPlan:
    """Only call this builder when Event 4688 / 4689 is actually present."""
    process = event.get("process") or "unbekannt"
    cmd = event.get("command_line") or ""
    eid = str(event.get("event_id") or "4688")

    return ActionPlan(
        title="Prüfe Prozesserstellung und Ausführungskontext",
        artifact_type=ARTIFACT_PROCESS,
        why=[
            f"Event {eid} = Prozesserstellung: '{process}'",
            "Elternprozess-Kind-Kette und Command-Line sind primäre Indikatoren",
        ],
        how=[
            f"Elternprozess von '{process}' identifizieren — erwartet für dieses Host-Profil?",
            f"Command-Line auf Obfuscation / suspicious Flags prüfen: {cmd[:100] if cmd else 'n/a'}",
            "Hash der Executable validieren (Get-FileHash / VirusTotal / Sigcheck)",
            "LOLBin-Muster prüfen: certutil, mshta, regsvr32, rundll32, wmic → besonders kritisch",
            "Netzwerkverbindungen des Prozesses nach Ausführung prüfen (5156/5157, NetFlow)",
            "Prozesshierarchie: Office/Browser als Parent für PowerShell/cmd ist Warnsignal",
        ],
        evidence=[eid, str(process)] + ([cmd[:80]] if cmd else []),
    )


def build_registry_action(event: dict[str, Any]) -> ActionPlan:
    """Builder for registry integrity / BAM / FIM registry events.

    Critical: BAM/UserSettings entries are EXECUTION HISTORY in the registry,
    NOT process creation events.  Never describe them as process creation.
    """
    rule_id = str(event.get("rule_id") or "")
    registry_key = str(event.get("registry_key") or "")
    rule_desc = str(event.get("rule_description") or "")
    process = str(event.get("process") or "").lower()
    cmd = str(event.get("command_line") or "").lower()
    combined = f"{registry_key} {process} {cmd}".lower()

    found_rmm = [t for t in sorted(_RMM_ADMIN_TOOLS) if t in combined]
    found_admin = [t for t in sorted(_ADMIN_SHELL_TOOLS) if t in combined]

    why: list[str] = [
        f"Registry-Integritätsänderung erkannt (Regel {rule_id}: {rule_desc or 'Registrierungsänderung'})",
        "BAM/UserSettings-Einträge dokumentieren Ausführungshistorie — kein direkter Angriffsbeweis",
    ]
    if found_rmm:
        why.append(f"RMM/Fernwartungs-Tool-Traces in Registry/BAM: {', '.join(found_rmm)}")
    if found_admin:
        why.append(f"Admin-/Shell-Tool-Traces in Registry/BAM: {', '.join(found_admin)}")

    how = [
        "Registry-Pfade aus Event-Daten extrahieren und nach Familie gruppieren:",
        "  • BAM\\UserSettings → Ausführungshistorie (welche Tools wurden gestartet)",
        "  • W32Time, SharedAccess, Tcpip → Windows-Konfiguration (meist legitim)",
        "  • VSS, FirewallRules → Sicherheitskonfiguration (kritischer bewerten)",
        "Admin/RMM-Tool-Referenzen separat bewerten — Fernwartungstools wie MeshAgent, TacticalRMM sind ggf. autorisiert",
        "Zeitpunkt und Häufigkeit der Registry-Änderungen mit normalem Betrieb vergleichen",
        "KEINE Prozesserstellungs-Maßnahmen anwenden — dies sind Registry/BAM-Spuren, keine 4688-Events",
        "Nur eskalieren wenn: unbekannte Tools, ungewöhnliche Pfade ODER Kombination mit 7045/4624-Cluster",
    ]

    evidence = [v for v in [rule_id, registry_key[:80], rule_desc] if v]
    return ActionPlan(
        title="Prüfe Registry-/BAM-/FIM-Änderungen",
        artifact_type=ARTIFACT_REGISTRY,
        why=why,
        how=how,
        evidence=evidence[:4],
    )


def build_fim_action(event: dict[str, Any]) -> ActionPlan:
    rule_desc = str(event.get("rule_description") or "")
    path = str(event.get("registry_key") or event.get("process") or "")

    return ActionPlan(
        title="Prüfe Dateiintegritäts-Änderung (FIM)",
        artifact_type=ARTIFACT_FIM,
        why=[
            f"FIM-/Integritätsprüfung angesprochen: {rule_desc or 'Checksumme geändert'}",
            "Geänderte Datei: " + (path or "Pfad unbekannt"),
        ],
        how=[
            "Betroffene Datei identifizieren und Pfad prüfen — erwartetes Systemverzeichnis?",
            "Änderungskontext: durch welchen Prozess / welchen Nutzer wurde die Datei geändert?",
            "Hash-Vergleich: vor vs. nach der Änderung (FIM-Baseline)",
            "Zeitlicher Kontext: gleichzeitige Anmeldung oder Prozesserstellung?",
            "Systemdateien-Änderungen außerhalb von Update-Zeitfenstern sind kritisch",
        ],
        evidence=[str(event.get("rule_id") or ""), path[:80]],
    )


def build_vuln_action(event: dict[str, Any]) -> ActionPlan:
    rule_desc = str(event.get("rule_description") or "")

    return ActionPlan(
        title="Prüfe Schwachstelle und Patch-Status",
        artifact_type=ARTIFACT_VULNERABILITY,
        why=[
            f"Schwachstellenhinweis: {rule_desc or 'CVE/Paket-Befund erkannt'}",
            "Kein aktiver Incident — Patch-Management erforderlich",
        ],
        how=[
            "Betroffenes Paket und installierte Version identifizieren",
            "Update-/Patch-Pfad prüfen und nach Kritikalität priorisieren (CVSS-Score)",
            "Exponierung bewerten: lokal verfügbar, serverseitig, internetnah?",
            "Workaround dokumentieren falls Patch nicht sofort einspielbar",
            "Nach Patch: erneut scannen zur Verifikation",
        ],
        evidence=[str(event.get("rule_id") or ""), rule_desc[:80]],
    )


def build_infra_action(event: dict[str, Any]) -> ActionPlan:
    rule_desc = str(event.get("rule_description") or "")
    eid = str(event.get("event_id") or "")

    return ActionPlan(
        title="Prüfe Infrastruktur- oder Erreichbarkeitsproblem",
        artifact_type=ARTIFACT_INFRASTRUCTURE,
        why=[
            f"Infrastruktur-Ereignis (ID {eid}): {rule_desc or 'DNS/Netzwerk/Erreichbarkeitsproblem'}",
            "Kein direkter Angriffsbeweis — ohne Korrelation mit Auth-Failures kein IR-Handlungsbedarf",
        ],
        how=[
            "DNS-Server auf Erreichbarkeit und Antwortzeiten prüfen",
            "Tailscale/VPN-DNS-Konfiguration validieren (besonders bei *.ts.net-Domains)",
            "Domain-Controller-Erreichbarkeit prüfen (LDAP SRV-Lookup fehlgeschlagen?)",
            "Event-Häufigkeit mit Baseline vergleichen — neu oder chronisch wiederkehrend?",
            "Erst als Sicherheitsrisiko bewerten wenn 4625/4768/4769-Cluster gleichzeitig auftritt",
        ],
        evidence=[eid, rule_desc[:80]],
    )


def build_system_noise_action(event: dict[str, Any]) -> ActionPlan:
    eid = str(event.get("event_id") or "")
    noise_eids = event.get("system_noise_eids") or [eid]

    noise_descriptions = {
        "16384": "Software Protection Service scheduled (Lizenzprüfung — reines OS-Event)",
        "10016": "DCOM-Berechtigungsfehler (bekannte Windows-Designschwäche — harmlos)",
        "7036":  "Service-Status-Änderung (Start/Stop) — Betriebs-Event",
        "6005":  "Event Log gestartet (System-Boot)",
        "6006":  "Event Log gestoppt (System-Shutdown)",
        "4800":  "Workstation gesperrt",
        "4801":  "Workstation entsperrt",
    }
    desc_parts = [noise_descriptions.get(e, f"Event {e}") for e in noise_eids[:5]]

    return ActionPlan(
        title="Als System-/Noise-Ereignis einordnen",
        artifact_type=ARTIFACT_SYSTEM_NOISE,
        why=[
            f"Event-ID(s) {', '.join(noise_eids[:5])} = bekannte System-/Betriebs-Events",
            "; ".join(desc_parts),
        ],
        how=[
            "Kein IR-Handlungsbedarf — reine Betriebsereignisse",
            "Optional: als Noise-Baseline markieren um künftige Alerts zu unterdrücken",
            "Nur erneut bewerten wenn ungewöhnliche Häufung oder gleichzeitig mit Security-Events auftritt",
        ],
        evidence=noise_eids[:5],
    )


def _build_unknown_action(event: dict[str, Any]) -> ActionPlan:
    eid = str(event.get("event_id") or "unbekannt")
    rule_desc = str(event.get("rule_description") or "")

    return ActionPlan(
        title="Allgemeine Sicherheitsüberprüfung",
        artifact_type=ARTIFACT_UNKNOWN,
        why=[
            f"Event-ID {eid}: {rule_desc or 'kein spezifisches Angriffsmuster identifiziert'}",
        ],
        how=[
            "Events chronologisch validieren — echtes Angriffsmuster oder Betrieb?",
            "Betroffene Nutzer und Prozesse in Event-Details nachverfolgen",
            "Zeitlich benachbarte Events auf demselben Host korrelieren",
            "Host im nächsten 24h-Fenster engmaschig monitoren",
        ],
        evidence=[eid, rule_desc[:60]],
    )


# ── Dispatcher ────────────────────────────────────────────────────────────────

def build_action_plan(event: dict[str, Any]) -> ActionPlan:
    """Classify the event and dispatch to the correct builder."""
    artifact_type = classify_artifact(event)

    if artifact_type == ARTIFACT_LOGON:
        return build_logon_action(event)
    if artifact_type == ARTIFACT_SERVICE_INSTALL:
        return build_service_action(event)
    if artifact_type == ARTIFACT_SERVICE_CONFIG:
        return build_service_action(event)
    if artifact_type == ARTIFACT_PROCESS:
        return build_process_action(event)
    if artifact_type == ARTIFACT_REGISTRY:
        return build_registry_action(event)
    if artifact_type == ARTIFACT_FIM:
        return build_fim_action(event)
    if artifact_type == ARTIFACT_VULNERABILITY:
        return build_vuln_action(event)
    if artifact_type == ARTIFACT_INFRASTRUCTURE:
        return build_infra_action(event)
    if artifact_type == ARTIFACT_SYSTEM_NOISE:
        return build_system_noise_action(event)
    return _build_unknown_action(event)


# ── Fullscan multi-event planner ──────────────────────────────────────────────

def build_action_plans_for_insights(
    top_event_ids: list[tuple[str, int]],
    top_rule_ids: list[tuple[str, int]] | None = None,
    top_processes: list[tuple[str, int]] | None = None,
    ti_matches: int = 0,
) -> list[ActionPlan]:
    """Build a deduplicated, priority-ordered list of ActionPlans from fullscan
    insight data.  Only plans for evidence that is ACTUALLY PRESENT are included.

    Args:
        top_event_ids:  list of (event_id_str, count) tuples from Counter.most_common()
        top_rule_ids:   list of (rule_id_str, count) tuples
        top_processes:  list of (process_name, count) tuples
        ti_matches:     number of threat-intel hits

    Returns:
        list of ActionPlan ordered by security relevance.
    """
    plans: list[ActionPlan] = []
    seen_types: set[str] = set()

    event_id_set: set[str] = {eid for eid, _ in (top_event_ids or [])}
    process_set: set[str] = {p.lower() for p, _ in (top_processes or [])}
    rule_id_set: set[str] = {rid for rid, _ in (top_rule_ids or [])}

    def _add(plan: ActionPlan) -> None:
        if plan.artifact_type not in seen_types:
            plans.append(plan)
            seen_types.add(plan.artifact_type)

    # Priority 1 — TI matches (always first if present)
    if ti_matches > 0:
        _add(ActionPlan(
            title=f"Prüfe Threat-Intel-Treffer ({ti_matches}x)",
            artifact_type="threat_intel",
            why=[f"{ti_matches} Threat-Intelligence-Treffer im Scan erkannt"],
            how=[
                "Betroffene Indikatoren (IPs, Hashes, Domains) in TI-Plattform validieren",
                "Host isolieren wenn aktiver C2-Traffic bestätigt",
                "TI-Kontext mit zeitnahen Prozess- und Netzwerk-Events korrelieren",
            ],
            evidence=[f"{ti_matches} TI matches"],
        ))

    # Priority 2 — Service install (7045, 4697)
    svc_install_eid = next((eid for eid, _ in (top_event_ids or [])
                             if eid in _SERVICE_INSTALL_EVENT_IDS), None)
    if svc_install_eid:
        _add(build_service_action({"event_id": svc_install_eid, "service_name": "unbekannt"}))

    # Priority 3 — Logon failures / auth events
    if "4625" in event_id_set:
        cnt_4625 = next((c for e, c in (top_event_ids or []) if e == "4625"), 1)
        _add(build_logon_action({
            "event_id": "4625",
            "user": f"{cnt_4625}x Login-Failure erfasst",
        }))
    elif "4624" in event_id_set:
        _add(build_logon_action({"event_id": "4624"}))

    # Priority 4 — Registry/FIM (by rule_id)
    registry_rule = next((rid for rid, _ in (top_rule_ids or [])
                           if rid in _REGISTRY_RULE_IDS), None)
    if registry_rule:
        _add(build_registry_action({"rule_id": registry_rule}))

    # Priority 5 — Process creation (only if 4688 is actually present)
    if event_id_set & _PROCESS_EVENT_IDS:
        top_proc = (top_processes or [("unbekannt", 0)])[0][0]
        _add(build_process_action({
            "event_id": "4688",
            "process": top_proc,
        }))

    # Priority 6 — Service config change (7040)
    if "7040" in event_id_set:
        _add(build_service_action({"event_id": "7040", "service_name": "unbekannt"}))

    # Priority 7 — System noise (always last, informational)
    noise_eids = [eid for eid, _ in (top_event_ids or []) if eid in _SYSTEM_NOISE_EVENT_IDS]
    if noise_eids:
        _add(build_system_noise_action({
            "event_id": noise_eids[0],
            "system_noise_eids": noise_eids,
        }))

    # Fallback
    if not plans:
        plans.append(_build_unknown_action({
            "event_id": (top_event_ids or [("n/a", 0)])[0][0],
        }))

    return plans


def action_plans_to_next_steps(plans: list[ActionPlan]) -> list[str]:
    """Convert ActionPlan list to a flat next_steps string list for fullscan reports."""
    steps: list[str] = []
    for plan in plans:
        steps.append(f"**[{plan.artifact_type.upper()}]** {plan.title}")
        if plan.why:
            steps.append(f"  Warum: {'; '.join(plan.why[:2])}")
        for h in plan.how[:3]:
            steps.append(f"  → {h}")
    return steps


# ── AI prompt guardrail block ─────────────────────────────────────────────────

def build_guardrail_block(event: dict[str, Any]) -> str:
    """Generate a structured guardrail text block for injection into AI prompts.

    Explicitly forbids certain phrases when the required evidence is absent.
    """
    artifact_type = classify_artifact(event)
    eid = str(event.get("event_id") or "")
    process = str(event.get("process") or "").lower()
    rule_id = str(event.get("rule_id") or "")

    lines: list[str] = [
        "── Artifact-Type Guardrails (VERBINDLICH – NICHT überschreiben) ──────────",
        f"Erkannter Artifact-Typ : {artifact_type.upper()}",
        f"Vorhandene Evidence    : event_id={eid or 'n/a'}, rule_id={rule_id or 'n/a'}, "
        f"process={process or 'n/a'}",
    ]

    forbidden: list[str] = []

    # 1. Process creation — only valid with 4688
    if eid not in _PROCESS_EVENT_IDS:
        forbidden.append(
            f'❌ "process creation" / "Prozesserstellung" / "Prozessschaffung" / '
            f'"Vielzahl von Prozessschaffungen" — Event 4688/4689 NICHT vorhanden '
            f'(aktuelles Event: {eid or "n/a"})'
        )

    # 2. New service install — only valid with 7045/4697
    if eid not in _SERVICE_INSTALL_EVENT_IDS:
        forbidden.append(
            f'❌ "new service install" / "neue Dienstinstallation" / "neuer Service installiert" — '
            f'Event 7045/4697 NICHT vorhanden; '
            f'bei Event 7040 nur "Service-Konfigurationsänderung" verwenden'
        )

    # 3. SSH usage — only valid when ssh process is actually present
    if not any(s in process for s in _SSH_PROCESSES):
        forbidden.append(
            '❌ "ssh usage" / "SSH-Nutzung" / "SSH-Verbindung" / "ssh.exe" — '
            'ssh.exe/sshd NICHT in Prozessdaten vorhanden'
        )

    # 4. Event 16384 — always noise
    if eid == "16384":
        forbidden.append(
            '❌ Event 16384 als sicherheitsrelevant oder angriffsindizierend einstufen — '
            'Dies ist immer System-Noise: Software Protection Service scheduled (Lizenzprüfung)'
        )

    # 5. Registry/BAM — do not describe as process creation
    if rule_id in _REGISTRY_RULE_IDS or artifact_type == ARTIFACT_REGISTRY:
        forbidden.append(
            '❌ BAM/Registry-Einträge als "Prozesserstellung" oder "Prozessausführung" beschreiben — '
            'BAM/UserSettings sind Ausführungshistorie IM Registry, kein 4688-Event'
        )

    if forbidden:
        lines.append("VERBOTEN (fehlende Evidenz):")
        lines.extend(forbidden)

    # Allowed hints per artifact type
    if artifact_type == ARTIFACT_REGISTRY:
        lines += [
            "ERLAUBT für REGISTRY:",
            '✅ "Registry-Änderung", "BAM-Trace", "BAM/UserSettings-Eintrag", "Ausführungshistorie im Registry"',
            '✅ RMM/Admin-Tools in BAM als Ausführungshistorie erwähnen, NICHT als laufende oder gerade gestartete Prozesse',
        ]
    elif artifact_type == ARTIFACT_SYSTEM_NOISE:
        lines += [
            "ERLAUBT für SYSTEM_NOISE:",
            '✅ "System-/Noise-Ereignis", "kein IR-Handlungsbedarf", "Betriebsereignis", "Baseline aufnehmen"',
        ]
    elif artifact_type == ARTIFACT_SERVICE_CONFIG:
        lines += [
            "ERLAUBT für SERVICE_CONFIG (7040):",
            '✅ "Service-Konfigurationsänderung" (Start-Typ, Pfad geändert)',
            '❌ NICHT "Service-Installation" oder "neuer Service" — das ist 7045/4697',
        ]
    elif artifact_type == ARTIFACT_LOGON:
        lines += [
            "ERLAUBT für LOGON:",
            '✅ Anmeldung, Login-Failure, Brute-Force-Muster (nur wenn 4625-Cluster vorhanden)',
            '✅ Logon-Type, Herkunfts-IP, Zeitkontext',
        ]

    lines.append("──────────────────────────────────────────────────────────────────────────")
    return "\n".join(lines)


# ── Hard validation (post-AI output sanitizer) ────────────────────────────────

# Each entry: (phrase_to_detect, evidence_field, required_values_set_or_None)
# If phrase is found AND required evidence is absent → rewrite the item
_FORBIDDEN_PHRASE_RULES: list[tuple[str, str, frozenset[str] | None]] = [
    # Process creation without 4688
    ("process creation",           "event_id", _PROCESS_EVENT_IDS),
    ("prozesserstellung",          "event_id", _PROCESS_EVENT_IDS),
    ("prozessschaffung",           "event_id", _PROCESS_EVENT_IDS),
    ("vielzahl von prozess",       "event_id", _PROCESS_EVENT_IDS),
    # New service install without 7045/4697
    ("new service install",        "event_id", _SERVICE_INSTALL_EVENT_IDS),
    ("neue dienstinstallation",    "event_id", _SERVICE_INSTALL_EVENT_IDS),
    ("neuer service installiert",  "event_id", _SERVICE_INSTALL_EVENT_IDS),
    # SSH without ssh process
    ("ssh usage",                  "process",  _SSH_PROCESSES),
    ("ssh-nutzung",                "process",  _SSH_PROCESSES),
    ("ssh-verbindung",             "process",  _SSH_PROCESSES),
]


def _has_evidence(event: dict[str, Any], field: str, required: frozenset[str] | None) -> bool:
    """Return True if the event contains acceptable evidence for the phrase."""
    val = str(event.get(field) or "").lower()
    if not val or val in ("-", "n/a"):
        return False
    if required is None:
        return True
    return any(r.lower() in val or val in r.lower() for r in required)


def validate_action_text(text: str, event: dict[str, Any]) -> str:
    """Rewrite a single action string if it contains forbidden phrases without evidence."""
    text_lower = text.lower()
    for phrase, field, required in _FORBIDDEN_PHRASE_RULES:
        if phrase in text_lower and not _has_evidence(event, field, required):
            repl = f"[⚠ TERM KORRIGIERT: '{phrase}' nicht durch Event-Daten belegt]"
            text = re.sub(re.escape(phrase), repl, text, flags=re.IGNORECASE)
    return text


def validate_action_list(actions: list[str], event: dict[str, Any]) -> list[str]:
    """Validate a list of action strings.  Returns list with corrected items."""
    return [validate_action_text(a, event) for a in actions]
