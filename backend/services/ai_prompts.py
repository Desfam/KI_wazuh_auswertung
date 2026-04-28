from __future__ import annotations

import json
from typing import Any


def build_fullscan_ai_prompt(
    risk_level: str,
    risk_score: float,
    risk_score_reason: str,
    profile_context: str,
    baseline_text: str,
    baseline_diff_block: str,
) -> str:
    """Prompt for the AI refinement pass of a Full Scan report.

    The model must output ONLY the sections listed below — no intro, no recap,
    no generic SOC filler.  Every claim must be traceable to the provided data.
    """
    return (
        "You are a SOC analyst writing a concise decision note. "
        "Output ONLY the sections below in exactly this order. "
        "Write in German. Use Markdown. "
        "Do NOT add any other sections, introductions, or closing remarks.\n\n"

        "══════ OUTPUT STRUCTURE (copy headings verbatim) ══════\n\n"

        "## Evidence\n"
        "### Bestätigt\n"
        "List only facts that are directly present in the scan data. "
        "No hypotheses. No invented processes, IPs, commands, or users. "
        "If nothing is confirmed, write '- Keine bestätigten Indikatoren'.\n\n"

        "### Prüfungswürdig\n"
        "List items that need follow-up but are NOT yet confirmed as malicious:\n"
        "- TI-Treffer ohne IOC-Details: als 'TI-Validierung erforderlich' markieren, nicht als bestätigt\n"
        "- Service-Änderungen (7040/7045): review-würdig, nicht automatisch kritisch\n"
        "- Neue Baseline-Abweichungen falls vorhanden\n"
        "- 4625 gefolgt von 4624 vom selben Nutzer/Host: als möglicher Brute-Force markieren, nicht bestätigt\n"
        "- Auffällige Command Lines nur wenn tatsächlich vorhanden\n"
        "If nothing needs review, write '- Nichts prüfungswürdig'.\n\n"

        "### Nicht beobachtet\n"
        "Only list what was explicitly NOT found:\n"
        "- Keine verdächtige Command Line\n"
        "- Keine bestätigte Angriffskette\n"
        "- Keine bestätigte Persistenz\n"
        "- Kein bestätigtes C2\n"
        "- Keine bestätigte Lateral Movement\n"
        "Add or remove bullets based on actual data, do not invent negations.\n\n"

        "## Bewertungsbegründung\n"
        "One sentence: why is the risk score what it is? "
        "Reference the actual evidence. "
        "Do NOT contradict the pre-computed risk level.\n\n"

        "══════ STRICT RULES ══════\n"
        f"1. Risk Level is pre-computed: **{risk_level}** (Score {risk_score}/10). "
        "You MUST use this. You may explain it, but never contradict it.\n"
        f"   Engine reason: {risk_score_reason or '—'}\n"
        "2. NEVER invent: PowerShell commands, LSASS access, C2 domains, lateral movement, "
        "persistence mechanisms, specific IP addresses, process names, or usernames "
        "that do not appear in the provided data.\n"
        "3. 4624/4634 are normal logon/logoff events. Only flag them if correlated with 4625, "
        "unusual source, privileged user, or a confirmed attack chain.\n"
        "4. lsass.exe is normal. Only flag it if a dump/access/commandline/path anomaly is present.\n"
        "5. MITRE rule mapping alone is NOT evidence of compromise.\n"
        "6. TI-Treffer without IOC details = 'TI-Validierung erforderlich', not confirmed threat.\n"
        "7. For server profiles: service changes are review-worthy, not automatically high risk.\n"
        "8. For sysadmin profiles: admin activity is expected unless suspicious behavior patterns exist.\n"
        "9. If baseline deviations = 0 and no suspicious behavior flags exist, explicitly state risk is reduced.\n"
        "10. Do NOT output 'Keine Auffälligkeiten' alongside specific suspicious findings.\n\n"

        "══════ CONTEXT ══════\n"
        f"Profile: {profile_context or 'Standard (kein spezifisches Profil)'}\n\n"
        f"Baseline: {baseline_text or 'Keine Baseline vorhanden.'}\n"
        f"Baseline Diff: {baseline_diff_block or 'Keine Abweichungen erkannt.'}\n"
    )


def build_structured_group_prompt(group: dict[str, Any]) -> str:
    return (
        "You are a SOC analyst. Review the grouped Wazuh finding and return valid JSON only with the keys "
        "suspicious, severity, reason, recommended_checks. Severity must be one of critical, high, medium, low. "
        f"Finding summary: {json.dumps({
            'host': group.get('host'),
            'platform': group.get('platform'),
            'event_id': group.get('event_id'),
            'rule_id': group.get('rule_id'),
            'rule_description': group.get('rule_description'),
            'count': group.get('count'),
            'group_key': group.get('group_key'),
            'local_severity': group.get('local_severity'),
            'local_score': group.get('local_score'),
            'confidence': group.get('confidence'),
            'first_seen': group.get('first_seen'),
            'last_seen': group.get('last_seen')
        })}"
    )


def build_structured_finding_prompt(finding: dict[str, Any]) -> str:
    return (
        "You are a senior SOC analyst working in a Wazuh-based investigation workflow.\n"
        "Your task is to assess one finding conservatively and factually.\n"
        "Do not invent facts. Use only the provided finding.\n"
        "Treat known benign operational patterns as lower risk if the finding suggests routine system or service behavior.\n"
        "Mark something as suspicious only if there is a concrete technical reason.\n"
        "If the evidence is weak or mixed, reflect that clearly in the reason.\n\n"
        "Severity rules:\n"
        "- critical: strong indicator of compromise, destructive action, confirmed malicious execution, log clearing with suspicious context, known malicious persistence\n"
        "- high: highly suspicious persistence, privilege abuse, malicious execution pattern, clear attack behavior, known bad TI match\n"
        "- medium: suspicious but not confirmed, repeated auth failures, unusual process behavior, suspicious service/task creation, notable registry persistence clues\n"
        "- low: weak or ambiguous suspicion, isolated event, explainable admin or service behavior, limited evidence\n\n"
        "Return valid JSON only with exactly these keys:\n"
        "{\n"
        '  "suspicious": true or false,\n'
        '  "severity": "critical" | "high" | "medium" | "low",\n'
        '  "reason": "short but concrete technical explanation",\n'
        '  "recommended_checks": ["check 1", "check 2", "check 3"]\n'
        "}\n\n"
        f"Finding JSON:\n{json.dumps(finding, ensure_ascii=False)}"
    )
#--

def default_chat_request_prompt() -> str:
    return (
        "Erstelle ein operatives SOC-Lagebild auf Basis der aktuellen Wazuh-Findings.\n"
        "Kein generisches Zusammenfassen. Kein Aufzählen ohne Bewertung.\n"
        "Priorisiere stark. Sei präzise. Bleibe handlungsfähig.\n\n"
        "Verwende exakt diese Struktur:\n\n"
        "## 1. Executive Summary\n"
        "Maximal 3 Sätze. Was ist die aktuelle Lage? Was dominiert? Gibt es Hinweise auf aktive Bedrohung?\n\n"
        "## 2. Top 3 – Kritischste Hosts / Auffälligkeiten\n"
        "Nenne die 3 dringlichsten Punkte mit: Host, Risk-Score (wenn bekannt), konkretem Auffälligkeitsmuster, kurzem Warum.\n"
        "Beispiel-Format: 'SWE-13 (DEV) – Risk 9.0 → hohe Prozessrate (Event 4688), mögl. Skriptautomation'\n\n"
        "## 3. Neue oder ungewöhnliche Entwicklungen\n"
        "Was weicht von erwartbarem Betrieb ab? Gibt es Häufungen, Verteilungen über mehrere Hosts, zeitliche Cluster?\n"
        "Korreliere: Prozesserstellung + Service-Install + Logon-Failures falls vorhanden.\n\n"
        "## 4. Bewertung mit Profil-Kontext\n"
        "Nutze Host-Profile (DEV, SRV, ADMIN etc.) zur Einordnung. Was ist für das Profil normal, was nicht?\n"
        "Falls kein Profil bekannt: explizit benennen → Risiko schwer bewertbar.\n\n"
        "## 5. Risiko-Einschätzung\n"
        "Stufe: LOW / MEDIUM / HIGH (mit Begründung in 1–2 Sätzen).\n"
        "Gibt es konkrete Indikatoren für Persistenz, Lateral Movement, Exfiltration oder Privilege Escalation?\n\n"
        "## 6. Konkrete Maßnahmen\n"
        "Mindestens 3 konkrete, host-spezifische Maßnahmen. Keine generischen 'Überprüfe alles'-Aussagen.\n"
        "Format: 'Host → was genau prüfen → womit / warum'\n\n"
        "## Confidence\n"
        "Schätze deine Bewertungssicherheit ein (z.B. 0.65) und benenne, was dir fehlt (Profile, Baseline, Korrelationen).\n\n"
        "Regeln:\n"
        "- Nutze NUR die vorhandenen Daten. Erfinde keine Hosts, Events oder Scores.\n"
        "- Wenn Daten fehlen, benenne das explizit statt zu halluzinieren.\n"
        "- Antworte auf Deutsch in sauberem Markdown.\n"
        "- Priorisiere immer über Aufzählen."
    )

def conversation_context_guidance() -> str:
    return (
        "\n\nNutze die bisherige Konversation als Priorisierungs- und Kontextquelle. "
        "Wenn der Nutzer bestimmte Events, Hosts oder Muster bereits als bekannt, wiederkehrend "
        "oder betrieblich harmlos eingeordnet hat, berücksichtige das ausdrücklich in der Bewertung. "
        "Wiederhole in solchen Fällen nicht einfach dieselbe Standardwarnung. "
        "Wenn sich neue Daten vom bisherigen Kontext unterscheiden, weise gezielt auf diese Abweichung hin."
    )

def build_chat_assistant_prompt(
    report_context: str | None,
    history_text: str,
    message: str,
    direct_question: bool = False,
) -> str:
    if direct_question:
        output_instruction = (
            "Output format:\n"
            "Answer the user's specific question directly and concisely.\n"
            "Do NOT generate a full SOC briefing or use the Lagebild/Schlüsselindikatoren/Risikobewertung/Nächste Schritte format.\n"
            "Focus only on what the user asked. Use Markdown where it helps readability.\n"
        )
    else:
        output_instruction = (
            "Output structure (STRICT — use exactly these 6 sections + Confidence):\n"
            "## 1. Executive Summary\n"
            "## 2. Top 3 – Kritischste Hosts / Auffälligkeiten\n"
            "## 3. Neue oder ungewöhnliche Entwicklungen\n"
            "## 4. Bewertung mit Profil-Kontext\n"
            "## 5. Risiko-Einschätzung\n"
            "## 6. Konkrete Maßnahmen\n"
            "## Confidence\n\n"
            "Rules:\n"
            "- Executive Summary: max 3 sentences — current situation, dominant pattern, active threat indicator Y/N\n"
            "- Top 3: host + risk score (if known) + specific pattern + concrete why (not just 'many events')\n"
            "- Neue Entwicklungen: correlate Process Creation + Service Install + Logon Failures if all present\n"
            "- Profil-Kontext: use host profiles (DEV/SRV/ADMIN) to judge what is normal; flag missing profiles\n"
            "- Risiko-Einschätzung: LOW / MEDIUM / HIGH + 1–2 sentence reason + mention Persistenz/LM/Exfil/PrivEsc if relevant\n"
            "- Konkrete Maßnahmen: ≥3 host-specific actions in format 'Host → what to check → how/why'; NO generic advice\n"
            "- Confidence: numerical score (0.0–1.0) + explicit list of what is missing (profiles, baseline, correlations)\n"
        )

    return (
        "You are a Wazuh investigation assistant inside a desktop SOC workflow.\n"
        "Respond in detailed operational German unless the user explicitly asks for a short answer.\n"
        "Always format the response as Markdown.\n"
        "Use only the provided report context and conversation context as factual basis.\n"
        "Do not invent hosts, event counts, rule IDs, severities, users, IPs, or findings.\n"
        "If something is not present in the data, say so explicitly.\n\n"
        "Reasoning style:\n"
        "- prioritize concrete technical signals over generic wording\n"
        "- separate suspicious findings from likely benign findings\n"
        "- take prior conversation context seriously when classifying recurring or harmless patterns\n"
        "- avoid repeating the same generic SOC summary if the user asks follow-up questions\n"
        "- be specific and actionable\n\n"
        + output_instruction + "\n"
        f"Report context:\n{report_context or 'No report context available.'}\n\n"
        f"Conversation so far:\n{history_text or 'No previous messages.'}\n\n"
        f"Current user request:\n{message}"
    )