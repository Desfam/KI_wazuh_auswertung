from __future__ import annotations

import json
from typing import Any


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