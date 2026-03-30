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
        "Analysiere die aktuellen Wazuh-Findings aus dem letzten Lauf wie ein SOC-Analyst.\n"
        "Ziel ist keine generische Zusammenfassung, sondern eine operative Lageeinschätzung.\n\n"
        "Beantworte insbesondere:\n"
        "1. Welche Findings sind technisch wirklich auffällig?\n"
        "2. Welche Findings wirken eher harmlos oder betrieblich erklärbar?\n"
        "3. Welche Hosts sollten priorisiert geprüft werden?\n"
        "4. Welche nächsten Schritte sind konkret sinnvoll?\n\n"
        "Arbeite faktenbasiert nur mit den vorhandenen Daten.\n"
        "Wenn Informationen fehlen, benenne das explizit.\n"
        "Antworte auf Deutsch in sauberem Markdown.\n"
        "Nutze klare Überschriften und konkrete, umsetzbare Punkte."
    )

def conversation_context_guidance() -> str:
    return (
        "\n\nNutze die bisherige Konversation als Priorisierungs- und Kontextquelle. "
        "Wenn der Nutzer bestimmte Events, Hosts oder Muster bereits als bekannt, wiederkehrend "
        "oder betrieblich harmlos eingeordnet hat, berücksichtige das ausdrücklich in der Bewertung. "
        "Wiederhole in solchen Fällen nicht einfach dieselbe Standardwarnung. "
        "Wenn sich neue Daten vom bisherigen Kontext unterscheiden, weise gezielt auf diese Abweichung hin."
    )

def build_chat_assistant_prompt(report_context: str | None, history_text: str, message: str) -> str:
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
        "Default output structure:\n"
        "## Lagebild\n"
        "## Schlüsselindikatoren\n"
        "## Risikobewertung\n"
        "## Nächste Schritte\n\n"
        "In 'Schlüsselindikatoren', mention concrete hosts, event IDs, rule IDs, processes, users, IPs, or counts only if present.\n"
        "In 'Risikobewertung', clearly distinguish between confirmed concern, plausible suspicion, and likely benign behavior.\n"
        "In 'Nächste Schritte', give practical SOC actions, not generic advice.\n\n"
        f"Report context:\n{report_context or 'No report context available.'}\n\n"
        f"Conversation so far:\n{history_text or 'No previous messages.'}\n\n"
        f"Current user request:\n{message}"
    )