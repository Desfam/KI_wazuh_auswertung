from __future__ import annotations
import json
import re

from db.database import get_active_connection
from schemas.types import AnalysisRunRequest, ChatRequest, ChatResponse, ChatScriptSummary, ChatTaskItem
from services.ai_prompts import conversation_context_guidance, default_chat_request_prompt
from services.ai_runtime import start_service
from services.ollama_client import chat_with_context
from services.remote_vm_script import run_remote_script_report


def _ensure_local_ai_started(connection: dict) -> None:
    ollama_url = str(connection.get("ollama_url") or "")
    if "127.0.0.1" in ollama_url or "localhost" in ollama_url or "0.0.0.0" in ollama_url:
        start_service()


def _build_rich_context(parsed_report: dict) -> str:
    """Build AI context from structured JSON only (no VM-generated narrative text)."""
    total = int(parsed_report.get("total_alerts", 0) or 0)
    relevant = int(parsed_report.get("relevant_alerts", 0) or 0)
    top_hosts = parsed_report.get("top_hosts", {}) or {}

    lines = [
        "=== STRUKTURIERTE DATEN (JSON-REFERENZ) ===",
        f"Gesamt-Alerts: {total}",
        f"Relevante Findings: {relevant}",
        "",
        "Top Hosts:",
    ]
    for host, count in list(top_hosts.items())[:10]:
        lines.append(f"- {host}: {count}")

    findings = parsed_report.get("findings")
    if isinstance(findings, list) and findings:
        lines.extend(["", "Top Findings:"])
        for finding in findings[:30]:
            severity = finding.get("local_severity") or finding.get("ai_severity") or finding.get("severity") or "?"
            rule = finding.get("rule_description") or finding.get("description") or finding.get("event_id") or finding.get("rule_id") or "?"
            host = finding.get("host", "?")
            platform = finding.get("platform", "?")
            count = finding.get("count", 0)
            suspicious = finding.get("suspicious", False)
            reason = finding.get("reason", "")
            lines.append(
                f"- [{str(severity).upper()}] {host} ({platform}) | {rule} | x{count} | "
                f"verdaechtig={suspicious} | {reason}"
            )
        return "\n".join(lines)

    windows_entries = parsed_report.get("windows", []) or []
    linux_entries = parsed_report.get("linux", []) or []
    lines.extend([
        "",
        f"Windows-Gruppen: {len(windows_entries)}",
        f"Linux-Gruppen: {len(linux_entries)}",
        "",
        "Top Windows-Gruppen:",
    ])
    for item in windows_entries[:20]:
        lines.append(
            f"- {item.get('host', '?')} | Event={item.get('event_id') or item.get('rule_id') or '?'} | "
            f"Count={item.get('count', 0)} | Level={item.get('level', '?')} | Desc={item.get('description', '?')}"
        )
    lines.append("")
    lines.append("Top Linux-Gruppen:")
    for item in linux_entries[:20]:
        lines.append(
            f"- {item.get('host', '?')} | Rule={item.get('rule_id') or '?'} | "
            f"Count={item.get('count', 0)} | Level={item.get('level', '?')} | Desc={item.get('description', '?')}"
        )

    return "\n".join(lines)


def _severity_rank(value: str) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return order.get(str(value).lower(), 0)


def _build_tasks(parsed_report: dict) -> list[ChatTaskItem]:
    findings = parsed_report.get("findings") or []
    if not isinstance(findings, list):
        return []

    sorted_findings = sorted(
        findings,
        key=lambda item: (
            _severity_rank(item.get("ai_severity") or item.get("local_severity") or "low"),
            1 if item.get("suspicious") else 0,
            int(item.get("local_score", 0)),
            int(item.get("count", 0)),
        ),
        reverse=True,
    )

    tasks: list[ChatTaskItem] = []
    for index, finding in enumerate(sorted_findings[:25], start=1):
        severity = str(finding.get("ai_severity") or finding.get("local_severity") or "low").lower()
        event_id = finding.get("event_id")
        rule_id = finding.get("rule_id")
        event_label = event_id or rule_id or "n/a"
        rule_description = finding.get("rule_description")
        title = f"[{severity.upper()}] {finding.get('host', '?')} - {rule_description or event_label}"
        details = (
            f"Platform={finding.get('platform', '?')} | Event={event_label} | "
            f"Count={finding.get('count', 0)} | Reason={finding.get('reason', 'n/a')}"
        )
        checks = finding.get("recommended_checks") or []
        if not isinstance(checks, list):
            checks = [str(checks)]

        # Extract MITRE IDs
        mitre_raw = finding.get("mitre_ids") or finding.get("mitre_techniques") or []
        if not isinstance(mitre_raw, list):
            mitre_raw = []
        mitre_ids = [str(m) for m in mitre_raw[:4]]

        tasks.append(
            ChatTaskItem(
                task_id=f"task-{index:02d}",
                host=str(finding.get("host", "unknown-host")),
                severity=severity,
                title=title,
                details=details,
                recommended_checks=[str(check) for check in checks[:5]],
                event_id=str(event_id) if event_id else None,
                rule_id=str(rule_id) if rule_id else None,
                rule_description=str(rule_description) if rule_description else None,
                platform=str(finding.get("platform", "")) or None,
                count=int(finding.get("count") or 1),
                reason=str(finding.get("reason", "")) or None,
                local_score=float(finding["local_score"]) if finding.get("local_score") is not None else None,
                mitre_ids=mitre_ids,
            )
        )
    return tasks


def _build_detailed_24h_summary(parsed_report: dict, tasks: list[ChatTaskItem]) -> str:
    total = int(parsed_report.get("total_alerts", 0) or 0)
    relevant = int(parsed_report.get("relevant_alerts", 0) or 0)
    critical = sum(1 for t in tasks if t.severity == "critical")
    high = sum(1 for t in tasks if t.severity == "high")

    severity_hint = ""
    if critical:
        severity_hint = f" darunter **{critical} kritisch**,"
    if high:
        severity_hint += f" **{high} hoch**"

    lines = [
        "✅ **Analyse abgeschlossen.**",
        "",
        f"- Alerts gesamt: **{total}** | Relevant: **{relevant}**",
        f"- **{len(tasks)} Tasks** wurden erstellt –{severity_hint} sieh links in der Task-Liste.",
        "",
        "_Stelle mir konkrete Fragen zu den Findings, z. B.: 'Was ist auf TACTICAL_RMM passiert?' oder 'Erklaere task-01.'_",
    ]
    return "\n".join(lines)


def _looks_like_raw_report_dump(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    markers = [
        "=== wazuh ai 24h report ===",
        "=== detaillierte 24h host-uebersicht",
        "=== automatisch erstellte tasks",
        "top hosts by relevant alerts",
        "generated at:",
    ]
    marker_hits = sum(1 for marker in markers if marker in lowered)
    has_many_task_lines = len(re.findall(r"\[task-\d{2}\]", lowered)) >= 3
    return marker_hits >= 2 or has_many_task_lines


def _build_question_fallback_answer(message: str, parsed_report: dict, tasks: list[ChatTaskItem]) -> str:
    top_hosts = parsed_report.get("top_hosts", {}) or {}
    relevant = int(parsed_report.get("relevant_alerts", 0) or 0)
    total = int(parsed_report.get("total_alerts", 0) or 0)
    top_task_lines: list[str] = []
    for task in tasks[:5]:
        top_task_lines.append(f"- **{task.severity.upper()}** {task.host}: {task.title}")

    source_lines = [
        "- Strukturierte JSON-Analyse aus aktuellem VM-Skript-Lauf",
        "- `parsed_report.findings`",
        "- `parsed_report.top_hosts`",
        "- automatisch generierte `generated_tasks`",
    ]

    lines = [
        "## Ergebnis aus aktuellem Lauf",
        "",
        f"- **Gesamt-Alerts:** {total}",
        f"- **Relevante Findings:** {relevant}",
        "",
        "### Wichtigste Findings",
    ]
    if top_task_lines:
        lines.extend(top_task_lines)
    else:
        lines.append("- Keine priorisierten Findings vorhanden.")

    if top_hosts:
        lines.extend(["", "### Top Hosts"])
        for host, count in list(top_hosts.items())[:5]:
            lines.append(f"- **{host}:** {count}")

    if "quelle" in message.lower() or "quell" in message.lower() or "source" in message.lower() or "daten" in message.lower():
        lines.extend(["", "### Quelldaten", *source_lines])

    lines.extend([
        "",
        "> Hinweis: Roh-Reportblöcke wurden unterdrückt, damit die Antwort nur aus strukturierten, aktuellen Daten besteht.",
    ])
    return "\n".join(lines)


def _try_build_host_detail_answer(message: str, parsed_report: dict) -> str | None:
    if not message or not isinstance(parsed_report, dict):
        return None

    findings = parsed_report.get("findings")
    if not isinstance(findings, list) or not findings:
        return None

    message_lower = message.lower()
    needs_detail = any(
        token in message_lower
        for token in [
            "was genau",
            "welche prozesse",
            "welche events",
            "details",
            "genau wird",
            "what exactly",
        ]
    )
    if not needs_detail:
        return None

    hosts = []
    for item in findings:
        host = str(item.get("host") or "").strip()
        if host and host not in hosts:
            hosts.append(host)

    selected_host = None
    for host in sorted(hosts, key=len, reverse=True):
        if host.lower() in message_lower:
            selected_host = host
            break

    if not selected_host:
        return None

    host_findings = [
        item for item in findings
        if str(item.get("host") or "").strip().lower() == selected_host.lower()
    ]
    if not host_findings:
        return None

    host_findings = sorted(host_findings, key=lambda item: int(item.get("count") or 0), reverse=True)
    total_for_host = sum(int(item.get("count") or 0) for item in host_findings)

    lines = [
        f"## Details fuer Host {selected_host}",
        "",
        f"- Gefundene Event-Gruppen: **{len(host_findings)}**",
        f"- Summe gezaehlter Vorkommnisse: **{total_for_host}**",
        "",
        "### Was genau wurde erkannt?",
    ]

    for item in host_findings[:12]:
        severity = str(item.get("ai_severity") or item.get("local_severity") or "unknown").upper()
        desc = item.get("rule_description") or item.get("description") or "(keine Regelbeschreibung)"
        event_id = item.get("event_id") or item.get("rule_id") or "n/a"
        count = int(item.get("count") or 0)
        suspicious = bool(item.get("suspicious"))
        reason = str(item.get("reason") or "")
        lines.append(
            f"- **[{severity}]** Event `{event_id}` | {desc} | x{count} | "
            f"verdaechtig={str(suspicious).lower()}"
            + (f" | Grund: {reason}" if reason else "")
        )

    lines.extend([
        "",
        "> Hinweis: Diese Antwort kommt direkt aus den strukturierten Findings des letzten 24h-Laufs.",
    ])
    return "\n".join(lines)


def handle_chat(request: ChatRequest) -> ChatResponse:
    connection = get_active_connection()
    if not connection:
        raise RuntimeError("No active connection configured")

    _ensure_local_ai_started(connection)

    report_context = request.report_context
    script_report: str | None = None
    script_summary: ChatScriptSummary | None = None
    generated_tasks: list[ChatTaskItem] = []
    report_txt_content: str | None = None
    report_json_content: str | None = None
    ran_script = False
    parsed_report: dict = {}

    should_run_script = bool(request.run_script)
    if should_run_script:
        requested_lookback = request.lookback_hours if request.lookback_hours is not None else int(connection.get("lookback_hours") or 24)
        profile = request.analysis_profile
        analysis_request = AnalysisRunRequest(
            mode="vm-script",
            lookback_hours=requested_lookback,
            query_size=10000,
            include_noise=bool(connection.get("default_include_noise")),
            run_ai=False,
            only_windows=bool(connection.get("default_only_windows")),
            only_linux=bool(connection.get("default_only_linux")),
            event_ids=profile.event_ids if profile and profile.event_ids else None,
            min_rule_level=profile.min_rule_level if profile else None,
            max_findings=profile.max_findings if profile else None,
            max_events_per_host=profile.max_events_per_host if profile else None,
        )
        result = run_remote_script_report(connection, analysis_request)
        ran_script = True
        script_report = result["report_text"].strip()
        report_txt_content = result["report_text"]
        report_json_content = result["report_json"]

        parsed_report = result.get("parsed_report", {})
        report_context = _build_rich_context(parsed_report)
        generated_tasks = _build_tasks(parsed_report)

        script_summary = ChatScriptSummary(
            lookback_hours=analysis_request.lookback_hours,
            total_alerts=int(result.get("total_alerts", 0)),
            relevant_alerts=int(result.get("relevant_alerts", 0)),
        )
    else:
        if request.report_json_content:
            try:
                parsed_report = json.loads(request.report_json_content)
                if not report_context:
                    report_context = _build_rich_context(parsed_report)
                generated_tasks = _build_tasks(parsed_report)
            except Exception:
                parsed_report = {}

    message = request.message.strip()

    ai_prompt = message if message else default_chat_request_prompt()
    if message:
        ai_prompt += conversation_context_guidance()
    direct_host_answer = _try_build_host_detail_answer(message, parsed_report)
    if direct_host_answer:
        reply = direct_host_answer
    else:
        reply = chat_with_context(
            connection=connection,
            message=ai_prompt,
            history=[item.model_dump() for item in request.history] if message else [],
            report_context=report_context,
            direct_question=bool(message),
        )
        if _looks_like_raw_report_dump(reply):
            reply = _build_question_fallback_answer(ai_prompt, parsed_report, generated_tasks)

    return ChatResponse(
        reply=reply,
        ran_script=ran_script,
        report_context=report_context,
        script_report=script_report,
        script_summary=script_summary,
        generated_tasks=generated_tasks,
        report_txt_content=report_txt_content,
        report_json_content=report_json_content,
    )