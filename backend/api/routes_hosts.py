from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from db.database import (
    get_active_connection,
    get_host_findings,
    get_host_overview,
    get_host_trend,
    get_latest_fullscan_report,
    get_latest_job_id,
    get_ranked_hosts,
    list_fullscan_reports,
    list_unified_hosts,
)
from schemas.types import FindingGroupRecord, HostOverviewResponse, HostRankingRecord, HostTrendPoint
from services.snipen_service import get_host_events, get_snipen_hosts

router = APIRouter(prefix="/hosts", tags=["hosts"])


AUTH_EVENT_IDS = {"4624", "4625", "4634", "4648", "4672", "4768", "4769", "4771", "4776"}
PERSISTENCE_EVENT_IDS = {"4697", "4698", "4702", "7045"}


def _as_iso(value: str | None) -> str | None:
    if not value:
        return None
    return value


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        txt = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(txt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _event_to_dict(event: Any) -> dict[str, Any]:
    smart = getattr(event, "smart", None)
    raw = getattr(event, "raw", None)
    return {
        "doc_id": getattr(event, "doc_id", None),
        "raw": raw if isinstance(raw, dict) else {},
        "smart": {
            "timestamp": getattr(smart, "timestamp", None),
            "host": getattr(smart, "host", None),
            "platform": getattr(smart, "platform", None),
            "event_id": getattr(smart, "event_id", None),
            "event_explanation": getattr(smart, "event_explanation", None),
            "system_message": getattr(smart, "system_message", None),
            "rule_id": getattr(smart, "rule_id", None),
            "rule_level": getattr(smart, "rule_level", None),
            "rule_description": getattr(smart, "rule_description", None),
            "groups": list(getattr(smart, "groups", []) or []),
            "user": getattr(smart, "user", None),
            "logon_type": getattr(smart, "logon_type", None),
            "ip_address": getattr(smart, "ip_address", None),
            "process": getattr(smart, "process", None),
            "command_line": getattr(smart, "command_line", None),
            "service_name": getattr(smart, "service_name", None),
            "registry_key": getattr(smart, "registry_key", None),
            "status": getattr(smart, "status", None),
            "mitre_id": getattr(smart, "mitre_id", None),
            "mitre_tactic": getattr(smart, "mitre_tactic", None),
        },
    }


def _ai_text_for_tab(tab: str, item_count: int, risk_score: float) -> str:
    if tab == "authentication":
        if item_count >= 15:
            return "Mehrere Auth-Events in kurzer Zeit. Bitte auf Brute-Force-Muster und privilegierte Logins pruefen."
        return "Keine auffaellige Auth-Dichte erkennbar. Login-Verhalten wirkt aktuell stabil."
    if tab == "processes":
        if item_count >= 25 or risk_score >= 7.5:
            return "Erhoehte Prozessaktivitaet mit moeglich auffaelligen Ausfuehrungen. Parent/Child-Beziehungen und Commandlines priorisiert pruefen."
        return "Prozessaktivitaet ohne klar kritische Anomalien. Fokus auf seltene Binaries empfohlen."
    if tab == "persistence":
        if item_count > 0:
            return "Persistence-nahe Events vorhanden. Neue Services, Tasks oder Registry-Aenderungen gegen Baseline validieren."
        return "Keine direkten Persistence-Indikatoren in den aktuellen Events erkannt."
    if tab == "vulnerabilities":
        if item_count > 0:
            return "Bekannte Schwachstellen vorhanden. Kritische CVEs zuerst priorisieren und Patch-Backlog aktualisieren."
        return "Keine aktuellen Vulnerability-Eintraege fuer diesen Host gefunden."
    if tab == "threat_intel":
        if item_count > 0:
            return "Threat-Intel-Korrelationen vorhanden. Indikatoren gegen bekannte gute Artefakte gegenpruefen und eskalieren falls bestaetigt."
        return "Keine aktuellen Threat-Intel-Treffer fuer den Host erkannt."
    if tab == "configuration":
        if item_count > 0:
            return "Konfigurations-/Compliance-Befunde vorhanden. Abweichungen mit Hardening-Standard abgleichen."
        return "Keine markanten Konfigurationsabweichungen aus den aktuellen Daten sichtbar."
    if tab == "fim":
        if item_count > 0:
            return "Dateiaenderungen erkannt. Ungewoehnliche Pfade und wiederkehrende Aenderungsmuster priorisiert pruefen."
        return "Keine auffaelligen FIM-Meldungen im aktuellen Datensatz."
    if tab == "mitre_rules":
        if item_count > 0:
            return "MITRE-/Rule-Signale vorhanden. Tactics/Techniques fuer priorisierte Detection-Checks verwenden."
        return "Keine eindeutigen MITRE-Hinweise im betrachteten Zeitraum gefunden."
    return "Tab-spezifische Bewertung verfuegbar, sobald Daten vorliegen."


def _risk_from_overview(overview: dict[str, Any] | None) -> float:
    if not overview:
        return 0.0
    top_local = int(overview.get("top_local_score") or 0)
    suspicious = int(overview.get("suspicious_groups") or 0)
    groups = int(overview.get("finding_groups") or 0)
    raw = min(10.0, round((top_local / 10.0) * 5.0 + min(3.0, suspicious * 0.5) + min(2.0, groups * 0.15), 1))
    return max(0.0, raw)


@router.get("/central")
def hosts_central(hours: int = Query(default=24, ge=1, le=720)) -> list[dict[str, Any]]:
    connection = get_active_connection()
    if not connection:
        return []

    snipen_hosts = get_snipen_hosts(connection, hours=hours)
    latest_job_id = get_latest_job_id()
    ranked_map: dict[str, dict[str, Any]] = {}
    if latest_job_id:
        for item in get_ranked_hosts(latest_job_id):
            ranked_map[item["host"]] = item

    # Build lookup from hostname_short → unified host row (for tactical_status + ip)
    rmm_map: dict[str, dict[str, Any]] = {}
    for uh in list_unified_hosts():
        key = (uh.get("hostname_short") or "").lower()
        if key:
            rmm_map[key] = uh
        # also index by display_name as fallback
        dn = (uh.get("display_name") or "").lower()
        if dn and dn not in rmm_map:
            rmm_map[dn] = uh

    now = datetime.now(timezone.utc)
    output: list[dict[str, Any]] = []
    for host_info in snipen_hosts:
        host = host_info.host
        rank = ranked_map.get(host, {})
        latest_scan = get_latest_fullscan_report(host)
        overview = get_host_overview(latest_job_id, host) if latest_job_id else None
        risk_score = float(latest_scan["risk_score"]) if latest_scan else _risk_from_overview(overview)
        last_seen_dt = _parse_iso(host_info.last_seen)
        is_online_wazuh = bool(last_seen_dt and (now - last_seen_dt) <= timedelta(hours=6))

        # Tactical RMM status takes priority over Wazuh last-seen estimate
        uh_row = rmm_map.get(host.lower())
        tactical_status = (uh_row.get("tactical_status") or "unknown") if uh_row else "unknown"
        if tactical_status == "online":
            connection_status = "reachable"
        elif tactical_status in ("offline", "overdue"):
            connection_status = "unreachable"
        else:
            connection_status = "reachable" if is_online_wazuh else "unknown"

        primary_ip = (uh_row.get("primary_ip") if uh_row else None)

        platforms = host_info.platforms or []
        # Access capabilities: inferred from platform until SSH/RDP manager integration
        is_windows = any(p.lower() == "windows" for p in platforms)
        is_linux = any(p.lower() == "linux" for p in platforms)
        output.append(
            {
                "host": host,
                "ip": primary_ip,
                "platforms": platforms,
                "last_activity": _as_iso(host_info.last_seen),
                "alerts_24h": int(host_info.alert_count),
                "findings_count": int(rank.get("findings_count") or 0),
                "risk_score": risk_score,
                "fullscan_status": latest_scan.get("status") if latest_scan else "never",
                "last_scan_at": latest_scan.get("created_at") if latest_scan else None,
                "status": "online" if connection_status == "reachable" else "offline",
                # ── Access (SSH / RDP) ── populated by SSH/RDP manager later
                "ssh_enabled": is_linux,
                "rdp_enabled": is_windows,
                "tactical_status": tactical_status,
                "connection_status": connection_status,
                "last_connection": None,
            }
        )

    output.sort(key=lambda item: (item.get("risk_score") or 0, item.get("alerts_24h") or 0), reverse=True)
    return output


@router.get("/{host}/central")
def host_central_detail(
    host: str,
    hours: int = Query(default=168, ge=1, le=720),
    limit: int = Query(default=250, ge=20, le=1000),
) -> dict[str, Any]:
    connection = get_active_connection()
    if not connection:
        raise HTTPException(status_code=404, detail="No active connection")

    latest_job_id = get_latest_job_id()
    findings = get_host_findings(latest_job_id, host) if latest_job_id else []
    overview = get_host_overview(latest_job_id, host) if latest_job_id else None
    trend = get_host_trend(host, limit=20)

    events = get_host_events(connection, host=host, hours=hours, limit=limit)
    event_rows = [_event_to_dict(ev) for ev in events]

    process_rows = [
        row for row in event_rows
        if str(row.get("smart", {}).get("event_id") or "") == "4688" or bool(row.get("smart", {}).get("process"))
    ]
    auth_rows = [
        row for row in event_rows
        if str(row.get("smart", {}).get("event_id") or "") in AUTH_EVENT_IDS or bool(row.get("smart", {}).get("logon_type"))
    ]
    persistence_rows = [
        row for row in event_rows
        if str(row.get("smart", {}).get("event_id") or "") in PERSISTENCE_EVENT_IDS
        or bool(row.get("smart", {}).get("service_name"))
        or bool(row.get("smart", {}).get("registry_key"))
    ]
    mitre_rows = [
        {
            "event_id": row.get("smart", {}).get("event_id"),
            "rule_id": row.get("smart", {}).get("rule_id"),
            "rule_description": row.get("smart", {}).get("rule_description"),
            "mitre_id": row.get("smart", {}).get("mitre_id"),
            "mitre_tactic": row.get("smart", {}).get("mitre_tactic"),
        }
        for row in event_rows
        if row.get("smart", {}).get("mitre_id") or row.get("smart", {}).get("rule_id")
    ]

    latest_scan = get_latest_fullscan_report(host)
    report_history = list_fullscan_reports(host=host, limit=15)
    latest_scan_result = latest_scan.get("result") if latest_scan else {}
    if not isinstance(latest_scan_result, dict):
        latest_scan_result = {}

    risk_score = float(latest_scan["risk_score"]) if latest_scan else _risk_from_overview(overview)
    findings_count = int(latest_scan["findings_count"]) if latest_scan else int((overview or {}).get("finding_groups") or 0)
    high_findings = int(latest_scan["high_findings"]) if latest_scan else int((overview or {}).get("severity_counts", {}).get("high") or 0)
    ti_matches = int(latest_scan["ti_matches"]) if latest_scan else 0

    ai_summary = (
        (latest_scan.get("summary") or {}).get("assessment") if latest_scan else None
    ) or (
        "Host zeigt mehrere auffaellige Muster. Prioritaet: Hoch" if risk_score >= 7.5
        else "Host zeigt einzelne verdaechtige Muster. Prioritaet: Mittel" if risk_score >= 5
        else "Host wirkt derzeit ueberwiegend unauffaellig. Prioritaet: Niedrig"
    )

    reports = [
        {
            "id": item.get("id"),
            "fullscan_job_id": item.get("fullscan_job_id"),
            "created_at": item.get("created_at"),
            "status": item.get("status"),
            "risk_score": item.get("risk_score"),
            "findings_count": item.get("findings_count"),
            "high_findings": item.get("high_findings"),
            "markdown_report": item.get("markdown_report") or "",
        }
        for item in report_history
    ]

    header = {
        "host": host,
        "ip": None,
        "platforms": list({row.get("smart", {}).get("platform") for row in event_rows if row.get("smart", {}).get("platform")}),
        "agent_id": None,
        "status": "online" if event_rows else "offline",
        "last_activity": event_rows[0].get("smart", {}).get("timestamp") if event_rows else None,
        "last_full_scan": latest_scan.get("created_at") if latest_scan else None,
    }

    tabs = {
        "events": {"items": event_rows[:300], "ai_assessment": _ai_text_for_tab("events", len(event_rows), risk_score)},
        "processes": {"items": process_rows[:250], "ai_assessment": _ai_text_for_tab("processes", len(process_rows), risk_score)},
        "authentication": {"items": auth_rows[:250], "ai_assessment": _ai_text_for_tab("authentication", len(auth_rows), risk_score)},
        "persistence": {"items": persistence_rows[:250], "ai_assessment": _ai_text_for_tab("persistence", len(persistence_rows), risk_score)},
        "vulnerabilities": {"items": latest_scan_result.get("vulnerabilities") or [], "ai_assessment": _ai_text_for_tab("vulnerabilities", len(latest_scan_result.get("vulnerabilities") or []), risk_score)},
        "fim": {"items": latest_scan_result.get("fim") or [], "ai_assessment": _ai_text_for_tab("fim", len(latest_scan_result.get("fim") or []), risk_score)},
        "configuration": {"items": latest_scan_result.get("config") or [], "ai_assessment": _ai_text_for_tab("configuration", len(latest_scan_result.get("config") or []), risk_score)},
        "threat_intel": {"items": latest_scan_result.get("threat_intel") or [], "ai_assessment": _ai_text_for_tab("threat_intel", len(latest_scan_result.get("threat_intel") or []), risk_score)},
        "mitre_rules": {"items": mitre_rows[:200], "ai_assessment": _ai_text_for_tab("mitre_rules", len(mitre_rows), risk_score)},
        "raw_data": {"items": latest_scan_result.get("raw_json") or {"events": event_rows[:80]}, "ai_assessment": "Rohdaten fuer technische Tiefenanalyse und Export."},
        "reports": {"items": reports, "ai_assessment": "Historie der Full-Scan-Ergebnisse fuer diesen Host."},
    }

    return {
        "header": header,
        "summary": {
            "risk_score": risk_score,
            "findings_count": findings_count,
            "high_findings": high_findings,
            "medium_findings": int((overview or {}).get("severity_counts", {}).get("medium") or 0),
            "low_findings": int((overview or {}).get("severity_counts", {}).get("low") or 0),
            "ti_matches": ti_matches,
            "last_scan_time": latest_scan.get("created_at") if latest_scan else None,
            "ai_assessment": ai_summary,
        },
        "tabs": tabs,
        "overview": overview,
        "findings": findings,
        "trend": trend,
    }


@router.get("/ranking")
def hosts_ranking(job_id: int | None = Query(default=None)) -> list[HostRankingRecord]:
    resolved_job_id = job_id or get_latest_job_id()
    if not resolved_job_id:
        return []
    return [HostRankingRecord(**item) for item in get_ranked_hosts(resolved_job_id)]


@router.get("/{host}/findings")
def host_findings(host: str, job_id: int | None = Query(default=None)) -> list[FindingGroupRecord]:
    resolved_job_id = job_id or get_latest_job_id()
    if not resolved_job_id:
        raise HTTPException(status_code=404, detail="No analysis job available")
    return [FindingGroupRecord(**item) for item in get_host_findings(resolved_job_id, host)]


@router.get("/{host}/overview")
def host_overview(host: str, job_id: int | None = Query(default=None)) -> HostOverviewResponse:
    resolved_job_id = job_id or get_latest_job_id()
    if not resolved_job_id:
        raise HTTPException(status_code=404, detail="No analysis job available")
    payload = get_host_overview(resolved_job_id, host)
    if not payload:
        raise HTTPException(status_code=404, detail="No findings for host")
    return HostOverviewResponse(**payload)


@router.get("/{host}/trend")
def host_trend(host: str, limit: int = Query(default=14, ge=1, le=90)) -> list[HostTrendPoint]:
    return [HostTrendPoint(**item) for item in get_host_trend(host, limit=limit)]
