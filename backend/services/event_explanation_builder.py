"""Event Explanation Builder
===========================
Deterministic, rule-based explanation engine for Wazuh events.

Returns structured explanation objects WITHOUT calling AI.

Both the Snipen Investigation view and the Event Map Workbench must
consume explanations built here. The AI may only reword the text —
it must never override verdict, risk_score, severity, or confidence.

Key principles
--------------
* verdict / risk_score / severity are ALWAYS computed from evaluation
  or from this engine.  Never from the AI alone.
* "may indicate malware" is only added when concrete indicators exist.
* Known Windows system processes from System32 are treated as benign
  unless additional signals override that assumption.
* All returned fields are plain Python dicts / lists of strings —
  never raw Python repr like "['item1', 'item2']".
"""
from __future__ import annotations

import os
import re
from typing import Any

# ── Known benign Windows system processes (basename, lowercase) ───────────────
_KNOWN_WINDOWS_SYSTEM_PROCESSES: frozenset[str] = frozenset({
    "backgroundtaskhost.exe",
    "svchost.exe",
    "taskhostw.exe",
    "taskhost.exe",
    "dllhost.exe",
    "conhost.exe",
    "csrss.exe",
    "lsass.exe",
    "lsm.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
    "spoolsv.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "wmiprvse.exe",
    "wsmprovhost.exe",
    "audiodg.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "ctfmon.exe",
    "msmpeng.exe",
    "mssense.exe",
    "securityhealthservice.exe",
    "msdtc.exe",
    "msiexec.exe",
    "wuauclt.exe",
    "usocoreworker.exe",
    "runtimebroker.exe",
    "smartscreen.exe",
    "explorer.exe",
    "taskmgr.exe",
    "notepad.exe",
    "calc.exe",
    "ipconfig.exe",
    "ping.exe",
    "netstat.exe",
    "net.exe",
    "net1.exe",
    "nslookup.exe",
    "hostname.exe",
    "whoami.exe",
    "systeminfo.exe",
    "gpupdate.exe",
})

# ── Office / browser processes that should NOT spawn shells ──────────────────
_OFFICE_PROCESSES: frozenset[str] = frozenset({
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "access.exe", "mspub.exe", "visio.exe",
})
_BROWSER_PROCESSES: frozenset[str] = frozenset({
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "brave.exe", "opera.exe",
})
_SHELL_INTERPRETERS: frozenset[str] = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "bash.exe", "sh",
})
_LOLBINS: frozenset[str] = frozenset({
    "certutil.exe", "regsvr32.exe", "rundll32.exe", "wmic.exe",
    "bitsadmin.exe", "odbcconf.exe", "appvlp.exe",
    "mavinject.exe", "msbuild.exe", "installutil.exe",
})

# ── Suspicious command-line patterns ─────────────────────────────────────────
_SUSPICIOUS_CMDLINE_RE = re.compile(
    r"-enc\b|-encodedcommand|frombase64string|iex\s*[\(\(]|invoke-expression"
    r"|invoke-webrequest|downloadstring|downloadfile"
    r"|new-object\s+net\.webclient|start-bitstransfer"
    r"|rundll32\s+javascript|mimikatz|sekurlsa"
    r"|vssadmin\s+delete|schtasks\s+/create"
    r"|net\s+(user|localgroup)\s+/add"
    r"|reg\s+add.{0,50}\\run\b"
    r"|powershell\s+-w\s+hidden|powershell\s+-windowstyle\s+hidden"
    r"|\-exec\s+bypass|amsi|shellcode|inject|reflective",
    re.IGNORECASE,
)

# ── Suspicious process paths ─────────────────────────────────────────────────
_SUSPICIOUS_PATH_RE = re.compile(
    r"\\temp\\"
    r"|\\tmp\\"
    r"|\\appdata\\local\\temp\\"
    r"|\\appdata\\roaming\\"
    r"|\\downloads\\"
    r"|\\users\\public\\"
    r"|\\\\\\$recycle\\.bin\\\\"
    r"|c:\\users\\.+\\desktop\\"
    r"|c:\\perflogs\\",
    re.IGNORECASE,
)

# ── Safe path prefixes (case-insensitive comparison) ─────────────────────────
_SAFE_PATH_PREFIXES: tuple[str, ...] = (
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\sysnative",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\windows\\winsxs",
)

# ── AppX / BackgroundTask command-line pattern ────────────────────────────────
_APPX_CMDLINE_RE = re.compile(
    r"-[sS]erverName:(global\.|local\.|appX|AppX|microsoft\.)",
    re.IGNORECASE,
)


# ── Path helpers ──────────────────────────────────────────────────────────────

def _norm(path: str) -> str:
    return path.lower().replace("/", "\\").strip()


def _is_safe_path(path: str | None) -> bool:
    if not path:
        return False
    p = _norm(path)
    return any(p.startswith(pfx) for pfx in _SAFE_PATH_PREFIXES)


def _is_suspicious_path(path: str | None) -> bool:
    if not path:
        return False
    return bool(_SUSPICIOUS_PATH_RE.search(_norm(path)))


def _has_suspicious_cmdline(cmdline: str | None) -> tuple[bool, str | None]:
    if not cmdline:
        return False, None
    m = _SUSPICIOUS_CMDLINE_RE.search(cmdline)
    if m:
        return True, m.group(0)[:60]
    return False, None


def _is_known_safe(name: str | None) -> bool:
    return (name or "").lower() in _KNOWN_WINDOWS_SYSTEM_PROCESSES


def _is_appx_backgroundtask(name: str | None, cmdline: str | None) -> bool:
    n = (name or "").lower()
    return n == "backgroundtaskhost.exe" and bool(_APPX_CMDLINE_RE.search(cmdline or ""))


def _get_win_ev(data: dict[str, Any]) -> dict[str, Any]:
    """Return win eventData dict — handles both 'eventdata' (Wazuh default) and 'eventData' keys."""
    win = data.get("win") or {}
    return win.get("eventdata") or win.get("eventData") or {}


def _extract_proc(event: dict[str, Any]) -> tuple[str | None, str | None, str | None, str | None]:
    """Return (process_path, process_name, command_line, parent_name)."""
    data   = event.get("data") or {}
    win_ev = _get_win_ev(data)

    # process path / name
    process_path = (
        win_ev.get("newProcessName")
        or win_ev.get("processName")
        or event.get("image_path")
        or event.get("process")
        or ""
    )
    process_name = os.path.basename(str(process_path)).lower() if process_path else None

    # command line
    command_line = (
        win_ev.get("commandLine")
        or win_ev.get("processCommandLine")
        or event.get("command_line")
        or ""
    ) or None

    # parent process
    parent_path = win_ev.get("parentProcessName") or event.get("parent_process") or ""
    parent_name = os.path.basename(str(parent_path)).lower() if parent_path else None

    return (str(process_path) if process_path else None,
            process_name or None,
            str(command_line) if command_line else None,
            parent_name or None)


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

def build_event_explanation(
    event: dict[str, Any],
    evaluation: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    knowledge: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic structured explanation for a Wazuh event.

    Parameters
    ----------
    event:
        Raw Wazuh event document.
    evaluation:
        Output of ``evaluate_event_with_baseline(event)`` (optional).
    evidence:
        Output of ``extract_event_evidence(event)`` (optional).
    knowledge:
        Output of ``resolve_event_knowledge(event)`` (optional).

    Returns
    -------
    dict with all explanation fields as plain strings / lists of strings.
    Never contains Python list repr like "['item1', 'item2']".
    """
    data    = event.get("data") or {}
    win_sys = (data.get("win") or {}).get("system") or {}
    rule    = event.get("rule") or {}

    event_id = str(
        win_sys.get("eventID") or win_sys.get("eventId")
        or data.get("eventid") or ""
    ).strip() or None
    rule_level       = max(0, int(rule.get("level", 0) or 0))
    rule_description = str(rule.get("description") or "").strip()

    win_ev = _get_win_ev(data)
    process_path, process_name, command_line, parent_name = _extract_proc(event)

    # ── Resolve verdict/risk from evaluation ─────────────────────────────────
    final_eval = (evaluation or {}).get("final_evaluation") or {}
    base_eval  = (evaluation or {}).get("base_evaluation") or {}
    if final_eval:
        verdict     = final_eval.get("verdict", "monitor")
        severity    = final_eval.get("severity", "low")
        risk_score  = float(final_eval.get("risk_score", 2.5))
        confidence  = final_eval.get("confidence", "medium")
        expl_source = "final_evaluation"
    elif base_eval:
        verdict     = base_eval.get("verdict", "monitor")
        severity    = base_eval.get("severity", "low")
        risk_score  = float(base_eval.get("risk_score", 2.5))
        confidence  = base_eval.get("confidence", "low")
        expl_source = "base_evaluation"
    elif knowledge:
        _sev_risk = {"info": 1.0, "low": 2.5, "medium": 5.0, "high": 7.5, "critical": 9.5}
        sev = str(knowledge.get("default_severity", "low"))
        risk_score = _sev_risk.get(sev, 2.5)
        if rule_level >= 10:
            risk_score = max(risk_score, 5.0)
        verdict = "review" if risk_score >= 4.0 else "monitor"
        severity = sev
        confidence = "medium" if knowledge.get("knowledge_level") in ("deep", "pattern") else "low"
        expl_source = "knowledge"
    else:
        risk_score  = 2.5
        verdict     = "monitor"
        severity    = "low"
        confidence  = "low"
        expl_source = "fallback"

    # ── Per-event analysis ────────────────────────────────────────────────────
    why_suspicious:      list[str] = []
    why_likely_benign:   list[str] = []
    not_enough_evidence: list[str] = []
    escalation_conds:    list[str] = []
    wording_warnings:    list[str] = []
    important_fields:    list[dict] = []

    baseline_notes = _extract_baseline_notes(evaluation)

    if event_id == "4688":
        title    = "Process Created"
        subtitle = f"{process_name or 'unknown process'} was started"
        _analyze_4688(
            process_name=process_name,
            process_path=process_path,
            command_line=command_line,
            parent_name=parent_name,
            rule_level=rule_level,
            why_suspicious=why_suspicious,
            why_likely_benign=why_likely_benign,
            not_enough_evidence=not_enough_evidence,
            escalation_conditions=escalation_conds,
            wording_warnings=wording_warnings,
            important_fields=important_fields,
        )
        # Deterministic engine is the floor — external evaluation can add context but never downgrade
        det_risk = get_4688_risk_score(
            process_name=process_name,
            process_path=process_path,
            command_line=command_line,
            parent_name=parent_name,
            rule_level=rule_level,
        )
        risk_score = max(risk_score, det_risk)
        if risk_score >= 8.5:
            severity = "critical"; verdict = "investigate"; confidence = "high"
        elif risk_score >= 7.0:
            severity = "high";    verdict = "investigate"; confidence = "high"
        elif risk_score >= 5.0:
            severity = "medium";  verdict = "review";      confidence = "medium"
        elif risk_score >= 3.5:
            severity = "low";     verdict = "review";      confidence = "medium"
        else:
            severity = "low";     verdict = "monitor";     confidence = "medium"
        expl_source = "process_analysis"

    elif event_id in {"4624", "4625", "4648", "4634", "4672"}:
        title, subtitle, risk_score, severity, verdict, confidence, expl_source = _get_logon_title(
            event_id, win_ev, expl_source, risk_score, severity, verdict, confidence,
        )
        _analyze_logon(
            event_id=event_id, win_ev=win_ev, rule_level=rule_level,
            why_suspicious=why_suspicious, why_likely_benign=why_likely_benign,
            not_enough_evidence=not_enough_evidence, escalation_conditions=escalation_conds,
            important_fields=important_fields,
        )
        # Always apply deterministic logon risk as a floor
        det_r, det_sev, det_verd, det_conf = _logon_risk(event_id, win_ev, rule_level)
        risk_score = max(risk_score, det_r)
        if risk_score == det_r:  # deterministic won — use its verdict/severity
            severity = det_sev; verdict = det_verd; confidence = det_conf
        expl_source = "logon_analysis"

    elif event_id in {"4697", "7045"}:
        title    = "New Service Installed"
        subtitle = _s(win_ev.get("serviceName") or win_ev.get("servicename") or rule_description)
        _analyze_service_install(
            win_ev=win_ev,
            why_suspicious=why_suspicious, why_likely_benign=why_likely_benign,
            not_enough_evidence=not_enough_evidence, escalation_conditions=escalation_conds,
            important_fields=important_fields,
        )
        # Service installs are always high-priority — deterministic floor
        risk_score = max(risk_score, 6.5)
        severity = "high" if risk_score >= 6.5 else severity
        verdict  = "investigate" if risk_score >= 6.5 else verdict
        confidence = "high"; expl_source = "service_analysis"

    elif event_id == "7040":
        title    = "Service Startup Type Changed"
        subtitle = _s(win_ev.get("serviceName") or win_ev.get("servicename") or rule_description)
        risk_score, severity, verdict, confidence, _sus, _ben = _analyze_service_change(
            win_ev=win_ev, rule_level=rule_level,
        )
        risk_score = max(risk_score, float((evaluation or {}).get("final_evaluation", {}).get("risk_score") or 0))
        why_suspicious.extend(_sus)
        why_likely_benign.extend(_ben)
        escalation_conds.extend([
            "Security service or AV disabled.",
            "Change follows suspicious logon or lateral movement.",
            "Service name is new or not in baseline.",
        ])
        if expl_source in ("fallback", "knowledge"):
            expl_source = "service_change_analysis"

    elif event_id == "4698":
        title    = "Scheduled Task Created"
        task_name = _s(win_ev.get("taskName") or win_ev.get("taskname") or "")
        subtitle = task_name or rule_description
        _analyze_scheduled_task(
            win_ev=win_ev,
            why_suspicious=why_suspicious, why_likely_benign=why_likely_benign,
            not_enough_evidence=not_enough_evidence, escalation_conditions=escalation_conds,
            important_fields=important_fields,
        )
        if expl_source in ("fallback", "knowledge"):
            risk_score = 5.5; severity = "medium"; verdict = "review"; confidence = "medium"
            expl_source = "task_analysis"
        else:
            risk_score = max(risk_score, 5.5)

    elif event_id == "1102":
        title    = "Audit Log Cleared"
        subtitle = "Windows Security event log was cleared"
        why_suspicious.append(
            "Clearing the audit log is a known anti-forensics technique used to hide prior activity."
        )
        why_suspicious.append(
            "This action removes evidence of all previous Security events on this host."
        )
        escalation_conds.extend([
            "Preceded by high-risk events (service installs, privilege assignments, process creation).",
            "Cleared by non-administrator or unexpected account.",
            "Occurs during off-hours or following suspicious logon.",
        ])
        not_enough_evidence.append(
            "No evidence of prior activity available — log contents were destroyed by this action."
        )
        if expl_source in ("fallback", "knowledge"):
            risk_score = 8.0; severity = "high"; verdict = "investigate"; confidence = "high"
            expl_source = "audit_clear_analysis"
        else:
            # Never downgrade 1102 below investigate
            risk_score = max(risk_score, 8.0)
            severity = "high"; verdict = "investigate"

    elif event_id == "1014":
        title    = "DNS Query Failure"
        subtitle = rule_description or "DNS client event"
        why_likely_benign.append(
            "DNS resolution failures are common and typically caused by transient network issues, "
            "misconfigured DNS, or temporary server unavailability."
        )
        not_enough_evidence.append(
            "The queried domain name is needed to assess risk — a single failure is usually benign."
        )
        escalation_conds.extend([
            "Repeated failures to unusual or new domains across multiple hosts.",
            "Domain matches threat intelligence feeds.",
            "Failure followed by network connection attempt or alert.",
        ])
        if expl_source in ("fallback", "knowledge"):
            risk_score = 1.5; severity = "low"; verdict = "monitor"; confidence = "medium"
            expl_source = "dns_analysis"

    elif event_id in {"1000", "1001", "1002", "1026"}:
        title    = "Application Error / Crash"
        subtitle = rule_description or "Application Event"
        _analyze_app_crash(
            event=event, win_ev=win_ev,
            why_suspicious=why_suspicious, why_likely_benign=why_likely_benign,
            not_enough_evidence=not_enough_evidence, escalation_conditions=escalation_conds,
        )
        if expl_source in ("fallback", "knowledge"):
            risk_score = 2.0; severity = "low"; verdict = "monitor"; confidence = "low"
            expl_source = "app_crash_analysis"

    else:
        # ── Try Linux/generic event handlers ─────────────────────────────────
        decoder = (event.get("decoder") or {}).get("name") or ""
        rule_groups: list[str] = list((rule.get("groups") or []))
        syscheck = event.get("syscheck") or {}

        if decoder == "sshd" or "sshd" in " ".join(rule_groups).lower():
            title, subtitle, why_s, why_b, not_ev, esc = _analyze_linux_ssh(event, rule_level)
            why_suspicious.extend(why_s)
            why_likely_benign.extend(why_b)
            not_enough_evidence.extend(not_ev)
            escalation_conds.extend(esc)
            if expl_source in ("fallback", "knowledge"):
                _is_failed = "fail" in rule_description.lower() or "invalid" in rule_description.lower()
                risk_score = 2.5 if not _is_failed else 2.0
                severity = "low"; verdict = "monitor"; confidence = "medium"
                expl_source = "linux_ssh_analysis"

        elif syscheck or "syscheck" in " ".join(rule_groups).lower():
            title, subtitle, why_s, why_b, not_ev, esc = _analyze_linux_fim(
                event, syscheck, rule_level,
            )
            why_suspicious.extend(why_s)
            why_likely_benign.extend(why_b)
            not_enough_evidence.extend(not_ev)
            escalation_conds.extend(esc)
            if expl_source in ("fallback", "knowledge"):
                _path = str(syscheck.get("path") or "").lower()
                _sens = any(p in _path for p in ("/etc/passwd", "/etc/shadow", "authorized_keys", "/etc/sudoers"))
                risk_score = 8.0 if _sens else 4.0
                severity   = "high" if _sens else "medium"
                verdict    = "investigate" if _sens else "review"
                confidence = "high" if _sens else "medium"
                expl_source = "fim_analysis"

        elif decoder == "auditd" or "audit" in " ".join(rule_groups).lower():
            title, subtitle, why_s, why_b, not_ev, esc = _analyze_linux_auditd(
                event, rule_level,
            )
            why_suspicious.extend(why_s)
            why_likely_benign.extend(why_b)
            not_enough_evidence.extend(not_ev)
            escalation_conds.extend(esc)
            if expl_source in ("fallback", "knowledge") and not why_s:
                risk_score = 3.5; severity = "low"; verdict = "monitor"; confidence = "low"
                expl_source = "auditd_analysis"

        else:
            title    = (knowledge or {}).get("title") or rule_description or f"Event {event_id}"
            subtitle = rule_description or ""

    # ── why_visible ───────────────────────────────────────────────────────────
    why_visible: list[str] = []
    if event_id in {"4688", "4689"}:
        why_visible.append(
            "Process-creation events are important for correlation and attack-chain reconstruction."
        )
        why_visible.append(
            "Malicious tools also produce 4688 events — keeping these events ensures detection coverage."
        )
    elif event_id in {"7045", "4697"}:
        why_visible.append("Service installations are a common persistence technique and are always reviewed.")
    elif event_id in {"4624", "4625", "4648"}:
        why_visible.append("Authentication events are essential for detecting brute-force and credential theft.")
    else:
        why_visible.append(
            f"Event {event_id} has rule level {rule_level} which meets the monitoring threshold."
        )

    # ── Recommended checks ────────────────────────────────────────────────────
    recommended_checks = _build_recommended_checks(
        event_id=event_id,
        process_name=process_name,
        process_path=process_path,
        command_line=command_line,
        parent_name=parent_name,
        why_suspicious=why_suspicious,
    )
    if not recommended_checks and knowledge:
        recommended_checks = list((knowledge.get("recommended_checks") or []))[:5]

    # ── Summary ───────────────────────────────────────────────────────────────
    summary = _build_summary(
        event_id=event_id,
        title=title,
        process_name=process_name,
        process_path=process_path,
        command_line=command_line,
        verdict=verdict,
        severity=severity,
        risk_score=risk_score,
        why_suspicious=why_suspicious,
        why_likely_benign=why_likely_benign,
        knowledge=knowledge,
    )

    # ── Wording safety ────────────────────────────────────────────────────────
    if expl_source == "fallback":
        wording_warnings.append("Explanation is generic and may be incomplete.")
    if not why_suspicious and verdict in ("monitor", "ignore"):
        wording_warnings.append(
            "No strong malicious indicator found — manual review only if correlated with other events."
        )

    return {
        "title":                 title,
        "subtitle":              subtitle,
        "verdict":               verdict,
        "severity":              severity,
        "risk_score":            round(risk_score, 2),
        "confidence":            confidence,
        "explanation_source":    expl_source,
        "summary":               summary,
        "why_visible":           why_visible,
        "why_suspicious":        why_suspicious,
        "why_likely_benign":     why_likely_benign,
        "not_enough_evidence":   not_enough_evidence,
        "important_fields":      important_fields,
        "recommended_checks":    recommended_checks,
        "escalation_conditions": escalation_conds,
        "baseline_notes":        baseline_notes,
        "wording_warnings":      wording_warnings,
    }


# ── 4688 analysis ─────────────────────────────────────────────────────────────

def _analyze_4688(
    *,
    process_name: str | None,
    process_path: str | None,
    command_line: str | None,
    parent_name: str | None,
    rule_level: int,
    why_suspicious: list[str],
    why_likely_benign: list[str],
    not_enough_evidence: list[str],
    escalation_conditions: list[str],
    wording_warnings: list[str],
    important_fields: list[dict],
) -> None:
    suspicious_cmdline, suspicious_pattern = _has_suspicious_cmdline(command_line)
    path_safe        = _is_safe_path(process_path)
    path_suspicious  = _is_suspicious_path(process_path)
    is_known_safe    = _is_known_safe(process_name)
    is_appx          = _is_appx_backgroundtask(process_name, command_line)
    parent_is_office  = (parent_name or "") in _OFFICE_PROCESSES
    parent_is_browser = (parent_name or "") in _BROWSER_PROCESSES
    proc_is_shell     = (process_name or "") in _SHELL_INTERPRETERS
    proc_is_lolbin    = (process_name or "") in _LOLBINS

    # ── Benign indicators ─────────────────────────────────────────────────────
    if is_appx:
        why_likely_benign.append(
            "backgroundTaskHost.exe is a normal Windows component for background tasks."
        )
        why_likely_benign.append(
            "The executable path is under C:\\Windows\\System32."
        )
        why_likely_benign.append(
            "The -ServerName:Global.AppX... command-line pattern is normal for Windows AppX background tasks."
        )
    elif path_safe and is_known_safe:
        why_likely_benign.append(
            f"{process_name} is a known Windows system process."
        )
        why_likely_benign.append(
            "The executable path is under C:\\Windows\\System32 or an equivalent safe location."
        )
    elif path_safe:
        why_likely_benign.append(
            "The executable path is under C:\\Windows\\System32 or Program Files."
        )
    elif is_known_safe:
        why_likely_benign.append(
            f"{process_name} is a recognized Windows system process."
        )

    if proc_is_shell and path_safe and not suspicious_cmdline:
        why_likely_benign.append(
            f"{process_name} running from System32 without suspicious arguments is "
            "often normal administrative activity."
        )

    # ── Suspicious indicators ─────────────────────────────────────────────────
    if suspicious_cmdline:
        why_suspicious.append(
            f"The command line contains a suspicious pattern: {suspicious_pattern}."
        )
        important_fields.append({
            "field":  "command_line",
            "value":  (command_line or "")[:120],
            "reason": f"Contains suspicious pattern: {suspicious_pattern}",
        })

    if path_suspicious:
        why_suspicious.append(
            f"The process is running from a suspicious path: {process_path}."
        )
        important_fields.append({
            "field":  "process_path",
            "value":  str(process_path)[:120],
            "reason": "Non-standard path (Temp / AppData / Downloads)",
        })

    if parent_is_office and proc_is_shell:
        why_suspicious.append(
            f"Office process ({parent_name}) spawning a shell interpreter ({process_name}) "
            "is a common malicious document technique."
        )
        important_fields.append({
            "field":  "parent_process",
            "value":  parent_name or "n/a",
            "reason": "Office process spawning shell interpreter",
        })

    if parent_is_browser and proc_is_shell:
        why_suspicious.append(
            f"Browser ({parent_name}) spawning a shell interpreter ({process_name}) "
            "is unusual and may indicate a browser exploit."
        )

    if proc_is_lolbin and not path_safe:
        why_suspicious.append(
            f"{process_name} (Living-Off-the-Land binary) is running from an unexpected path."
        )
    elif proc_is_lolbin:
        not_enough_evidence.append(
            f"{process_name} is a LOLBin and may be used legitimately or maliciously. "
            "Verify the full command line."
        )

    # ── Missing evidence ──────────────────────────────────────────────────────
    if not process_path:
        not_enough_evidence.append(
            "No process path available — cannot determine if the executable path is legitimate."
        )
    if not command_line:
        not_enough_evidence.append(
            "No command line captured — cannot analyse for obfuscation or suspicious arguments. "
            "Enable process command-line auditing or use Sysmon."
        )
    if not parent_name:
        not_enough_evidence.append(
            "No parent process information — cannot determine the spawn chain."
        )

    # ── Escalation conditions ─────────────────────────────────────────────────
    escalation_conditions.extend([
        "Parent process is an Office application or browser spawning a shell interpreter.",
        "Command line contains encoded, obfuscated, or download-related arguments.",
        "Process path is under Temp, AppData, Downloads, or another user-writable directory.",
        "Process immediately creates a network connection to an external IP address.",
        "Process is new or rare on this host according to the baseline.",
        "Preceded by an unusual logon event (4624/4648) or privilege assignment (4672).",
    ])

    if not why_suspicious and not why_likely_benign:
        not_enough_evidence.append(
            "No suspicious or clearly benign indicators identified — requires correlation context."
        )


# ── Recommended checks ────────────────────────────────────────────────────────

def _build_recommended_checks(
    *,
    event_id: str | None,
    process_name: str | None,
    process_path: str | None,
    command_line: str | None,
    parent_name: str | None,
    why_suspicious: list[str],
) -> list[str]:
    if event_id != "4688":
        return []

    checks: list[str] = []
    if why_suspicious:
        checks.extend([
            "Investigate the parent process and verify if spawning this child is expected.",
            "Review the full command line for obfuscation or dangerous arguments.",
            "Check for network connections from this process shortly after creation.",
            "Verify the process hash against threat intelligence.",
            "Look for subsequent persistence events (7045, 4698, registry run keys).",
        ])
    else:
        checks.extend([
            "Check the parent process — is it expected to spawn this child?",
        ])
        if not command_line:
            checks.append(
                "Try to retrieve the command line via Sysmon Event ID 1 or process audit logs."
            )
        checks.extend([
            "Review the ±15-minute timeline for related events on the same host.",
            "Check baseline: is this process common on this host?",
        ])
        if not parent_name:
            checks.append(
                "Correlate with Sysmon Event ID 1 to obtain parent process information."
            )

    return checks[:6]


# ── Summary text ─────────────────────────────────────────────────────────────

def _build_summary(
    *,
    event_id: str | None,
    title: str,
    process_name: str | None,
    process_path: str | None,
    command_line: str | None,
    verdict: str,
    severity: str,
    risk_score: float,
    why_suspicious: list[str],
    why_likely_benign: list[str],
    knowledge: dict[str, Any] | None,
) -> str:
    if event_id == "4688":
        proc = process_name or "an unknown process"
        path_note = ""
        if process_path:
            if _is_safe_path(process_path):
                path_note = f"The executable path ({process_path[:60]}) is under a standard Windows location. "
            elif _is_suspicious_path(process_path):
                path_note = f"The executable is in an unusual path: {process_path[:60]}. "

        suspicious_cmdline, pattern = _has_suspicious_cmdline(command_line)

        if _is_appx_backgroundtask(process_name, command_line):
            return (
                f"{proc} was started. "
                "This is a normal Windows process for Background Tasks and AppX applications. "
                f"{path_note}"
                "The command line matches the expected -ServerName:Global.AppX pattern. "
                "Currently this looks like normal Windows background activity. "
                "No action required — escalate only if additional suspicious context appears on this host."
            )
        elif why_suspicious:
            suspicious_note = why_suspicious[0] if why_suspicious else ""
            return (
                f"{proc} was started and has suspicious indicators. "
                f"{path_note}"
                f"{suspicious_note} "
                f"Verdict: {verdict} (risk {risk_score:.1f}/10). "
                "Requires correlation with parent process and timeline context."
            )
        else:
            benign_note = why_likely_benign[0] if why_likely_benign else ""
            return (
                f"{proc} was started. "
                f"{path_note}"
                f"{benign_note + ' ' if benign_note else ''}"
                f"Verdict: {verdict} (risk {risk_score:.1f}/10). "
                "Retain in timeline for correlation — escalate only if additional context warrants it."
            )

    kb_summary = (knowledge or {}).get("summary") or ""
    if kb_summary:
        return f"{kb_summary} Verdict: {verdict} (risk {risk_score:.1f}/10)."
    return f"{title}. Verdict: {verdict} (risk {risk_score:.1f}/10)."


# ── Baseline notes ────────────────────────────────────────────────────────────

def _extract_baseline_notes(evaluation: dict[str, Any] | None) -> list[str]:
    if not evaluation:
        return []
    ctx = evaluation.get("baseline_context") or {}
    notes: list[str] = []

    if not ctx.get("baseline_available"):
        notes.append(
            "No host baseline available — cannot determine if this activity is common on this host."
        )
        return notes

    new_features = ctx.get("new_features") or []
    if new_features:
        notes.append(f"New for this host: {', '.join(str(f) for f in new_features[:5])}.")
    rare_features = ctx.get("rare_features") or []
    if rare_features:
        notes.append(f"Rare on this host: {', '.join(str(f) for f in rare_features[:3])}.")

    kf = ctx.get("known_features") or {}
    if kf.get("process") is True:
        notes.append("This process is common on this host according to the baseline.")
    elif kf.get("process") is False:
        notes.append("This process is new for this host — not seen in the baseline window.")

    if ctx.get("baseline_candidate"):
        reason = ctx.get("baseline_candidate_reason") or "Safe to add to baseline."
        notes.append(f"Baseline candidate: {reason}")

    return notes


# ── Process info helpers (re-exported for other services) ─────────────────────

def is_benign_4688(
    process_name: str | None,
    process_path: str | None,
    command_line: str | None,
    parent_name: str | None = None,
) -> bool:
    """Return True when a 4688 event shows no suspicious indicators at all."""
    suspicious_cmdline, _ = _has_suspicious_cmdline(command_line)
    if suspicious_cmdline:
        return False
    if _is_suspicious_path(process_path):
        return False
    parent_office  = (parent_name or "") in _OFFICE_PROCESSES
    parent_browser = (parent_name or "") in _BROWSER_PROCESSES
    proc_shell     = (process_name or "") in _SHELL_INTERPRETERS
    if (parent_office or parent_browser) and proc_shell:
        return False
    proc_lolbin = (process_name or "") in _LOLBINS
    if proc_lolbin and not _is_safe_path(process_path):
        return False
    return True


def get_4688_risk_score(
    process_name: str | None,
    process_path: str | None,
    command_line: str | None,
    parent_name: str | None = None,
    rule_level: int = 5,
) -> float:
    """Return a deterministic risk score (0–10) for a 4688 process creation event."""
    # Base: monitor/low
    score = 2.0

    suspicious_cmdline, _ = _has_suspicious_cmdline(command_line)
    if suspicious_cmdline:
        score += 5.0

    if _is_suspicious_path(process_path):
        score += 3.0

    parent_office  = (parent_name or "") in _OFFICE_PROCESSES
    parent_browser = (parent_name or "") in _BROWSER_PROCESSES
    proc_shell     = (process_name or "") in _SHELL_INTERPRETERS
    if (parent_office or parent_browser) and proc_shell:
        score += 4.0

    proc_lolbin = (process_name or "") in _LOLBINS
    if proc_lolbin and not _is_safe_path(process_path):
        score += 2.0

    # Boost from rule level
    if rule_level >= 10:
        score += 2.0
    elif rule_level >= 7:
        score += 1.0

    # Discount for known-safe path + known-safe process
    # Only applies when no suspicious command line was detected
    if _is_safe_path(process_path) and _is_known_safe(process_name) and not suspicious_cmdline:
        score = min(score, 3.0)

    # Never less than 1.0, cap at 10.0
    return round(min(10.0, max(1.0, score)), 2)


# ── String helper ─────────────────────────────────────────────────────────────

def _s(v: object) -> str:
    """Safe string cast — never produces Python list repr."""
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v or "")


# ══════════════════════════════════════════════════════════════════════════════
# Logon event helpers (4624 / 4625 / 4648 / 4634 / 4672)
# ══════════════════════════════════════════════════════════════════════════════

_LOGON_TYPE_NAMES: dict[str, str] = {
    "2":  "Interactive",
    "3":  "Network",
    "4":  "Batch",
    "5":  "Service",
    "7":  "Unlock",
    "8":  "NetworkCleartext",
    "9":  "NewCredentials (RunAs)",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def _get_logon_title(
    event_id: str,
    win_ev: dict,
    expl_source: str,
    risk_score: float,
    severity: str,
    verdict: str,
    confidence: str,
) -> tuple[str, str, float, str, str, str, str]:
    user = _s(win_ev.get("targetUserName") or win_ev.get("targetusername") or "")
    ip   = _s(win_ev.get("ipAddress") or win_ev.get("ipaddress") or "")
    lt   = _s(win_ev.get("logonType") or win_ev.get("logontype") or "")
    lt_name = _LOGON_TYPE_NAMES.get(lt, f"type {lt}" if lt else "")

    if event_id == "4624":
        title    = "Successful Logon"
        subtitle = f"{user or 'unknown user'} logged on" + (f" ({lt_name})" if lt_name else "")
    elif event_id == "4625":
        title    = "Failed Logon Attempt"
        subtitle = f"{user or 'unknown user'} failed to log on" + (f" ({lt_name})" if lt_name else "")
    elif event_id == "4648":
        title    = "Logon with Explicit Credentials"
        subtitle = f"RunAs or pass-through logon by {user or 'unknown user'}"
    elif event_id == "4634":
        title    = "Logoff"
        subtitle = f"{user or 'unknown user'} logged off"
    elif event_id == "4672":
        priv = _s(win_ev.get("privilegeList") or win_ev.get("privilegelist") or "")
        title    = "Special Privileges Assigned"
        subtitle = f"Elevated privileges granted to {user or 'unknown user'}"
        _ = priv  # used in analysis
    else:
        title    = f"Authentication Event {event_id}"
        subtitle = ""

    return title, subtitle, risk_score, severity, verdict, confidence, expl_source


def _logon_risk(
    event_id: str,
    win_ev: dict,
    rule_level: int,
) -> tuple[float, str, str, str]:
    lt = _s(win_ev.get("logonType") or win_ev.get("logontype") or "")

    if event_id == "4672":
        return 4.5, "medium", "review", "high"
    if event_id == "4634":
        return 1.0, "low", "monitor", "high"
    if event_id == "4624":
        if lt == "10":  # RDP
            return 3.5, "low", "review", "medium"
        if lt in ("9",):  # RunAs / NewCredentials
            return 3.5, "low", "review", "medium"
        return 2.0, "low", "monitor", "medium"
    if event_id in ("4625", "4648"):
        base = 2.5 if event_id == "4625" else 3.5
        if rule_level >= 10:
            base = max(base, 5.0)
        sev    = "medium" if base >= 5.0 else "low"
        verdict = "review" if base >= 4.0 else "monitor"
        return base, sev, verdict, "medium"

    return 2.5, "low", "monitor", "low"


def _analyze_logon(
    *,
    event_id: str,
    win_ev: dict,
    rule_level: int,
    why_suspicious: list[str],
    why_likely_benign: list[str],
    not_enough_evidence: list[str],
    escalation_conditions: list[str],
    important_fields: list[dict],
) -> None:
    user  = _s(win_ev.get("targetUserName") or win_ev.get("targetusername") or "")
    ip    = _s(win_ev.get("ipAddress") or win_ev.get("ipaddress") or "")
    lt    = _s(win_ev.get("logonType") or win_ev.get("logontype") or "")
    wkst  = _s(win_ev.get("workstationName") or win_ev.get("workstationname") or "")
    priv  = _s(win_ev.get("privilegeList") or win_ev.get("privilegelist") or "")

    if event_id == "4672":
        if not priv:
            not_enough_evidence.append(
                "Privilege list is empty — cannot determine which elevated rights were assigned."
            )
        else:
            dangerous = [p for p in priv.splitlines() if p.strip() in (
                "SeDebugPrivilege", "SeTcbPrivilege", "SeCreateTokenPrivilege",
                "SeLoadDriverPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
            )]
            if dangerous:
                why_suspicious.append(
                    f"High-risk privileges assigned: {', '.join(dangerous[:4])}."
                )
                important_fields.append({
                    "field": "privilegeList",
                    "value": ", ".join(dangerous[:4]),
                    "reason": "Contains dangerous elevated privileges",
                })
            else:
                why_likely_benign.append(
                    "Assigned privileges are standard and expected for administrative logons."
                )
        escalation_conditions.extend([
            "Privileges include SeDebugPrivilege, SeTcbPrivilege, or SeLoadDriverPrivilege.",
            "Account is not a known administrator or service account.",
            "Preceded by credential-stuffing or brute-force events on this host.",
        ])
        return

    if event_id == "4634":
        why_likely_benign.append(
            "Logoff events are normal and expected — no action required unless part of a suspicious pattern."
        )
        return

    lt_name = _LOGON_TYPE_NAMES.get(lt, f"type {lt}" if lt else "unknown type")

    if event_id == "4624":
        if lt == "10":
            why_suspicious.append(
                f"Logon type 10 (RemoteInteractive / RDP) from {ip or 'unknown IP'} — "
                "review for unauthorised remote access."
            )
            important_fields.append({"field": "logonType", "value": "10 (RDP)", "reason": "Remote logon"})
        elif lt == "9":
            why_suspicious.append(
                "Logon type 9 (NewCredentials / RunAs) — explicit alternative credentials used. "
                "Verify this is expected administrative activity."
            )
        elif lt == "3" and (not ip or ip in ("-", "::1", "127.0.0.1")):
            why_likely_benign.append(
                "Network logon from localhost or blank IP is typical for service account activity."
            )
        else:
            why_likely_benign.append(
                f"Logon type {lt_name} is common and expected in routine operation."
            )
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            important_fields.append({"field": "ipAddress", "value": ip, "reason": "Remote source IP"})
        escalation_conditions.extend([
            "Source IP is external, unusual, or flagged by threat intelligence.",
            "User account is privileged or service account used interactively.",
            "Logon follows failed logon attempts (4625) within a short window.",
        ])

    elif event_id == "4625":
        why_likely_benign.append(
            "A single failed logon is common (mistyped password, expired token, etc.)."
        )
        not_enough_evidence.append(
            "A pattern of 4625 events (brute force) requires multiple events — "
            "assess this event in the context of the full timeline."
        )
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            important_fields.append({"field": "ipAddress", "value": ip, "reason": "Source of failed logon"})
        escalation_conditions.extend([
            "Many failures in a short window from the same source IP (brute force).",
            "Failures targeting a privileged or service account.",
            "Followed by a successful 4624 from the same source.",
        ])

    elif event_id == "4648":
        why_suspicious.append(
            "Explicit credentials passed at logon can indicate pass-the-hash, credential theft, "
            "or deliberate impersonation."
        )
        not_enough_evidence.append(
            "Verify if this user is expected to use RunAs or explicit credentials on this host."
        )
        escalation_conditions.extend([
            "Target user is a domain administrator or service account.",
            "Preceded by a credential dumping event or failed logon burst.",
            "Source process is an unexpected binary.",
        ])

    if not user:
        not_enough_evidence.append("Username is missing — cannot identify the account involved.")


# ══════════════════════════════════════════════════════════════════════════════
# Service install helpers (4697 / 7045)
# ══════════════════════════════════════════════════════════════════════════════

_SAFE_SERVICE_PUBLISHERS: tuple[str, ...] = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
)

_HIGH_RISK_SERVICE_PATHS: tuple[str, ...] = (
    "\\temp\\", "\\appdata\\", "\\downloads\\", "\\users\\public\\",
    "cmd.exe", "powershell", "mshta", "wscript", "cscript",
)


def _analyze_service_install(
    *,
    win_ev: dict,
    why_suspicious: list[str],
    why_likely_benign: list[str],
    not_enough_evidence: list[str],
    escalation_conditions: list[str],
    important_fields: list[dict],
) -> None:
    svc_name = _s(win_ev.get("serviceName") or win_ev.get("servicename") or "")
    svc_file = _s(win_ev.get("serviceFileName") or win_ev.get("servicefilename") or "")
    svc_acct = _s(win_ev.get("serviceAccount") or win_ev.get("serviceaccount") or "")
    svc_file_l = svc_file.lower()

    if not svc_file:
        not_enough_evidence.append("Service binary path is empty — cannot assess legitimacy.")
    else:
        important_fields.append(
            {"field": "serviceFileName", "value": svc_file[:120], "reason": "New service binary to verify"}
        )
        is_safe = any(svc_file_l.startswith(p) for p in _SAFE_SERVICE_PUBLISHERS)
        is_risky = any(p in svc_file_l for p in _HIGH_RISK_SERVICE_PATHS)
        if is_risky:
            why_suspicious.append(
                f"Service binary path contains a high-risk location or interpreter: {svc_file[:80]}."
            )
        elif is_safe:
            why_likely_benign.append(
                f"Service binary is under a standard Windows or Program Files location: {svc_file[:80]}."
            )
        else:
            not_enough_evidence.append(
                f"Service binary is at an unfamiliar path: {svc_file[:80]}. Verify against known software."
            )

    if svc_acct in ("LocalSystem", "NT AUTHORITY\\SYSTEM", "SYSTEM"):
        why_suspicious.append(
            "Service runs as SYSTEM (highest privilege) — this is expected for some drivers but "
            "unusual for user-installed software."
        )
    elif not svc_acct:
        not_enough_evidence.append("Service account is not recorded — cannot assess privilege level.")

    if svc_name:
        important_fields.append(
            {"field": "serviceName", "value": svc_name, "reason": "New service name to verify"}
        )

    escalation_conditions.extend([
        "Binary path is under Temp, AppData, or contains shell interpreters (cmd, powershell, mshta).",
        "Service account is SYSTEM and binary is not from a trusted publisher.",
        "Service name is random-looking or mimics a known Windows service name.",
        "Installation follows unusual logon or privilege escalation events.",
        "Binary is not code-signed or hash is unknown.",
    ])


# ══════════════════════════════════════════════════════════════════════════════
# Service type change helper (7040)
# ══════════════════════════════════════════════════════════════════════════════

_SECURITY_SERVICES: frozenset[str] = frozenset({
    "windows defender", "wdav", "wscsvc", "wuauserv", "eventlog",
    "vss", "swprv", "mpssvc", "windefend", "securityhealthservice",
    "sfc", "bits",
})


def _analyze_service_change(
    *,
    win_ev: dict,
    rule_level: int,
) -> tuple[float, str, str, str, list[str], list[str]]:
    svc_name = _s(win_ev.get("param1") or "").lower()
    old_type = _s(win_ev.get("param2") or "")
    new_type = _s(win_ev.get("param3") or "")
    why_suspicious: list[str] = []
    why_likely_benign: list[str] = []

    is_security = any(kw in svc_name for kw in _SECURITY_SERVICES)
    disabled    = "disabled" in new_type.lower() if new_type else False

    if is_security:
        why_suspicious.append(
            f"A security-relevant service ({svc_name}) had its startup type changed."
        )
        if disabled:
            why_suspicious.append(
                f"The service was set to 'disabled' — this can suppress security monitoring."
            )
        risk = 7.5; sev = "high"; verdict = "investigate"; conf = "high"
    elif disabled:
        why_suspicious.append(
            f"Service '{svc_name}' was disabled — verify if this is expected administrative activity."
        )
        risk = 4.5; sev = "medium"; verdict = "review"; conf = "medium"
    else:
        why_likely_benign.append(
            f"Startup type changed for '{svc_name}' — this is common during software updates."
        )
        risk = 3.5; sev = "low"; verdict = "review"; conf = "low"

    return risk, sev, verdict, conf, why_suspicious, why_likely_benign


# ══════════════════════════════════════════════════════════════════════════════
# Scheduled task helper (4698)
# ══════════════════════════════════════════════════════════════════════════════

def _analyze_scheduled_task(
    *,
    win_ev: dict,
    why_suspicious: list[str],
    why_likely_benign: list[str],
    not_enough_evidence: list[str],
    escalation_conditions: list[str],
    important_fields: list[dict],
) -> None:
    task_name    = _s(win_ev.get("taskName") or win_ev.get("taskname") or "")
    task_content = _s(win_ev.get("taskContent") or win_ev.get("taskcontent") or "")
    content_l    = task_content.lower()

    risky_kw = ("powershell", "cmd.exe", "mshta", "wscript", "cscript",
                 "encoded", "-enc", "bypass", "http", "bitsadmin", "regsvr32")
    hits = [kw for kw in risky_kw if kw in content_l]

    if task_name:
        important_fields.append(
            {"field": "taskName", "value": task_name[:80], "reason": "Verify this task name is expected"}
        )
    if hits:
        why_suspicious.append(
            f"Task action contains high-risk keywords: {', '.join(hits[:4])}."
        )
    elif task_content:
        why_likely_benign.append(
            "Task action does not contain obvious shell interpreter or download keywords."
        )
    else:
        not_enough_evidence.append(
            "Task content is not available — cannot evaluate the actual action the task will perform."
        )

    escalation_conditions.extend([
        "Task action launches PowerShell, mshta, wscript, or downloads a file.",
        "Task runs at logon, as SYSTEM, or with elevated privileges.",
        "Task name mimics a Windows built-in task.",
        "Task was created by an unexpected user or process.",
    ])


# ══════════════════════════════════════════════════════════════════════════════
# Application crash helper (1000 / 1001 / 1002 / 1026)
# ══════════════════════════════════════════════════════════════════════════════

_SECURITY_PROCESSES: frozenset[str] = frozenset({
    "lsass.exe", "winlogon.exe", "services.exe", "csrss.exe",
    "smss.exe", "wininit.exe", "svchost.exe", "ntoskrnl.exe",
    "msseces.exe", "msmpeng.exe", "mpcmdrun.exe",
})


def _analyze_app_crash(
    *,
    event: dict,
    win_ev: dict,
    why_suspicious: list[str],
    why_likely_benign: list[str],
    not_enough_evidence: list[str],
    escalation_conditions: list[str],
) -> None:
    app_name  = _s(win_ev.get("applicationName") or win_ev.get("applicationname")
                   or event.get("rule", {}).get("description") or "")
    app_n_l   = app_name.lower()

    is_security = any(p in app_n_l for p in _SECURITY_PROCESSES)
    if is_security:
        why_suspicious.append(
            f"A security-critical process ({app_name}) crashed — this may indicate exploitation "
            "or a forced termination attempt."
        )
    else:
        why_likely_benign.append(
            "Application crashes are common and usually caused by bugs, resource exhaustion, "
            "or transient OS conditions."
        )
        not_enough_evidence.append(
            "A single crash event alone cannot distinguish exploitation from a benign crash. "
            "Review crash dumps and correlate with security events."
        )

    escalation_conditions.extend([
        "Crashed process is a security or authentication component (lsass, winlogon, AV).",
        "Crash is followed by a new process creation or logon attempt.",
        "Multiple crashes on the same process in a short window.",
        "Crash dump contains shellcode patterns (requires external analysis).",
    ])


# ══════════════════════════════════════════════════════════════════════════════
# Linux SSH helper
# ══════════════════════════════════════════════════════════════════════════════

def _analyze_linux_ssh(
    event: dict,
    rule_level: int,
) -> tuple[str, str, list[str], list[str], list[str], list[str]]:
    rule_desc  = str((event.get("rule") or {}).get("description") or "")
    srcip      = str(event.get("srcip") or (event.get("data") or {}).get("srcip") or "")
    user       = str(event.get("dstuser") or (event.get("data") or {}).get("dstuser") or "")
    desc_l     = rule_desc.lower()

    is_fail    = "fail" in desc_l or "invalid" in desc_l or "refused" in desc_l
    is_success = "success" in desc_l or "accepted" in desc_l

    title    = "SSH Authentication Failure" if is_fail else "SSH Logon"
    subtitle = f"{user or 'unknown user'} from {srcip or 'unknown IP'}" if (user or srcip) else rule_desc

    why_suspicious:      list[str] = []
    why_likely_benign:   list[str] = []
    not_enough_evidence: list[str] = []
    escalation_conditions: list[str] = []

    if is_fail:
        why_likely_benign.append("A single SSH authentication failure is normal.")
        not_enough_evidence.append(
            "Multiple failures from the same IP are required to assess brute-force activity."
        )
        escalation_conditions.extend([
            "Many failures from the same source IP in a short window.",
            "Failures targeting root or a privileged account.",
            "Followed by a successful SSH logon from the same IP.",
        ])
    elif is_success:
        if user in ("root", "admin"):
            why_suspicious.append(
                f"SSH logon as '{user}' — direct root/admin access via SSH should be restricted."
            )
        else:
            why_likely_benign.append("Successful SSH logon by a non-root user is typical for remote management.")
        if srcip:
            not_enough_evidence.append(
                f"Verify that {srcip} is an expected source for SSH connections."
            )
        escalation_conditions.extend([
            "Logon as root or administrator when root SSH is supposed to be disabled.",
            "Source IP is external or not in the expected management range.",
            "Logon follows failed authentication attempts from the same IP.",
        ])
    else:
        not_enough_evidence.append("SSH event type is unclear from the description — review raw event.")

    return title, subtitle, why_suspicious, why_likely_benign, not_enough_evidence, escalation_conditions


# ══════════════════════════════════════════════════════════════════════════════
# Linux FIM helper
# ══════════════════════════════════════════════════════════════════════════════

_SENSITIVE_FIM_PATHS: tuple[str, ...] = (
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d",
    "authorized_keys", "/etc/ssh/sshd_config", "/etc/hosts",
    "/etc/crontab", "/etc/cron.", "/var/spool/cron",
)


def _analyze_linux_fim(
    event: dict,
    syscheck: dict,
    rule_level: int,
) -> tuple[str, str, list[str], list[str], list[str], list[str]]:
    path       = str(syscheck.get("path") or "")
    event_type = str(syscheck.get("event") or "")
    path_l     = path.lower()

    title    = f"File {event_type.capitalize() or 'Changed'}"
    subtitle = path or "unknown path"

    why_suspicious:      list[str] = []
    why_likely_benign:   list[str] = []
    not_enough_evidence: list[str] = []
    escalation_conditions: list[str] = []

    is_sensitive = any(p in path_l for p in _SENSITIVE_FIM_PATHS)
    if is_sensitive:
        why_suspicious.append(
            f"Sensitive file modified: {path}. "
            "Changes to this file can affect authentication, authorisation, or SSH access."
        )
    else:
        why_likely_benign.append(
            f"{path} is not in the list of critical system files — "
            "this change may be from normal software maintenance."
        )
        not_enough_evidence.append(
            "The modifying process or user is not visible in the FIM event alone. "
            "Correlate with auditd or sudo logs."
        )

    escalation_conditions.extend([
        "Modified file is /etc/passwd, /etc/shadow, authorized_keys, or sshd_config.",
        "Change was made by an unexpected user or process.",
        "Change followed an unusual SSH logon or privilege escalation.",
        "New file created in a cron directory.",
    ])

    return title, subtitle, why_suspicious, why_likely_benign, not_enough_evidence, escalation_conditions


# ══════════════════════════════════════════════════════════════════════════════
# Linux auditd helper
# ══════════════════════════════════════════════════════════════════════════════

def _analyze_linux_auditd(
    event: dict,
    rule_level: int,
) -> tuple[str, str, list[str], list[str], list[str], list[str]]:
    rule_desc  = str((event.get("rule") or {}).get("description") or "")
    rule_groups: list[str] = list((event.get("rule") or {}).get("groups") or [])
    groups_str  = " ".join(rule_groups).lower()
    data        = event.get("data") or {}

    title    = rule_desc or "Linux Audit Event"
    subtitle = ""

    why_suspicious:      list[str] = []
    why_likely_benign:   list[str] = []
    not_enough_evidence: list[str] = []
    escalation_conditions: list[str] = []

    if "config_change" in groups_str:
        why_suspicious.append(
            "Audit configuration was changed — this can suppress security monitoring."
        )
        escalation_conditions.extend([
            "Audit rules modified to suppress logging of specific syscalls or paths.",
            "Change preceded by privilege escalation or lateral movement.",
        ])
    elif "add_user" in groups_str or "adduser" in rule_desc.lower():
        why_suspicious.append("A new user account was created on this host.")
        not_enough_evidence.append(
            "Verify the account was created by an authorized administrator for a legitimate purpose."
        )
    elif "del_user" in groups_str or "delete" in groups_str:
        why_suspicious.append("A user account was deleted — may be evidence of covering tracks.")
    elif "sudoers" in rule_desc.lower():
        why_suspicious.append("Sudoers file was modified — unauthorized changes grant root access.")
    else:
        why_likely_benign.append(
            "Auditd event — review context to determine if this represents expected administrative activity."
        )
        not_enough_evidence.append(
            "Auditd events require process and syscall context to properly evaluate."
        )

    escalation_conditions.extend([
        "Activity is outside normal maintenance windows.",
        "Action was performed by a non-administrative account.",
        "Audit config changes reduce logging coverage.",
    ])

    return title, subtitle, why_suspicious, why_likely_benign, not_enough_evidence, escalation_conditions
