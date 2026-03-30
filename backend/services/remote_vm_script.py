from __future__ import annotations

import json
import shlex
from datetime import datetime, timezone
from typing import Any

import paramiko

from db.database import save_finding_groups
from schemas.types import AnalysisRunRequest


def ping_remote_script(connection: dict[str, Any] | Any) -> tuple[bool, str]:
    if isinstance(connection, dict):
        vm_enabled = bool(connection.get("vm_enabled"))
        vm_host = connection.get("vm_host")
    else:
        vm_enabled = bool(connection.vm_enabled)
        vm_host = connection.vm_host

    if not vm_enabled:
        return True, "VM script execution disabled"
    if not vm_host:
        return False, "VM host missing"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=vm_host,
            port=_get(connection, "vm_port", 22),
            username=_get(connection, "vm_username"),
            password=_get(connection, "vm_password"),
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(f"test -f {shlex.quote(_get(connection, 'vm_script_path'))} && echo ok || echo missing")
        result = stdout.read().decode().strip()
        error_text = stderr.read().decode().strip()
        if result == "ok":
            return True, "SSH reachable and VM script present"
        if error_text:
            return False, error_text
        return False, "SSH reachable but VM script path not found"
    except Exception as exc:
        return False, str(exc)
    finally:
        client.close()


def run_remote_analysis_job(job_id: int, connection: dict[str, Any], request: AnalysisRunRequest) -> dict[str, Any]:
    result = run_remote_script_report(connection, request)
    save_finding_groups(job_id, result["findings"])

    return {
        "total_alerts": result["total_alerts"],
        "relevant_alerts": result["relevant_alerts"],
        "findings": result["findings"],
        "report_markdown": "```text\n" + result["report_text"].strip() + "\n```",
        "report_json": result["report_json"],
        "completed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


def run_remote_script_report(connection: dict[str, Any], request: AnalysisRunRequest) -> dict[str, Any]:
    if not connection.get("vm_enabled"):
        raise RuntimeError("VM script execution is not enabled in the active connection")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=connection.get("vm_host"),
            port=int(connection.get("vm_port") or 22),
            username=connection.get("vm_username"),
            password=connection.get("vm_password"),
            timeout=20,
            look_for_keys=False,
            allow_agent=False,
        )
        command = build_remote_command(connection, request, include_profile_args=True)
        stdin, stdout, stderr = client.exec_command(command, timeout=900)
        exit_code = stdout.channel.recv_exit_status()
        stdout_text = stdout.read().decode()
        stderr_text = stderr.read().decode()

        if exit_code != 0 and _looks_like_unrecognized_arguments(stderr_text or stdout_text):
            fallback_command = build_remote_command(connection, request, include_profile_args=False)
            stdin, stdout, stderr = client.exec_command(fallback_command, timeout=900)
            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode()
            stderr_text = stderr.read().decode()

        if exit_code != 0:
            raise RuntimeError(stderr_text.strip() or stdout_text.strip() or f"Remote script failed with exit code {exit_code}")

        parsed_stdout = _extract_embedded_reports(stdout_text)
        report_txt = parsed_stdout.get("report_text")
        report_json = parsed_stdout.get("report_json")

        if not report_txt or not report_json:
            raise RuntimeError(
                "Remote script did not return embedded report payload (stdout markers missing). "
                "Please deploy the latest /home/ai_wazuh_24h_v2.py version."
            )
    finally:
        client.close()

    parsed_report = json.loads(report_json)
    findings = normalize_remote_findings(parsed_report)

    return {
        "total_alerts": int(parsed_report.get("total_alerts", 0)),
        "relevant_alerts": int(parsed_report.get("relevant_alerts", 0)),
        "findings": findings,
        "report_text": report_txt,
        "report_json": report_json,
        "parsed_report": parsed_report,
    }


def build_remote_command(connection: dict[str, Any], request: AnalysisRunRequest, include_profile_args: bool = True) -> str:
    command_parts = [
        shlex.quote(connection["vm_python_path"]),
        shlex.quote(connection["vm_script_path"]),
        "--indexer-url",
        shlex.quote(connection["indexer_url"]),
        "--indexer-user",
        shlex.quote(connection["indexer_username"]),
        "--indexer-pass",
        shlex.quote(connection["indexer_password"]),
        "--index-pattern",
        shlex.quote(connection["indexer_index_pattern"]),
        "--ollama-url",
        shlex.quote(connection["ollama_url"].rstrip("/") + "/api/generate"),
        "--ollama-model",
        shlex.quote(connection["ollama_model"]),
        "--lookback-hours",
        str(request.lookback_hours),
        "--size",
        str(request.query_size),
        "--output-txt",
        shlex.quote(connection["vm_report_txt_path"]),
        "--output-json",
        shlex.quote(connection["vm_report_json_path"]),
        "--stdout-only",
    ]
    if not connection.get("verify_ssl"):
        command_parts.append("--insecure")
    if request.only_windows or request.platform_filter == "windows":
        command_parts.append("--only-windows")
    if request.only_linux or request.platform_filter == "linux":
        command_parts.append("--only-linux")
    if request.include_noise:
        command_parts.append("--include-noise")
    if not request.run_ai:
        command_parts.append("--skip-ai")
    if request.host_filter:
        command_parts.extend(["--host-filter", shlex.quote(request.host_filter)])
    if include_profile_args:
        if request.event_ids:
            command_parts.extend(["--event-ids", shlex.quote(",".join(request.event_ids))])
        if request.min_rule_level is not None:
            command_parts.extend(["--min-rule-level", str(int(request.min_rule_level))])
        if request.max_findings is not None:
            command_parts.extend(["--max-findings", str(int(request.max_findings))])
        if request.max_events_per_host is not None:
            command_parts.extend(["--max-events-per-host", str(int(request.max_events_per_host))])
    return " ".join(command_parts)


def _looks_like_unrecognized_arguments(text: str) -> bool:
    lowered = (text or "").lower()
    return "unrecognized arguments" in lowered or "error: unrecognized" in lowered


def normalize_remote_findings(parsed_report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in parsed_report.get("findings", []):
        findings.append(
            {
                "host": item.get("host", "unknown-host"),
                "platform": item.get("platform", "other"),
                "event_id": item.get("event_id"),
                "rule_id": item.get("rule_id"),
                "rule_description": item.get("rule_description") or item.get("description"),
                "count": int(item.get("count", 0)),
                "group_key": item.get("group_key") or f"{item.get('host', 'unknown-host')}|{item.get('platform', 'other')}|{item.get('event_id') or item.get('rule_id') or 'n/a'}",
                "local_severity": item.get("local_severity", item.get("ai_severity", "low")),
                "local_score": int(item.get("local_score", 0)),
                "confidence": int(item.get("confidence", 50)),
                "suspicious": bool(item.get("suspicious", False)),
                "ai_severity": item.get("ai_severity", item.get("local_severity", "low")),
                "reason": item.get("reason", "Remote script completed"),
                "recommended_checks": item.get("recommended_checks", []),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
            }
        )
    return findings


def _extract_embedded_reports(stdout_text: str) -> dict[str, str]:
    report_text = _extract_between(stdout_text, "===REPORT_TEXT_BEGIN===", "===REPORT_TEXT_END===")
    report_json = _extract_between(stdout_text, "===REPORT_JSON_BEGIN===", "===REPORT_JSON_END===")
    payload: dict[str, str] = {}
    if report_text is not None:
        payload["report_text"] = report_text.strip()
    if report_json is not None:
        payload["report_json"] = report_json.strip()
    return payload


def _extract_between(text: str, start_marker: str, end_marker: str) -> str | None:
    start_index = text.find(start_marker)
    if start_index == -1:
        return None
    start_index += len(start_marker)
    end_index = text.find(end_marker, start_index)
    if end_index == -1:
        return None
    return text[start_index:end_index]


def _get(connection: dict[str, Any] | Any, key: str, default: Any = None) -> Any:
    if isinstance(connection, dict):
        return connection.get(key, default)
    return getattr(connection, key, default)