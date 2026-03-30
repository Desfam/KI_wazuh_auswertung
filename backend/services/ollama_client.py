from __future__ import annotations

import json
import time
from typing import Any
import re

import httpx

from services.ai_prompts import build_chat_assistant_prompt, build_structured_group_prompt
from schemas.types import OllamaAssessment


def ping_ollama(connection: dict[str, Any] | Any) -> tuple[bool, str]:
    url = connection["ollama_url"] if isinstance(connection, dict) else connection.ollama_url
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(f"{url.rstrip('/')}/api/tags")
            response.raise_for_status()
        return True, "Ollama reachable"
    except Exception as exc:
        return False, str(exc)


def assess_group(connection: dict[str, Any], group: dict[str, Any]) -> OllamaAssessment:
    prompt = build_prompt(group)
    payload = {
        "model": connection["ollama_model"],
        "format": "json",
        "stream": False,
        "prompt": prompt,
    }

    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.post(f"{connection['ollama_url'].rstrip('/')}/api/generate", json=payload)
            response.raise_for_status()
            raw_response = response.json().get("response", "{}")
    except Exception as exc:
        return OllamaAssessment(
            suspicious=bool(group.get("suspicious", False)),
            severity=group.get("local_severity", "medium"),
            reason=f"AI request failed: {exc}",
            recommended_checks=fallback_checks(group),
        )

    try:
        parsed = json.loads(raw_response)
        return OllamaAssessment(
            suspicious=bool(parsed.get("suspicious", group.get("suspicious", False))),
            severity=str(parsed.get("severity", group.get("local_severity", "medium"))).lower(),
            reason=str(parsed.get("reason", "No reason returned by model.")),
            recommended_checks=[str(item) for item in parsed.get("recommended_checks", [])],
        )
    except Exception:
        return OllamaAssessment(
            suspicious=bool(group.get("suspicious", False)),
            severity=group.get("local_severity", "medium"),
            reason=str(raw_response),
            recommended_checks=fallback_checks(group),
        )


def build_prompt(group: dict[str, Any]) -> str:
    return build_structured_group_prompt(group)


def fallback_checks(group: dict[str, Any]) -> list[str]:
    platform = group.get("platform")
    if platform == "windows":
        return [
            "Inspect raw Windows Security events on the host",
            "Correlate the target user and source address with known admin activity",
            "Review adjacent 4624, 4688, and service events for the same time window",
        ]
    return [
        "Review /var/log/auth.log or journalctl around the same time window",
        "Validate whether the account activity matches an approved change",
        "Check for additional SSH, sudo, and cron anomalies on the host",
    ]


def chat_with_context(
    connection: dict[str, Any],
    message: str,
    history: list[dict[str, str]] | None = None,
    report_context: str | None = None,
) -> str:
    def _is_raw_report_like(content: str) -> bool:
        lowered = content.lower()
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

    filtered_history = []
    for item in history or []:
        content = str(item.get("content", ""))
        role = str(item.get("role", "user"))
        if content and _is_raw_report_like(content):
            if role == "assistant":
                continue
            content = "[Nutzer hat einen Roh-Reportblock gepostet. Bitte antworte nur mit strukturierten Kernergebnissen.]"
        filtered_history.append({"role": role, "content": content})

    history_text = "\n".join(
        f"{item.get('role', 'user').upper()}: {item.get('content', '')}"
        for item in filtered_history[-8:]
        if item.get("content")
    )
    prompt = build_chat_assistant_prompt(
        report_context=report_context,
        history_text=history_text,
        message=message,
    )
    last_error: Exception | None = None
    with httpx.Client(timeout=150.0) as client:
        for attempt in range(3):
            payload = {
                "model": connection["ollama_model"],
                "stream": False,
                "prompt": prompt,
            }
            try:
                response = client.post(f"{connection['ollama_url'].rstrip('/')}/api/generate", json=payload)
                response.raise_for_status()
                return str(response.json().get("response", "")).strip()
            except httpx.HTTPStatusError as exc:
                last_error = exc
                if exc.response.status_code != 500 or attempt == 2:
                    raise
                time.sleep(2)
            except Exception as exc:
                last_error = exc
                if attempt == 2:
                    raise
                time.sleep(2)

    if last_error:
        raise last_error
    raise RuntimeError("Unexpected chat_with_context failure")
