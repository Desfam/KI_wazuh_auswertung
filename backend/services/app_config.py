from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from db.database import upsert_active_connection
from schemas.types import AnalysisProfileConfig, ConnectionCreate


CONFIG_PATH = Path(__file__).resolve().parents[2] / ".config" / "app-config.json"


def _connection_payload_to_dict(payload: ConnectionCreate | dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload, dict):
        data = dict(payload)
    elif hasattr(payload, "model_dump"):
        data = payload.model_dump()
    else:
        data = payload.dict()

    data.pop("id", None)
    data.pop("created_at", None)
    data.pop("updated_at", None)
    data.pop("is_active", None)
    return data


def load_connection_from_config() -> ConnectionCreate | None:
    if not CONFIG_PATH.exists():
        return None

    raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    connection_data = raw.get("connection")
    if not isinstance(connection_data, dict):
        return None

    return ConnectionCreate(**connection_data)


def sync_config_connection_to_db() -> int | None:
    payload = load_connection_from_config()
    if payload is None:
        return None
    return upsert_active_connection(payload)


def save_connection_to_config(payload: ConnectionCreate | dict[str, Any]) -> None:
    connection_data = _connection_payload_to_dict(payload)
    config: dict[str, Any] = {}
    if CONFIG_PATH.exists():
        try:
            config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            config = {}

    config["connection"] = connection_data
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")


def load_analysis_profile_from_config() -> AnalysisProfileConfig:
    if not CONFIG_PATH.exists():
        return AnalysisProfileConfig()
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return AnalysisProfileConfig()
    profile = raw.get("analysis_profile")
    if not isinstance(profile, dict):
        return AnalysisProfileConfig()
    return AnalysisProfileConfig(**profile)


def save_analysis_profile_to_config(payload: AnalysisProfileConfig | dict[str, Any]) -> AnalysisProfileConfig:
    profile_data = payload.model_dump() if hasattr(payload, "model_dump") else dict(payload)
    config: dict[str, Any] = {}
    if CONFIG_PATH.exists():
        try:
            config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            config = {}
    config["analysis_profile"] = profile_data
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return AnalysisProfileConfig(**profile_data)


def load_remote_access_mode_from_config() -> dict[str, Any]:
    default = {
        "mode": "admin",
        "changed_by": "system",
        "changed_at": "",
        "reason": "",
    }
    if not CONFIG_PATH.exists():
        return default

    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default

    mode_data = raw.get("remote_access_mode")
    if not isinstance(mode_data, dict):
        return default

    mode = str(mode_data.get("mode", "admin")).strip().lower()
    if mode not in {"safe", "admin", "break_glass"}:
        mode = "admin"

    return {
        "mode": mode,
        "changed_by": str(mode_data.get("changed_by", "system")),
        "changed_at": str(mode_data.get("changed_at", "")),
        "reason": str(mode_data.get("reason", "")),
    }


def save_remote_access_mode_to_config(mode: str, changed_by: str, reason: str = "") -> dict[str, Any]:
    clean_mode = str(mode).strip().lower()
    if clean_mode not in {"safe", "admin", "break_glass"}:
        raise ValueError("mode must be one of: safe, admin, break_glass")

    payload = {
        "mode": clean_mode,
        "changed_by": str(changed_by or "system").strip() or "system",
        "changed_at": datetime.now(timezone.utc).isoformat(),
        "reason": str(reason or "").strip(),
    }

    config: dict[str, Any] = {}
    if CONFIG_PATH.exists():
        try:
            config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            config = {}

    config["remote_access_mode"] = payload
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return payload