from __future__ import annotations

import json
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