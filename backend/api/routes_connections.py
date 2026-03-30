from fastapi import APIRouter, HTTPException

from db.database import get_active_connection, get_connection_by_id, list_connections, save_connection, update_connection
from schemas.types import ConnectionCreate, ConnectionRecord, ConnectionTestRequest, ConnectionTestResponse
from services.app_config import save_connection_to_config
from services.remote_vm_script import ping_remote_script
from services.ollama_client import ping_ollama
from services.wazuh_indexer import ping_indexer

router = APIRouter(prefix="/connections", tags=["connections"])


@router.get("/")
def get_connections() -> list[ConnectionRecord]:
    connections = list_connections()
    # Convert integer booleans to Python bools for pydantic validation
    records = []
    for conn in connections:
        # Convert 0/1 to bool
        conn['verify_ssl'] = bool(conn.get('verify_ssl', 0))
        conn['vm_enabled'] = bool(conn.get('vm_enabled', 0))
        conn['default_only_windows'] = bool(conn.get('default_only_windows', 0))
        conn['default_only_linux'] = bool(conn.get('default_only_linux', 0))
        conn['default_include_noise'] = bool(conn.get('default_include_noise', 0))
        conn['default_run_ai'] = bool(conn.get('default_run_ai', 0))
        try:
            records.append(ConnectionRecord(**conn))
        except Exception as e:
            print(f"Error validating connection {conn.get('id')}: {e}")
            raise
    return records


@router.post("/")
def create_connection(payload: ConnectionCreate) -> ConnectionRecord:
    connection_id = save_connection(payload)
    save_connection_to_config(payload)
    record = get_connection_by_id(connection_id)
    if not record:
        raise HTTPException(status_code=500, detail="Connection could not be persisted")
    return ConnectionRecord(**record)


@router.put("/{connection_id}")
def put_connection(connection_id: int, payload: ConnectionCreate) -> ConnectionRecord:
    updated = update_connection(connection_id, payload)
    if not updated:
        raise HTTPException(status_code=404, detail="Connection not found")
    save_connection_to_config(payload)
    record = get_connection_by_id(connection_id)
    if not record:
        raise HTTPException(status_code=404, detail="Connection not found after update")
    return ConnectionRecord(**record)


@router.post("/test")
def test_connection(payload: ConnectionTestRequest) -> ConnectionTestResponse:
    indexer_ok, indexer_detail = ping_indexer(payload)
    ollama_ok, ollama_detail = ping_ollama(payload)
    vm_ok, vm_detail = ping_remote_script(payload)
    return ConnectionTestResponse(
        indexer={"ok": indexer_ok, "detail": indexer_detail},
        ollama={"ok": ollama_ok, "detail": ollama_detail},
        vm_script={"ok": vm_ok, "detail": vm_detail},
    )


@router.get("/active")
def get_connection_active() -> ConnectionRecord:
    record = get_active_connection()
    if not record:
        raise HTTPException(status_code=404, detail="No active connection configured")
    return ConnectionRecord(**record)
