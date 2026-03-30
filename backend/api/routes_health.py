from fastapi import APIRouter, HTTPException

from db.database import get_active_connection
from services.ollama_client import ping_ollama
from services.wazuh_indexer import ping_indexer

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/indexer")
def health_indexer() -> dict[str, str | bool]:
    connection = get_active_connection()
    if not connection:
        raise HTTPException(status_code=404, detail="No active connection configured")

    success, detail = ping_indexer(connection)
    return {"status": "ok" if success else "error", "reachable": success, "detail": detail}


@router.get("/ollama")
def health_ollama() -> dict[str, str | bool]:
    connection = get_active_connection()
    if not connection:
        raise HTTPException(status_code=404, detail="No active connection configured")

    success, detail = ping_ollama(connection)
    return {"status": "ok" if success else "error", "reachable": success, "detail": detail}
