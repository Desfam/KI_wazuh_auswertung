from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes_analysis import router as analysis_router
from api.routes_baseline import router as baseline_router
from api.routes_connections import router as connections_router
from api.routes_health import router as health_router
from api.routes_hosts import router as hosts_router
from api.routes_profiles import router as profiles_router
from api.routes_reports import router as reports_router
from api.routes_snipen import router as snipen_router
from api.routes_system import router as system_router
from api.routes_fullscan import router as fullscan_router
from db.database import init_db, ensure_default_connection
from services.app_config import sync_config_connection_to_db


init_db()
ensure_default_connection()
sync_config_connection_to_db()


app = FastAPI(
    title="Wazuh AI Analyzer",
    version="0.1.0",
    description=(
        "Desktop-oriented security analysis backend for Wazuh alerts, "
        "local risk scoring, and Ollama-assisted triage."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(connections_router)
app.include_router(analysis_router)
app.include_router(hosts_router)
app.include_router(reports_router)
app.include_router(system_router)
app.include_router(snipen_router)
app.include_router(profiles_router)
app.include_router(fullscan_router)
app.include_router(baseline_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "Wazuh AI Analyzer API", "status": "ok"}
