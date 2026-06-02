from dotenv import load_dotenv
load_dotenv(dotenv_path=__import__('pathlib').Path(__file__).parent.parent / '.env', override=False)

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
from api.routes_fleet_scan import router as fleet_scan_router
from api.routes_integrations_tactical import router as tactical_router
from api.routes_unified_hosts import router as unified_hosts_router
from api.routes_constellation import router as constellation_router
from api.routes_event_map import router as event_map_router
from api.routes_scripts import router as scripts_router
from api.routes_timeline import router as timeline_router
from api.routes_audit import router as audit_router
from api.routes_validation import router as validation_router
from api.routes_runner import router as runner_router
from api.routes_event_evaluation import router as event_evaluation_router
from api.routes_wazuh_manager import router as wazuh_manager_router
from api.routes_server import router as server_router
from db.database import init_db, ensure_default_connection, ensure_runner_scripts
from services.app_config import sync_config_connection_to_db


init_db()
ensure_default_connection()
sync_config_connection_to_db()
ensure_runner_scripts()


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
app.include_router(fleet_scan_router)
app.include_router(baseline_router)
app.include_router(tactical_router)
app.include_router(unified_hosts_router)
app.include_router(constellation_router)
app.include_router(event_map_router)
app.include_router(scripts_router)
app.include_router(timeline_router)
app.include_router(audit_router)
app.include_router(validation_router)
app.include_router(runner_router)
app.include_router(event_evaluation_router)
app.include_router(wazuh_manager_router)
app.include_router(server_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "Wazuh AI Analyzer API", "status": "ok"}
