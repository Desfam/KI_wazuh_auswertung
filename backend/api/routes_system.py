from fastapi import APIRouter, HTTPException

from schemas.types import AnalysisProfileConfig, ChatRequest, ChatResponse
from services.ai_runtime import get_state, start_service, stop_service, test_generate
from services.app_config import load_analysis_profile_from_config, save_analysis_profile_to_config
from services.chat_assistant import handle_chat

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/ai")
def ai_status() -> dict:
    return get_state()


@router.post("/ai/start")
def ai_start() -> dict:
    return start_service()


@router.post("/ai/stop")
def ai_stop() -> dict:
    return stop_service()


@router.post("/ai/test")
def ai_test() -> dict:
    return test_generate()


@router.post("/chat")
def system_chat(payload: ChatRequest) -> ChatResponse:
    try:
        return handle_chat(payload)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/analysis-profile")
def get_analysis_profile() -> AnalysisProfileConfig:
    return load_analysis_profile_from_config()


@router.put("/analysis-profile")
def update_analysis_profile(payload: AnalysisProfileConfig) -> AnalysisProfileConfig:
    return save_analysis_profile_to_config(payload)
