"""
Event Evaluation API
====================
POST /event-evaluation/evaluate-with-baseline
POST /event-evaluation/evaluate  (base KB only; optionally include baseline)
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/event-evaluation", tags=["event-evaluation"])


class EvaluateRequest(BaseModel):
    event:            dict[str, Any] = Field(description="Raw Wazuh event document")
    include_baseline: bool           = Field(default=True,
                                             description="Include host baseline context in evaluation")


@router.post("/evaluate-with-baseline")
def evaluate_with_baseline(req: EvaluateRequest) -> dict[str, Any]:
    """
    Full event evaluation: KB knowledge + host baseline context + final merged verdict.

    If the host has no baseline snapshot the evaluation still returns, but
    the baseline_context.baseline_available field will be false and a warning
    is included.
    """
    if not isinstance(req.event, dict):
        raise HTTPException(status_code=422, detail="event must be a JSON object")
    try:
        from services.final_event_evaluator import evaluate_event_with_baseline  # type: ignore[import]
        return evaluate_event_with_baseline(req.event)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Evaluation error: {exc}") from exc


@router.post("/evaluate")
def evaluate_base(req: EvaluateRequest) -> dict[str, Any]:
    """
    KB-only evaluation (fast path).  Set include_baseline=true to also
    run the full baseline-aware evaluation.
    """
    if not isinstance(req.event, dict):
        raise HTTPException(status_code=422, detail="event must be a JSON object")

    if req.include_baseline:
        try:
            from services.final_event_evaluator import evaluate_event_with_baseline  # type: ignore[import]
            return evaluate_event_with_baseline(req.event)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Evaluation error: {exc}") from exc

    # KB only
    try:
        from knowledge.event_knowledge_resolver import resolve_event_knowledge  # type: ignore[import]
        kb = resolve_event_knowledge(req.event) or {}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"KB resolver error: {exc}") from exc

    return {"knowledge": kb, "base_evaluation": None, "baseline_context": None, "final_evaluation": None}
