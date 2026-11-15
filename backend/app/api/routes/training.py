from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from app.core.dependencies import get_current_user
from app.schemas.training import (
    TrainingScenarioPublic,
    TrainingSubmissionRequest,
    TrainingEvaluationResult,
    TrainingUserStats
)
from app.services.training_service import (
    get_all_scenarios_public,
    get_user_training_stats,
    evaluate_user_submission,
    reset_user_training
)

router = APIRouter()

@router.get("/scenarios", response_model=List[TrainingScenarioPublic])
async def list_scenarios(current_user: dict = Depends(get_current_user)):
    """Fetch all training scenarios without exposing actual answers or explanations."""
    return get_all_scenarios_public()

@router.get("/stats", response_model=TrainingUserStats)
async def get_stats(current_user: dict = Depends(get_current_user)):
    """Get the current authenticated user's training completion and accuracy metrics."""
    return await get_user_training_stats(current_user["sub"])

@router.post("/submit", response_model=TrainingEvaluationResult)
async def submit_answer(
    request: TrainingSubmissionRequest,
    current_user: dict = Depends(get_current_user)
):
    """Evaluate a user's answer against scenario ground truth and ML analysis."""
    try:
        return await evaluate_user_submission(current_user["sub"], request)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )

@router.post("/reset")
async def reset_progress(current_user: dict = Depends(get_current_user)):
    """Reset the user's training scenario progress so they can retake the assessment."""
    return await reset_user_training(current_user["sub"])

