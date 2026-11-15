from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum

class ScenarioType(str, Enum):
    email = "email"
    sms = "sms"
    url = "url"

class DifficultyLevel(str, Enum):
    beginner = "beginner"
    intermediate = "intermediate"
    advanced = "advanced"

class TrainingScenarioPublic(BaseModel):
    id: str
    type: ScenarioType
    title: str
    difficulty: DifficultyLevel
    sender: Optional[str] = None
    subject: Optional[str] = None
    content: str
    url: Optional[str] = None
    clue_options: List[str]

class TrainingSubmissionRequest(BaseModel):
    scenario_id: str
    user_verdict: str # "safe" or "scam"
    selected_clues: List[str] = Field(default_factory=list)

class TrainingEvaluationResult(BaseModel):
    scenario_id: str
    user_verdict: str
    actual_verdict: str
    is_correct: bool
    ml_confidence: float
    ml_reasons: List[str]
    explanation: str
    key_takeaway: str
    correct_clues: List[str]
    total_score: int
    user_stats: dict

class TrainingUserStats(BaseModel):
    total_attempted: int
    total_correct: int
    accuracy_percent: float
    current_streak: int
    rank_tier: str

