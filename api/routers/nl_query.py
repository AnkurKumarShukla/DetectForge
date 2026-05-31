"""Natural language coverage query endpoint — powered by Claude."""
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.config import get_settings
from core.splunk.mcp_client import SplunkMCPClient
from db.database import get_db
from db.models import Gap, RuleClassification
from features.nl_interface.coverage_responder import NLCoverageResponder

router = APIRouter(tags=["nl"])


class AskRequest(BaseModel):
    question: str
    industry: str = "healthcare"
    conversation_history: list[dict] = []
    stream: bool = False


@router.post("/ask")
def ask_coverage_question(
    body: AskRequest,
    db: Annotated[Session, Depends(get_db)],
):
    settings = get_settings()
    if not settings.together_api_key:
        return {"answer": "NL interface requires TOGETHER_API_KEY to be configured.", "error": True}

    mcp = SplunkMCPClient()
    responder = NLCoverageResponder(mcp)

    coverage_map = _load_coverage_map(db)
    gaps = _load_top_gaps(db, body.industry)

    if body.stream:
        def event_stream():
            for chunk in responder.answer_stream(
                body.question, coverage_map, gaps, body.industry, body.conversation_history
            ):
                yield chunk

        return StreamingResponse(event_stream(), media_type="text/plain")

    answer = responder.answer(
        body.question, coverage_map, gaps, body.industry, body.conversation_history
    )
    return {"answer": answer, "question": body.question}


def _load_coverage_map(db: Session) -> dict:
    classifications = db.query(RuleClassification).filter(RuleClassification.technique_id.isnot(None)).all()
    return {c.technique_id: {"rule_name": c.search_name, "confidence": c.confidence} for c in classifications}


def _load_top_gaps(db: Session, industry: str, limit: int = 30) -> list[dict]:
    gaps = (
        db.query(Gap)
        .filter(Gap.industry == industry)
        .filter(Gap.status != "CLOSED")
        .order_by(Gap.financial_exposure_usd.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "technique_id": g.technique_id,
            "technique_name": g.technique_name,
            "tactic": g.tactic,
            "financial_exposure_usd": g.financial_exposure_usd,
            "status": g.status,
        }
        for g in gaps
    ]
