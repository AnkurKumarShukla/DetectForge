"""Rule genealogy and coverage timeline endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from db.database import get_db
from features.coverage_timeline.timeline_tracker import get_drift_summary, get_timeline
from features.genealogy.rule_lineage import get_rule_lineage

router = APIRouter(tags=["genealogy"])


@router.get("/rules/{rule_id}/lineage")
def rule_lineage(rule_id: str, db: Annotated[Session, Depends(get_db)]):
    lineage = get_rule_lineage(rule_id, db)
    if not lineage:
        raise HTTPException(status_code=404, detail="Rule not found")
    return lineage


@router.get("/coverage/timeline")
def coverage_timeline(
    db: Annotated[Session, Depends(get_db)],
    industry: str | None = Query(None),
    limit: int = Query(30, le=90),
):
    return get_timeline(db, industry, limit)


@router.get("/coverage/drift-summary")
def drift_summary(
    db: Annotated[Session, Depends(get_db)],
    days: int = Query(30, le=90),
):
    return get_drift_summary(db, days)
