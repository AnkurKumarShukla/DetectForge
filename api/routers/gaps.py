"""Gaps API endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import Gap

router = APIRouter(tags=["gaps"])


@router.get("/gaps")
def list_gaps(
    db: Annotated[Session, Depends(get_db)],
    scan_id: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, le=200),
):
    q = db.query(Gap)
    if scan_id:
        q = q.filter(Gap.scan_id == scan_id)
    if status:
        q = q.filter(Gap.status == status)
    q = q.order_by(Gap.priority_score.desc()).limit(limit)
    gaps = q.all()
    return [
        {
            "id": g.id,
            "technique_id": g.technique_id,
            "technique_name": g.technique_name,
            "tactic": g.tactic,
            "priority_score": g.priority_score,
            "financial_exposure_usd": g.financial_exposure_usd,
            "status": g.status,
            "data_gap_detail": g.data_gap_detail,
            "industry": g.industry,
            "first_identified": g.first_identified.isoformat() if g.first_identified else None,
        }
        for g in gaps
    ]


@router.get("/gaps/financial")
def gaps_by_financial_exposure(
    db: Annotated[Session, Depends(get_db)],
    scan_id: str | None = Query(None),
    limit: int = Query(20, le=100),
):
    q = db.query(Gap).filter(Gap.financial_exposure_usd.isnot(None))
    if scan_id:
        q = q.filter(Gap.scan_id == scan_id)
    gaps = q.order_by(Gap.financial_exposure_usd.desc()).limit(limit).all()
    total = sum(g.financial_exposure_usd or 0 for g in gaps)
    return {
        "gaps": [
            {
                "technique_id": g.technique_id,
                "technique_name": g.technique_name,
                "tactic": g.tactic,
                "financial_exposure_usd": g.financial_exposure_usd,
                "status": g.status,
                "priority_score": g.priority_score,
            }
            for g in gaps
        ],
        "total_exposure_usd": total,
    }
