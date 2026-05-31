"""Coverage history and stats endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import CoverageHistory, Rule, RuleClassification

router = APIRouter(tags=["coverage"])


@router.get("/coverage")
def get_current_coverage(db: Annotated[Session, Depends(get_db)]):
    latest = db.query(CoverageHistory).order_by(CoverageHistory.measured_at.desc()).first()
    if not latest:
        return {"coverage_pct": 0.0, "message": "No scan data yet — run a scan first"}

    deployed_count = db.query(Rule).filter(Rule.status == "DEPLOYED").count()
    broken_count = db.query(Rule).filter(Rule.status == "BROKEN").count()

    return {
        "coverage_pct": latest.coverage_pct,
        "techniques_covered": latest.techniques_covered,
        "techniques_total": latest.techniques_total,
        "rules_deployed": deployed_count,
        "rules_broken": broken_count,
        "financial_exposure_usd": latest.financial_exposure_usd,
        "industry_profile": latest.industry_profile,
        "measured_at": latest.measured_at.isoformat() if latest.measured_at else None,
        "scan_id": latest.scan_id,
    }


@router.get("/coverage/history")
def get_coverage_history(
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(30, le=90),
):
    history = (
        db.query(CoverageHistory)
        .order_by(CoverageHistory.measured_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "measured_at": h.measured_at.isoformat() if h.measured_at else None,
            "coverage_pct": h.coverage_pct,
            "industry_profile": h.industry_profile,
            "financial_exposure_usd": h.financial_exposure_usd,
            "scan_id": h.scan_id,
        }
        for h in history
    ]
