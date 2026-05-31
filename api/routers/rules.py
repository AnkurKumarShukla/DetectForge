"""Rules API endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import Rule, TuningHistory, DriftEvent

router = APIRouter(tags=["rules"])


@router.get("/rules")
def list_rules(
    db: Annotated[Session, Depends(get_db)],
    status: str | None = Query(None),
    scan_id: str | None = Query(None),
    limit: int = Query(50, le=200),
):
    q = db.query(Rule)
    if status:
        q = q.filter(Rule.status == status)
    if scan_id:
        q = q.filter(Rule.scan_id == scan_id)
    q = q.order_by(Rule.created_at.desc()).limit(limit)
    return [_rule_to_dict(r) for r in q.all()]


@router.get("/rules/{rule_id}")
def get_rule(rule_id: str, db: Annotated[Session, Depends(get_db)]):
    rule = db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    result = _rule_to_dict(rule)

    tuning = db.query(TuningHistory).filter(TuningHistory.rule_id == rule_id).order_by(TuningHistory.iteration).all()
    result["tuning_history"] = [
        {
            "iteration": t.iteration,
            "hits_before": t.hits_before,
            "hits_after": t.hits_after,
            "reason": t.reason,
            "tuned_at": t.tuned_at.isoformat() if t.tuned_at else None,
        }
        for t in tuning
    ]

    drift = db.query(DriftEvent).filter(DriftEvent.rule_id == rule_id).order_by(DriftEvent.detected_at.desc()).all()
    result["drift_events"] = [
        {
            "drift_type": d.drift_type,
            "detail": d.detail,
            "detected_at": d.detected_at.isoformat() if d.detected_at else None,
            "resolved_at": d.resolved_at.isoformat() if d.resolved_at else None,
            "resolution": d.resolution,
        }
        for d in drift
    ]

    return result


def _rule_to_dict(r: Rule) -> dict:
    return {
        "id": r.id,
        "technique_id": r.technique_id,
        "technique_name": r.technique_name,
        "tactic": r.tactic,
        "spl": r.spl,
        "spl_explanation": r.spl_explanation,
        "splunk_search_name": r.splunk_search_name,
        "confidence_score": r.confidence_score,
        "generation_attempts": r.generation_attempts,
        "tuning_rounds": r.tuning_rounds,
        "hits_per_day": r.hits_per_day,
        "false_pos_estimate": r.false_pos_estimate,
        "status": r.status,
        "industry": r.industry,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "deployed_at": r.deployed_at.isoformat() if r.deployed_at else None,
        "reviewed_by": r.reviewed_by,
    }
