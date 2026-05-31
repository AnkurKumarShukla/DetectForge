"""Rule genealogy — full audit trail from gap identification to health history."""
from sqlalchemy.orm import Session

from db.models import DriftEvent, ReviewQueue, Rule, TuningHistory


def get_rule_lineage(rule_id: str, db: Session) -> dict | None:
    rule = db.get(Rule, rule_id)
    if not rule:
        return None

    tuning = db.query(TuningHistory).filter(
        TuningHistory.rule_id == rule_id
    ).order_by(TuningHistory.iteration).all()

    drift = db.query(DriftEvent).filter(
        DriftEvent.rule_id == rule_id
    ).order_by(DriftEvent.detected_at.asc()).all()

    review = db.query(ReviewQueue).filter(ReviewQueue.rule_id == rule_id).first()

    # Find all regenerated children
    children = db.query(Rule).filter(Rule.parent_rule_id == rule_id).all()

    return {
        "rule_id": rule_id,
        "technique_id": rule.technique_id,
        "technique_name": rule.technique_name,
        "tactic": rule.tactic,
        "current_status": rule.status,
        "current_spl": rule.spl,
        "origin": {
            "identified_at": rule.created_at.isoformat() if rule.created_at else None,
            "confidence_score": rule.confidence_score,
            "generation_attempts": rule.generation_attempts,
            "used_seed": rule.generation_attempts >= 3 and rule.confidence_score < 0.70,
        },
        "validation": {
            "hits_per_day": rule.hits_per_day,
            "false_pos_estimate": rule.false_pos_estimate,
            "tuning_rounds": rule.tuning_rounds,
        },
        "tuning_history": [
            {
                "iteration": t.iteration,
                "hits_before": t.hits_before,
                "hits_after": t.hits_after,
                "reason": t.reason,
                "tuned_at": t.tuned_at.isoformat() if t.tuned_at else None,
            }
            for t in tuning
        ],
        "review": {
            "mandatory": review.mandatory if review else None,
            "decision": review.decision if review else None,
            "decided_by": review.decided_by if review else None,
            "decided_at": review.decided_at.isoformat() if review and review.decided_at else None,
            "edit_notes": review.edit_notes if review else None,
        } if review else None,
        "deployment": {
            "splunk_search_name": rule.splunk_search_name,
            "deployed_at": rule.deployed_at.isoformat() if rule.deployed_at else None,
            "reviewed_by": rule.reviewed_by,
        },
        "health_history": [
            {
                "drift_type": d.drift_type,
                "detail": d.detail,
                "detected_at": d.detected_at.isoformat() if d.detected_at else None,
                "resolved_at": d.resolved_at.isoformat() if d.resolved_at else None,
                "resolution": d.resolution,
            }
            for d in drift
        ],
        "regenerated_as": [c.id for c in children],
    }
