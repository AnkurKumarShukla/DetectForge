"""Review queue state management."""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from core.splunk.mcp_client import SplunkMCPClient
from core.splunk.rest_client import SplunkRestClient
from core.agent.nodes.deployer import deploy_rule
from core.agent.nodes.validator import validate_spl
from db.models import ReviewQueue, Rule

logger = logging.getLogger(__name__)


def get_pending_queue(db: Session) -> list[dict]:
    entries = (
        db.query(ReviewQueue)
        .filter(ReviewQueue.decision == "PENDING")
        .order_by(ReviewQueue.mandatory.desc(), ReviewQueue.queued_at.asc())
        .all()
    )
    result = []
    for entry in entries:
        rule = entry.rule
        if not rule:
            continue
        result.append({
            "queue_id": entry.id,
            "rule_id": rule.id,
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "tactic": rule.tactic,
            "spl": rule.spl,
            "spl_explanation": rule.spl_explanation,
            "confidence_score": rule.confidence_score,
            "hits_per_day": rule.hits_per_day,
            "false_pos_estimate": rule.false_pos_estimate,
            "mandatory": entry.mandatory,
            "queued_at": entry.queued_at.isoformat() if entry.queued_at else None,
            "industry": rule.industry,
            "tuning_rounds": rule.tuning_rounds,
            "generation_attempts": rule.generation_attempts,
        })
    return result


def approve_rule(queue_id: str, reviewer: str, db: Session, mcp: SplunkMCPClient, rest: SplunkRestClient) -> bool:
    entry = db.get(ReviewQueue, queue_id)
    if not entry or entry.decision != "PENDING":
        return False

    rule = entry.rule
    entry.decision = "APPROVED"
    entry.decided_at = datetime.now(timezone.utc)
    entry.decided_by = reviewer
    rule.reviewed_at = datetime.now(timezone.utc)
    rule.reviewed_by = reviewer
    db.commit()

    success = deploy_rule(rule, rest, mcp, db)
    return success


def reject_rule(queue_id: str, reviewer: str, reason: str, db: Session) -> bool:
    entry = db.get(ReviewQueue, queue_id)
    if not entry or entry.decision != "PENDING":
        return False

    rule = entry.rule
    entry.decision = "REJECTED"
    entry.decided_at = datetime.now(timezone.utc)
    entry.decided_by = reviewer
    entry.edit_notes = reason
    rule.status = "ARCHIVED"
    rule.reviewed_at = datetime.now(timezone.utc)
    rule.reviewed_by = reviewer
    db.commit()
    return True


def edit_and_revalidate(
    queue_id: str,
    new_spl: str,
    reviewer: str,
    db: Session,
    mcp: SplunkMCPClient,
    rest: SplunkRestClient,
) -> dict:
    entry = db.get(ReviewQueue, queue_id)
    if not entry:
        return {"error": "Queue entry not found"}

    rule = entry.rule
    old_spl = rule.spl
    rule.spl = new_spl
    db.commit()

    # Re-validate with the edited SPL
    validation = validate_spl(new_spl, rule.index_name or "main", rule.sourcetype or "*", mcp)
    rule.hits_per_day = validation["hits_per_day"]
    rule.false_pos_estimate = validation.get("false_pos_estimate")
    db.commit()

    entry.edit_notes = f"SPL edited by {reviewer}. Previous: {old_spl[:100]}..."
    db.commit()

    return {"validation": validation, "rule_id": rule.id}
