"""Auto-Tuner: reduces false positives via saia_optimize_spl feedback loop."""
import logging

from sqlalchemy.orm import Session

from core.agent.nodes.validator import validate_spl, STATUS_GOOD, STATUS_DATA_ABSENT
from core.config import get_settings
from core.splunk.mcp_client import SplunkMCPClient
from db.models import Rule, TuningHistory

logger = logging.getLogger(__name__)


def tune_rule(rule: Rule, mcp: SplunkMCPClient, db: Session) -> dict:
    """
    Run up to max_tuning_rounds of saia_optimize_spl + re-validation.
    Updates the rule record in DB with each round.
    Returns final validation result.
    """
    settings = get_settings()
    max_rounds = settings.max_tuning_rounds
    current_spl = rule.spl
    index = rule.index_name or "main"
    sourcetype = rule.sourcetype or "*"

    last_validation: dict = {}

    for round_num in range(1, max_rounds + 1):
        hits_per_day = rule.hits_per_day or 999.0
        issue = f"Rule generates {hits_per_day} hits/day which is too noisy for production use. Reduce false positives by adding more specific filters, time windows, or statistical thresholds."

        try:
            tuned_spl = mcp.optimize_spl(current_spl, issue, hits_per_day)
        except Exception as e:
            logger.error("saia_optimize_spl failed on round %d: %s", round_num, e)
            break

        if not tuned_spl.strip() or tuned_spl.strip() == current_spl.strip():
            logger.info("Auto-tuner: no change from optimizer on round %d", round_num)
            break

        # Re-validate the tuned SPL
        validation = validate_spl(tuned_spl, index, sourcetype, mcp)

        # Log tuning history
        history = TuningHistory(
            rule_id=rule.id,
            iteration=round_num,
            spl_before=current_spl,
            spl_after=tuned_spl,
            hits_before=hits_per_day,
            hits_after=validation["hits_per_day"],
            reason=issue,
        )
        db.add(history)

        # Update rule
        rule.spl = tuned_spl
        rule.hits_per_day = validation["hits_per_day"]
        rule.tuning_rounds = round_num
        db.commit()

        current_spl = tuned_spl
        last_validation = validation

        logger.info(
            "[AutoTuner] Round %d/%d: %.1f → %.1f hits/day status=%s",
            round_num, max_rounds, hits_per_day, validation["hits_per_day"], validation["status"],
        )

        if validation["status"] in (STATUS_GOOD, STATUS_DATA_ABSENT):
            return validation

    # After max rounds, flag for human review
    if not last_validation:
        last_validation = {"status": "NEEDS_HUMAN_REVIEW", "hits_per_day": rule.hits_per_day or 999.0}
    else:
        last_validation["status"] = "NEEDS_HUMAN_REVIEW"

    rule.status = "PENDING_REVIEW"
    db.commit()
    return last_validation
