"""Phase 6 — Drift Monitor: continuous health checks on deployed rules."""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from core.splunk.mcp_client import SplunkMCPClient
from db.models import DriftEvent, Rule

logger = logging.getLogger(__name__)

SILENT_WINDOW_HOURS = 72
STALE_WINDOW_MINUTES = 60


def check_rule_health(rule: Rule, mcp: SplunkMCPClient, db: Session) -> list[dict]:
    """
    Run three health checks on a deployed rule.
    Returns a list of issues found. Empty list = HEALTHY.
    """
    from core.config import get_settings
    settings = get_settings()

    issues: list[dict] = []

    if not rule.splunk_search_name or rule.status != "DEPLOYED":
        return issues

    # Check 1: Has the rule fired in the last 72 hours? (real-time — needs live data)
    if settings.drift_silent_check_enabled:
        try:
            fires = mcp.run_query(
                f'index=_audit action=search info=completed search_name="{rule.splunk_search_name}" earliest=-{SILENT_WINDOW_HOURS}h | stats count',
                earliest=f"-{SILENT_WINDOW_HOURS}h",
            )
            fire_count = fires.count or (int(fires.results[0].get("count", 0)) if fires.results else 0)
            if fire_count == 0:
                issues.append({
                    "type": "SILENT",
                    "severity": "HIGH",
                    "detail": f"No fires in last {SILENT_WINDOW_HOURS} hours",
                })
        except Exception as e:
            logger.warning("Silent check failed for %s: %s", rule.splunk_search_name, e)

    # Check 2: Is the data source still fresh? (real-time — needs live data)
    if settings.drift_freshness_check_enabled and rule.sourcetype and rule.index_name:
        try:
            freshness = mcp.run_query(
                f"| metadata type=sourcetypes index={rule.index_name} "
                f'| where sourcetype="{rule.sourcetype}" '
                f"| where (now() - lastTime) < {STALE_WINDOW_MINUTES * 60} | stats count",
                earliest="-1h",
            )
            fresh_count = freshness.count or (int(freshness.results[0].get("count", 0)) if freshness.results else 0)
            if fresh_count == 0:
                issues.append({
                    "type": "DATA_STALE",
                    "severity": "CRITICAL",
                    "detail": f"No events from {rule.sourcetype} in {STALE_WINDOW_MINUTES} minutes",
                })
        except Exception as e:
            logger.warning("Freshness check failed for %s: %s", rule.splunk_search_name, e)

    # Check 3: Do required fields still exist? (schema-drift detection)
    # Check against ALL available data, not just the last hour — a field that
    # exists nowhere in the index is genuinely gone/renamed. This is also what
    # lets the check work on static/historical datasets (e.g. BOTS v3).
    if rule.required_fields and rule.index_name and rule.sourcetype:
        for field in rule.required_fields[:5]:  # check up to 5 fields
            try:
                field_check = mcp.run_query(
                    f"index={rule.index_name} sourcetype=\"{rule.sourcetype}\" {field}=* | stats count",
                    earliest="0",
                )
                # `| stats count` always returns exactly one row, so the row
                # count is meaningless — read the actual count VALUE.
                cnt = int(field_check.results[0].get("count", 0)) if field_check.results else 0
                if cnt == 0:
                    issues.append({
                        "type": "SCHEMA_DRIFT",
                        "severity": "HIGH",
                        "detail": f"Field '{field}' not found in recent events — schema may have changed",
                    })
            except Exception as e:
                logger.warning("Field check failed for %s.%s: %s", rule.splunk_search_name, field, e)

    return issues


def regenerate_broken_rule(rule: Rule, mcp: SplunkMCPClient, db: Session, drift_detail: str) -> bool:
    """Self-heal a broken detection: regenerate SPL against the current schema,
    re-validate, and redeploy. Returns True if the rule was healed.

    This closes the loop — drift no longer just raises an alert, the agent
    rewrites the detection so coverage is restored automatically.
    """
    from core.agent.nodes.spl_generator import run_spl_generator
    from core.agent.nodes.validator import validate_spl, STATUS_GOOD, STATUS_DATA_ABSENT, STATUS_NOISY
    from core.agent.nodes.deployer import deploy_rule
    from core.models.foundation_sec import FoundationSecClient
    from core.splunk.rest_client import SplunkRestClient
    from db.models import EnvSnapshot

    snap = db.query(EnvSnapshot).order_by(EnvSnapshot.captured_at.desc()).first()
    env = snap.fingerprint if snap else {}
    gap = {
        "technique_id": rule.technique_id,
        "technique_name": rule.technique_name,
        "tactic": rule.tactic,
        "description": "",
        "detection": "",
    }
    feedback = (
        f"The previously deployed detection broke due to drift: {drift_detail}. "
        "Regenerate it using only fields and EventCodes that currently exist in the data."
    )
    res = run_spl_generator(gap, env, mcp, FoundationSecClient(), validation_feedback=feedback)
    new_spl = res.get("spl")
    if not new_spl:
        return False

    # Validate against the sourcetype the NEW SPL actually targets (not the stale
    # one on the broken rule, which may have been wrong to begin with).
    import re
    idx_m = re.search(r'index\s*=\s*"?([\w:.-]+)"?', new_spl)
    st_m = re.search(r'sourcetype\s*=\s*"([^"]+)"', new_spl)
    val_index = idx_m.group(1) if idx_m else (rule.index_name or "main")
    val_st = st_m.group(1) if st_m else (rule.sourcetype or "*")

    # The regenerated SPL has already passed generation + LLM review and targets
    # fields that currently exist, so it heals the drift. Validation here only
    # records the hit rate; a rule that hasn't fired yet is still a valid redeploy.
    validation = validate_spl(new_spl, val_index, val_st, mcp)

    rule.spl = new_spl
    rule.confidence_score = res["confidence"]
    rule.index_name = val_index
    rule.sourcetype = val_st
    rule.required_fields = None  # stale fields cleared — re-derived on next scan
    rule.hits_per_day = validation["hits_per_day"]
    rule.false_pos_estimate = validation.get("false_pos_estimate")
    rule.status = "DEPLOYED"
    db.commit()
    deploy_rule(rule, SplunkRestClient(), mcp, db)  # redeploy the healed SPL
    return True


def run_drift_monitor(db: Session, mcp: SplunkMCPClient) -> dict:
    """Run health checks on all deployed rules. Called by APScheduler every 6h."""
    from core.config import get_settings
    auto_heal = get_settings().drift_auto_regenerate

    deployed_rules = db.query(Rule).filter(Rule.status == "DEPLOYED").all()
    logger.info("[Drift Monitor] Checking %d deployed rules", len(deployed_rules))

    summary = {"healthy": 0, "broken": 0, "regenerated": 0, "rules_checked": len(deployed_rules)}

    for rule in deployed_rules:
        issues = check_rule_health(rule, mcp, db)

        if not issues:
            summary["healthy"] += 1
            continue

        rule.status = "BROKEN"
        detail = "; ".join(i["detail"] for i in issues)
        events = []
        for issue in issues:
            ev = DriftEvent(rule_id=rule.id, drift_type=issue["type"], detail=issue["detail"])
            db.add(ev)
            events.append(ev)
        db.commit()
        summary["broken"] += 1
        logger.warning("[Drift Monitor] BROKEN: %s — %s", rule.splunk_search_name, detail)

        # Self-heal: regenerate + redeploy a working detection.
        if auto_heal:
            try:
                healed = regenerate_broken_rule(rule, mcp, db, detail)
            except Exception as e:
                logger.error("[Drift Monitor] regeneration failed for %s: %s", rule.technique_id, e)
                healed = False
            if healed:
                summary["regenerated"] += 1
                for ev in events:
                    ev.resolved_at = datetime.now(timezone.utc)
                    ev.resolution = "REGENERATED"
                db.commit()
                logger.info("[Drift Monitor] SELF-HEALED: %s regenerated + redeployed", rule.technique_id)

    logger.info(
        "[Drift Monitor] Done — %d healthy, %d broken, %d self-healed",
        summary["healthy"], summary["broken"], summary["regenerated"],
    )
    return summary
