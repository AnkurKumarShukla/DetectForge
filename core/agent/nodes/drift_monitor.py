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
    issues: list[dict] = []

    if not rule.splunk_search_name or rule.status != "DEPLOYED":
        return issues

    # Check 1: Has the rule fired in the last 72 hours?
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

    # Check 2: Is the data source still fresh?
    if rule.sourcetype and rule.index_name:
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

    # Check 3: Do required fields still exist?
    if rule.required_fields and rule.index_name and rule.sourcetype:
        for field in rule.required_fields[:5]:  # check up to 5 fields
            try:
                field_check = mcp.run_query(
                    f"index={rule.index_name} sourcetype=\"{rule.sourcetype}\" {field}=* | head 1 | stats count",
                    earliest="-1h",
                )
                exists = field_check.count > 0 or (int(field_check.results[0].get("count", 0)) > 0 if field_check.results else False)
                if not exists:
                    issues.append({
                        "type": "SCHEMA_DRIFT",
                        "severity": "HIGH",
                        "detail": f"Field '{field}' not found in recent events — schema may have changed",
                    })
            except Exception as e:
                logger.warning("Field check failed for %s.%s: %s", rule.splunk_search_name, field, e)

    return issues


def run_drift_monitor(db: Session, mcp: SplunkMCPClient) -> dict:
    """Run health checks on all deployed rules. Called by APScheduler every 6h."""
    deployed_rules = db.query(Rule).filter(Rule.status == "DEPLOYED").all()
    logger.info("[Drift Monitor] Checking %d deployed rules", len(deployed_rules))

    summary = {"healthy": 0, "broken": 0, "rules_checked": len(deployed_rules)}

    for rule in deployed_rules:
        issues = check_rule_health(rule, mcp, db)

        if issues:
            rule.status = "BROKEN"
            for issue in issues:
                drift_event = DriftEvent(
                    rule_id=rule.id,
                    drift_type=issue["type"],
                    detail=issue["detail"],
                )
                db.add(drift_event)
            db.commit()
            summary["broken"] += 1
            logger.warning(
                "[Drift Monitor] BROKEN: %s — %s",
                rule.splunk_search_name,
                "; ".join(i["detail"] for i in issues),
            )
        else:
            summary["healthy"] += 1

    logger.info(
        "[Drift Monitor] Done — %d healthy, %d broken",
        summary["healthy"], summary["broken"],
    )
    return summary
