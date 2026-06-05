"""Phase 5 — Deployer: deploys approved rules to Splunk via REST API."""
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy.orm import Session

from core.splunk.mcp_client import SplunkMCPClient
from core.splunk.rest_client import SplunkRestClient
from db.models import Gap, Rule

logger = logging.getLogger(__name__)

SEARCH_NAME_PREFIX = "DetectForge"


def deploy_rule(rule: Rule, rest: SplunkRestClient, mcp: SplunkMCPClient, db: Session) -> bool:
    """Deploy a rule to Splunk and update DB status. Returns True on success."""
    search_name = f"{SEARCH_NAME_PREFIX} - {rule.technique_id} - {rule.technique_name}"

    # Generate plain English explanation
    try:
        explanation = mcp.explain_spl(rule.spl)
        rule.spl_explanation = explanation
    except Exception as e:
        logger.warning("saia_explain_spl failed for %s: %s", rule.technique_id, e)

    try:
        rest.create_saved_search(
            name=search_name,
            spl=rule.spl,
            description=rule.spl_explanation or "",
            technique_id=rule.technique_id,
            tactic=rule.tactic,
            severity=_severity_from_tactic(rule.tactic),
            industry=rule.industry,
        )
    except httpx.HTTPStatusError as e:
        # Already deployed (same search name) — update it instead of failing.
        if e.response.status_code == 409:
            try:
                rest.update_saved_search(search_name, rule.spl)
                logger.info("Updated existing saved search: %s", search_name)
            except Exception as e2:
                logger.error("Update after 409 failed for %s: %s", rule.technique_id, e2)
                return False
        else:
            logger.error("Deployment failed for %s: %s", rule.technique_id, e)
            return False
    except Exception as e:
        logger.error("Deployment failed for %s: %s", rule.technique_id, e)
        return False

    rule.splunk_search_name = search_name
    rule.status = "DEPLOYED"
    rule.deployed_at = datetime.now(timezone.utc)

    # Close the corresponding gap
    if rule.gap_id:
        gap = db.get(Gap, rule.gap_id)
        if gap:
            gap.status = "CLOSED"
            gap.closed_at = datetime.now(timezone.utc)

    db.commit()
    logger.info("Deployed: %s", search_name)
    return True


def _severity_from_tactic(tactic: str) -> str:
    high_severity_tactics = {
        "credential-access", "credential access",
        "lateral-movement", "lateral movement",
        "impact", "exfiltration",
        "defense-evasion", "defense evasion",
        "privilege-escalation", "privilege escalation",
    }
    tactic_lower = tactic.lower()
    if tactic_lower in high_severity_tactics:
        return "high"
    if tactic_lower in ("execution", "persistence", "collection"):
        return "medium"
    return "low"
