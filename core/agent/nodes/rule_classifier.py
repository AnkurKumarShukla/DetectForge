"""Phase 2a — Rule Classifier: maps existing Splunk rules to MITRE ATT&CK via Foundation-sec."""
import logging

from sqlalchemy.orm import Session

from core.models.foundation_sec import FoundationSecClient
from db.models import RuleClassification

logger = logging.getLogger(__name__)


def run_rule_classifier(state: dict, db: Session, foundation_sec: FoundationSecClient) -> dict:
    existing_rules: list[dict] = state.get("existing_rules", [])
    scan_id = state["scan_id"]
    logger.info("[Phase 2a] Rule Classifier — classifying %d existing rules", len(existing_rules))

    coverage_map: dict[str, dict] = {}  # technique_id → {covered, confidence, rule_name, quality}

    for rule in existing_rules:
        name = rule.get("name", "")
        spl = rule.get("spl", "")
        if not spl.strip():
            continue

        try:
            result = foundation_sec.classify_rule(name=name, spl=spl)
        except Exception as e:
            logger.warning("Classification failed for '%s': %s", name, e)
            continue

        technique_id = result.get("technique_id")
        confidence = result.get("confidence", 0.0)

        if technique_id:
            # Store in coverage map (keep highest confidence if duplicate)
            existing = coverage_map.get(technique_id, {})
            if confidence >= existing.get("confidence", 0.0):
                coverage_map[technique_id] = {
                    "covered": True,
                    "confidence": confidence,
                    "rule_name": name,
                    "coverage_quality": result.get("coverage_quality", "unknown"),
                    "coverage_gaps": result.get("coverage_gaps", ""),
                    "tactic": result.get("tactic", ""),
                }

        # Persist classification
        classification = RuleClassification(
            scan_id=scan_id,
            search_name=name,
            spl=spl,
            technique_id=technique_id,
            technique_name=result.get("technique_name"),
            tactic=result.get("tactic"),
            confidence=confidence,
            reasoning=result.get("reasoning"),
            coverage_quality=result.get("coverage_quality"),
            coverage_gaps=result.get("coverage_gaps"),
        )
        db.add(classification)

    db.commit()
    logger.info("[Phase 2a] Coverage map built — %d techniques covered", len(coverage_map))

    return {
        **state,
        "coverage_map": coverage_map,
        "phase": "rule_classifier_complete",
    }
