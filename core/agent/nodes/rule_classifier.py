"""Phase 2a — Rule Classifier: maps existing Splunk rules to MITRE ATT&CK.

Detections that already carry an ATT&CK annotation (as mature SIEM content like
Splunk ESCU does) are read directly; un-annotated rules are inferred with
Foundation-sec. This mirrors real environments and keeps classification reliable
where ground truth exists.
"""
import logging
import re

from sqlalchemy.orm import Session

from core.models.foundation_sec import FoundationSecClient
from db.models import RuleClassification

logger = logging.getLogger(__name__)

# Matches explicit ATT&CK annotations carried in the detection (SPL header
# comment, name, or description), e.g. "ATTACK_TECHNIQUE=T1003.001" or
# "mitre_t1003_001". Mature SIEM content (Splunk ESCU) annotates detections this
# way, so DetectForge reads ground truth where it exists.
_ANNOTATION_RE = re.compile(
    r"(?:ATTACK_TECHNIQUE=|mitre[_\- ]?)t(\d{4})(?:[._](\d{3}))?", re.IGNORECASE
)
_TACTIC_RE = re.compile(r"(?:ATTACK_TACTIC=|tactic[_\- ])([a-z\-]+)", re.IGNORECASE)


def _extract_annotated_technique(rule: dict) -> dict | None:
    """Read an explicit ATT&CK annotation from a rule's SPL/name/description.

    Returns a classification dict (confidence 1.0, source=annotation) or None.
    """
    text = f"{rule.get('spl', '')} {rule.get('description', '')} {rule.get('name', '')}"
    m = _ANNOTATION_RE.search(text)
    if not m:
        return None
    tid = f"T{m.group(1)}.{m.group(2)}" if m.group(2) else f"T{m.group(1)}"
    tactic_m = _TACTIC_RE.search(text)
    return {
        "technique_id": tid,
        "technique_name": None,
        "tactic": tactic_m.group(1).replace("-", " ") if tactic_m else None,
        "confidence": 1.0,
        "reasoning": "Read from existing ATT&CK annotation on the detection",
        "coverage_quality": "high",
        "coverage_gaps": "",
    }

# Built-in Splunk apps whose saved searches are operational/health, not security
# detections — skip them so we don't waste LLM calls mapping ops searches to null.
_SYSTEM_APPS = {
    "splunk_instrumentation", "splunkdeploymentserverconfig",
    "splunk_monitoring_console", "audit_trail", "introspection_generator_addon",
    "learned", "splunk_archiver", "splunk_secure_gateway",
}


def _is_security_relevant(rule: dict) -> bool:
    """Heuristic: keep candidate detections, drop Splunk's own ops/health searches."""
    app = (rule.get("app") or rule.get("metadata", {}).get("app", "")).lower()
    if app in _SYSTEM_APPS:
        return False
    spl = (rule.get("spl") or "").strip()
    if not spl:
        return False
    # Searches that only query internal _indexes are platform telemetry, not detections.
    if "index=_" in spl and "index=" not in spl.replace("index=_", ""):
        return False
    return True


def run_rule_classifier(state: dict, db: Session, foundation_sec: FoundationSecClient) -> dict:
    all_existing: list[dict] = state.get("existing_rules", [])
    existing_rules = [r for r in all_existing if _is_security_relevant(r)]
    scan_id = state["scan_id"]
    logger.info(
        "[Phase 2a] Rule Classifier — %d/%d saved searches look security-relevant",
        len(existing_rules), len(all_existing),
    )

    coverage_map: dict[str, dict] = {}  # technique_id → {covered, confidence, rule_name, quality}

    for rule in existing_rules:
        name = rule.get("name", "")
        spl = rule.get("spl", "")
        if not spl.strip():
            continue

        annotated = _extract_annotated_technique(rule)
        if annotated:
            result = annotated
        else:
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
