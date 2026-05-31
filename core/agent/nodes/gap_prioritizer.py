"""Phase 2b — Gap Prioritizer: scores and ranks detection gaps by financial exposure."""
import logging

from sqlalchemy.orm import Session

from core.intelligence.attack_loader import get_attack_loader
from core.intelligence.threat_intel import (
    calculate_annual_exposure,
    calculate_priority_score,
)
from db.models import Gap

logger = logging.getLogger(__name__)

# Data availability score constants
DATA_AVAILABLE_SCORE = 1.0
DATA_PARTIAL_SCORE = 0.4
DATA_MISSING_SCORE = 0.0


def run_gap_prioritizer(state: dict, db: Session) -> dict:
    coverage_map: dict = state.get("coverage_map", {})
    env_fingerprint: dict = state.get("env_fingerprint", {})
    industry = state.get("industry", "healthcare")
    scan_id = state["scan_id"]

    loader = get_attack_loader()
    all_techniques = loader.get_all_techniques()

    available_sourcetypes = _get_available_sourcetypes(env_fingerprint)

    gaps = []
    covered_count = len(coverage_map)
    total_count = len(all_techniques)

    for technique in all_techniques:
        if technique.id in coverage_map:
            continue  # already covered

        # Estimate data availability for scoring
        data_score = _estimate_data_availability(technique, available_sourcetypes)

        priority = calculate_priority_score(technique.id, industry, data_score)
        exposure = calculate_annual_exposure(technique.id, industry)
        tactic = technique.tactics[0] if technique.tactics else "unknown"

        gaps.append({
            "technique_id": technique.id,
            "technique_name": technique.name,
            "tactic": tactic,
            "priority_score": round(priority, 4),
            "financial_exposure_usd": exposure,
            "data_score": data_score,
            "data_sources": technique.data_sources,
            "description": technique.description[:500],
            "detection": technique.detection[:500],
        })

    gaps.sort(key=lambda g: g["priority_score"], reverse=True)

    # Persist top gaps to DB
    for gap_data in gaps[:100]:
        gap = Gap(
            scan_id=scan_id,
            technique_id=gap_data["technique_id"],
            technique_name=gap_data["technique_name"],
            tactic=gap_data["tactic"],
            industry=industry,
            priority_score=gap_data["priority_score"],
            financial_exposure_usd=gap_data["financial_exposure_usd"],
            status="CLOSABLE" if gap_data["data_score"] >= DATA_AVAILABLE_SCORE else (
                "DATA_PARTIAL" if gap_data["data_score"] > DATA_MISSING_SCORE else "DATA_GAP"
            ),
        )
        db.add(gap)
    db.commit()

    total_exposure = sum(g["financial_exposure_usd"] for g in gaps)
    coverage_pct = round(covered_count / total_count * 100, 1) if total_count else 0.0

    # Only include CLOSABLE gaps in the generation queue
    closable = [g for g in gaps if g["data_score"] >= DATA_AVAILABLE_SCORE]

    logger.info(
        "[Phase 2b] %d gaps found — %d closable — coverage %.1f%% — total exposure $%.0fM",
        len(gaps), len(closable), coverage_pct, total_exposure / 1_000_000,
    )

    return {
        **state,
        "all_gaps": gaps,
        "prioritized_gaps": closable,
        "coverage_before_pct": coverage_pct,
        "total_financial_exposure_usd": total_exposure,
        "current_gap_index": 0,
        "phase": "gap_prioritizer_complete",
    }


def _get_available_sourcetypes(env_fingerprint: dict) -> set[str]:
    sourcetypes: set[str] = set()
    for idx_data in env_fingerprint.get("indexes", {}).values():
        for st in idx_data.get("sourcetypes", {}).keys():
            sourcetypes.add(st.lower())
    return sourcetypes


def _estimate_data_availability(technique, available_sourcetypes: set[str]) -> float:
    """Rough heuristic: check if any known data source for this technique is present."""
    if not technique.data_sources:
        return DATA_PARTIAL_SCORE

    # Map ATT&CK data sources to common Splunk sourcetype patterns
    source_patterns = {
        "process": ["sysmon", "wineventlog", "crowdstrike", "carbon_black", "endpoint"],
        "network": ["zeek", "suricata", "bro", "firewall", "cisco", "palo_alto", "netflow"],
        "file": ["sysmon", "wineventlog", "carbon_black"],
        "authentication": ["wineventlog:security", "okta", "azure_ad", "auth"],
        "command": ["sysmon", "powershell", "wineventlog"],
        "registry": ["sysmon", "wineventlog"],
        "cloud": ["aws", "azure", "gcp", "cloudtrail", "office365"],
        "email": ["o365", "exchange", "proofpoint", "mimecast"],
    }

    for data_source in technique.data_sources:
        ds_lower = data_source.lower()
        for category, patterns in source_patterns.items():
            if category in ds_lower:
                if any(p in st for st in available_sourcetypes for p in patterns):
                    return DATA_AVAILABLE_SCORE

    return DATA_PARTIAL_SCORE
