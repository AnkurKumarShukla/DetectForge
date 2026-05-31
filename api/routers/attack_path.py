"""Attack path graph and kill chain endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from core.intelligence.attack_loader import get_attack_loader
from core.intelligence.kill_chain_mapper import THREAT_ACTOR_CHAINS, score_all_actors
from core.config import get_settings
from db.database import get_db
from db.models import Gap, Rule, RuleClassification
from features.attack_path.graph_builder import build_attack_graph, to_api_dict

router = APIRouter(tags=["attack-path"])


@router.get("/attack-path")
def get_attack_path(
    db: Annotated[Session, Depends(get_db)],
    industry: str = Query(None),
):
    settings = get_settings()
    industry = industry or settings.industry_profile

    coverage_map = _load_coverage_map(db)
    broken_techniques = _load_broken_techniques(db)
    gaps = _load_gaps(db, industry)
    loader = get_attack_loader()

    graph = build_attack_graph(industry, coverage_map, broken_techniques, gaps, loader)
    return to_api_dict(graph)


@router.get("/attack-path/actors")
def list_actors(industry: str = Query(None)):
    settings = get_settings()
    industry = industry or settings.industry_profile
    actors = list(THREAT_ACTOR_CHAINS.get(industry, {}).keys())
    return {"industry": industry, "actors": actors}


@router.get("/attack-path/actor/{actor_name}")
def get_actor_chain(
    actor_name: str,
    db: Annotated[Session, Depends(get_db)],
    industry: str = Query(None),
):
    settings = get_settings()
    industry = industry or settings.industry_profile

    coverage_map = _load_coverage_map(db)
    broken_techniques = _load_broken_techniques(db)
    loader = get_attack_loader()

    from core.intelligence.kill_chain_mapper import score_actor_chain
    result = score_actor_chain(actor_name, industry, coverage_map, broken_techniques, loader)

    return {
        "actor": result.actor,
        "industry": result.industry,
        "coverage_pct": result.coverage_pct,
        "covered": result.covered_count,
        "total_steps": result.total_steps,
        "longest_blind_window": result.longest_blind_window,
        "min_viable_detection": result.min_viable_detection,
        "critical_path": result.critical_path,
        "chain": [
            {
                "step": s.step,
                "technique_id": s.technique_id,
                "technique_name": s.technique_name,
                "tactic": s.tactic,
                "status": s.status,
            }
            for s in result.chain
        ],
    }


@router.post("/drift-monitor/trigger")
def trigger_drift_monitor():
    """Manually trigger the drift monitor — useful for demo."""
    from scheduler.scheduler import trigger_drift_monitor_now
    result = trigger_drift_monitor_now()
    return result


def _load_coverage_map(db: Session) -> dict:
    rows = db.query(RuleClassification).filter(RuleClassification.technique_id.isnot(None)).all()
    return {r.technique_id: {"rule_name": r.search_name, "confidence": r.confidence} for r in rows}


def _load_broken_techniques(db: Session) -> set[str]:
    rules = db.query(Rule).filter(Rule.status == "BROKEN").all()
    return {r.technique_id for r in rules}


def _load_gaps(db: Session, industry: str) -> list[dict]:
    gaps = db.query(Gap).filter(Gap.industry == industry).all()
    return [
        {
            "technique_id": g.technique_id,
            "financial_exposure_usd": g.financial_exposure_usd or 0,
            "status": g.status,
        }
        for g in gaps
    ]
