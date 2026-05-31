"""Coverage timeline — tracks detection coverage % over time from DB."""
from sqlalchemy.orm import Session

from db.models import CoverageHistory, DriftEvent, Rule


def get_timeline(db: Session, industry: str | None = None, limit: int = 30) -> list[dict]:
    q = db.query(CoverageHistory)
    if industry:
        q = q.filter(CoverageHistory.industry_profile == industry)
    rows = q.order_by(CoverageHistory.measured_at.asc()).limit(limit).all()

    points = []
    for row in rows:
        broken = db.query(Rule).filter(
            Rule.scan_id == row.scan_id,
            Rule.status == "BROKEN"
        ).count()

        points.append({
            "measured_at": row.measured_at.isoformat() if row.measured_at else None,
            "coverage_pct": row.coverage_pct,
            "industry": row.industry_profile,
            "financial_exposure_usd": row.financial_exposure_usd,
            "rules_broken": broken,
            "scan_id": row.scan_id,
        })
    return points


def get_drift_summary(db: Session, days: int = 30) -> dict:
    from datetime import datetime, timezone, timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    events = db.query(DriftEvent).filter(DriftEvent.detected_at >= cutoff).all()

    by_type: dict[str, int] = {}
    for e in events:
        by_type[e.drift_type] = by_type.get(e.drift_type, 0) + 1

    resolved = sum(1 for e in events if e.resolved_at)
    return {
        "total_drift_events": len(events),
        "resolved": resolved,
        "unresolved": len(events) - resolved,
        "by_type": by_type,
        "period_days": days,
    }
