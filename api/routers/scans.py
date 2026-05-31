"""POST /scan — trigger a full DetectForge pipeline run."""
import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.agent.orchestrator import DetectForgeOrchestrator
from db.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scans"])

# In-memory scan status (replace with DB in production)
_scan_status: dict[str, dict] = {}


class ScanRequest(BaseModel):
    industry: str = "healthcare"
    max_gaps: int = 20


def _run_scan_background(scan_id: str, industry: str, max_gaps: int, db: Session):
    _scan_status[scan_id] = {"status": "running", "scan_id": scan_id}
    try:
        orchestrator = DetectForgeOrchestrator(db)
        result = orchestrator.run(industry=industry, max_gaps=max_gaps)
        _scan_status[scan_id] = {"status": "complete", **result}
    except Exception as e:
        logger.error("Scan %s failed: %s", scan_id, e)
        _scan_status[scan_id] = {"status": "error", "error": str(e), "scan_id": scan_id}
    finally:
        db.close()


@router.post("/scan")
def start_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[Session, Depends(get_db)],
):
    scan_id = str(uuid.uuid4())
    _scan_status[scan_id] = {"status": "queued", "scan_id": scan_id}
    background_tasks.add_task(
        _run_scan_background, scan_id, body.industry, body.max_gaps, db
    )
    return {"scan_id": scan_id, "status": "queued"}


@router.get("/scan/{scan_id}/status")
def get_scan_status(scan_id: str):
    status = _scan_status.get(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")
    return status
