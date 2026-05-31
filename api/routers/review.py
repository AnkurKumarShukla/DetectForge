"""Review queue API endpoints."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.splunk.mcp_client import SplunkMCPClient
from core.splunk.rest_client import SplunkRestClient
from db.database import get_db
from features.review_queue.queue_manager import (
    approve_rule,
    edit_and_revalidate,
    get_pending_queue,
    reject_rule,
)

router = APIRouter(tags=["review"])


class ApproveRequest(BaseModel):
    reviewer: str = "analyst"


class RejectRequest(BaseModel):
    reviewer: str = "analyst"
    reason: str = ""


class EditRequest(BaseModel):
    new_spl: str
    reviewer: str = "analyst"


@router.get("/review/queue")
def list_queue(db: Annotated[Session, Depends(get_db)]):
    return get_pending_queue(db)


@router.post("/review/{queue_id}/approve")
def approve(queue_id: str, body: ApproveRequest, db: Annotated[Session, Depends(get_db)]):
    mcp = SplunkMCPClient()
    rest = SplunkRestClient()
    success = approve_rule(queue_id, body.reviewer, db, mcp, rest)
    if not success:
        raise HTTPException(status_code=400, detail="Approval failed or entry not found")
    return {"status": "approved", "queue_id": queue_id}


@router.post("/review/{queue_id}/reject")
def reject(queue_id: str, body: RejectRequest, db: Annotated[Session, Depends(get_db)]):
    success = reject_rule(queue_id, body.reviewer, body.reason, db)
    if not success:
        raise HTTPException(status_code=400, detail="Rejection failed or entry not found")
    return {"status": "rejected", "queue_id": queue_id}


@router.post("/review/{queue_id}/edit")
def edit(queue_id: str, body: EditRequest, db: Annotated[Session, Depends(get_db)]):
    mcp = SplunkMCPClient()
    rest = SplunkRestClient()
    result = edit_and_revalidate(queue_id, body.new_spl, body.reviewer, db, mcp, rest)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result
