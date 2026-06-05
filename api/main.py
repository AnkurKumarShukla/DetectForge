"""FastAPI application entrypoint."""
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from api.routers import attack_path, coverage, gaps, genealogy, nl_query, review, rules, scans
from db.database import init_db
from scheduler.scheduler import start_scheduler, stop_scheduler

STATIC_DIR = Path(__file__).parent / "static"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("DetectForge API starting up")
    init_db()
    start_scheduler()
    yield
    stop_scheduler()
    logger.info("DetectForge API shut down")


app = FastAPI(
    title="DetectForge",
    description="Autonomous Detection Engineering Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router, prefix="/api/v1")
app.include_router(rules.router, prefix="/api/v1")
app.include_router(coverage.router, prefix="/api/v1")
app.include_router(review.router, prefix="/api/v1")
app.include_router(gaps.router, prefix="/api/v1")
app.include_router(nl_query.router, prefix="/api/v1")
app.include_router(attack_path.router, prefix="/api/v1")
app.include_router(genealogy.router, prefix="/api/v1")


@app.get("/")
def control_panel():
    """Human-in-the-loop control panel — the live demo surface."""
    return FileResponse(STATIC_DIR / "control.html")


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "detectforge"}
