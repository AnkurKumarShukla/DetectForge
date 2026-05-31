"""APScheduler setup — registers all background jobs."""
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from core.config import get_settings

logger = logging.getLogger(__name__)
_scheduler: BackgroundScheduler | None = None


def start_scheduler() -> None:
    global _scheduler
    settings = get_settings()
    _scheduler = BackgroundScheduler(timezone="UTC")

    _scheduler.add_job(
        _run_drift_monitor,
        trigger=IntervalTrigger(hours=settings.drift_monitor_interval_hours),
        id="drift_monitor",
        name="Drift Monitor",
        replace_existing=True,
    )

    _scheduler.add_job(
        _run_threat_intel_sync,
        trigger=IntervalTrigger(hours=24),
        id="threat_intel_sync",
        name="Threat Intel Sync",
        replace_existing=True,
    )

    _scheduler.start()
    logger.info("Scheduler started — drift monitor every %dh", settings.drift_monitor_interval_hours)


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")


def trigger_drift_monitor_now() -> dict:
    """Manually trigger the drift monitor — useful for demo."""
    return _run_drift_monitor()


def _run_drift_monitor() -> dict:
    from core.agent.nodes.drift_monitor import run_drift_monitor
    from core.splunk.mcp_client import SplunkMCPClient
    from db.database import get_session_factory

    factory = get_session_factory()
    db = factory()
    try:
        mcp = SplunkMCPClient()
        return run_drift_monitor(db, mcp)
    except Exception as e:
        logger.error("Drift monitor job failed: %s", e)
        return {"error": str(e)}
    finally:
        db.close()


def _run_threat_intel_sync() -> None:
    """Daily refresh of CISA KEV data."""
    try:
        from scheduler.jobs.threat_intel_sync import sync_cisa_kev
        sync_cisa_kev()
    except Exception as e:
        logger.error("Threat intel sync failed: %s", e)
