"""Daily sync of CISA Known Exploited Vulnerabilities (KEV) catalog."""
import json
import logging
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = Path(__file__).parent.parent.parent / "knowledge" / "cisa_kev.json"


def sync_cisa_kev() -> dict:
    """Download latest CISA KEV catalog and cache it locally."""
    logger.info("Syncing CISA KEV catalog...")
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(CISA_KEV_URL)
        resp.raise_for_status()
        data = resp.json()

        KEV_CACHE.parent.mkdir(parents=True, exist_ok=True)
        KEV_CACHE.write_bytes(resp.content)

        vuln_count = len(data.get("vulnerabilities", []))
        logger.info("CISA KEV synced: %d vulnerabilities", vuln_count)
        return {"status": "ok", "vulnerabilities": vuln_count}
    except Exception as e:
        logger.error("CISA KEV sync failed: %s", e)
        return {"status": "error", "error": str(e)}


def load_kev_cve_ids() -> set[str]:
    """Load CVE IDs from cached KEV data."""
    if not KEV_CACHE.exists():
        return set()
    data = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
    return {v["cveID"] for v in data.get("vulnerabilities", [])}
