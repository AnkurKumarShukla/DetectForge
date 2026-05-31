"""Phase 1 — Environment Scanner: fingerprints the live Splunk environment."""
import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from core.splunk.mcp_client import SplunkMCPClient
from db.models import EnvSnapshot

logger = logging.getLogger(__name__)


def run_env_scanner(state: dict, db: Session, mcp: SplunkMCPClient) -> dict:
    logger.info("[Phase 1] Environment Scanner starting — scan_id=%s", state["scan_id"])

    fingerprint: dict = {
        "scan_id": state["scan_id"],
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "splunk_version": "",
        "indexes": {},
        "existing_rules": [],
        "missing_sourcetypes": [],
    }

    # Splunk version
    try:
        info = mcp.get_splunk_info()
        fingerprint["splunk_version"] = info.get("version", "unknown")
    except Exception as e:
        logger.warning("Could not get Splunk info: %s", e)

    # Index inventory
    try:
        indexes = mcp.get_indexes()
        for idx in indexes:
            if idx.name.startswith("_"):
                continue
            sourcetypes = mcp.get_sourcetypes_for_index(idx.name)
            sourcetype_details: dict = {}
            for st in sourcetypes:
                fields = mcp.get_fields_for_sourcetype(st, idx.name)
                # Check freshness
                freshness = mcp.run_query(
                    f"index={idx.name} sourcetype=\"{st}\" | tail 1 | fields _time",
                    earliest="-30d",
                )
                last_event = None
                if freshness.results:
                    last_event = freshness.results[0].get("_time")

                sourcetype_details[st] = {
                    "fields": fields[:50],  # cap at 50 fields
                    "last_event_utc": last_event,
                }
            fingerprint["indexes"][idx.name] = {
                "sourcetypes": sourcetype_details,
                "total_event_count": idx.total_event_count,
                "current_size_mb": idx.current_size_mb,
            }
        logger.info("Scanned %d indexes", len(fingerprint["indexes"]))
    except Exception as e:
        logger.error("Index scan failed: %s", e)
        state.setdefault("errors", []).append(f"env_scanner index scan: {e}")

    # Existing saved searches
    try:
        kos = mcp.discover_knowledge_objects()
        rules = []
        for ko in kos:
            if ko.spl:
                rules.append({
                    "name": ko.name,
                    "spl": ko.spl,
                    "enabled": ko.enabled,
                    "description": ko.description,
                })
        fingerprint["existing_rules"] = rules
        logger.info("Found %d existing saved searches", len(rules))
    except Exception as e:
        logger.error("Knowledge object discovery failed: %s", e)
        state.setdefault("errors", []).append(f"env_scanner ko discovery: {e}")

    schema_hash = hashlib.md5(json.dumps(fingerprint, sort_keys=True).encode()).hexdigest()
    fingerprint["schema_hash"] = schema_hash

    # Persist to DB
    snapshot = EnvSnapshot(
        scan_id=state["scan_id"],
        fingerprint=fingerprint,
        schema_hash=schema_hash,
    )
    db.add(snapshot)
    db.commit()

    logger.info("[Phase 1] Complete — schema_hash=%s", schema_hash)
    return {
        **state,
        "env_fingerprint": fingerprint,
        "splunk_version": fingerprint["splunk_version"],
        "schema_hash": schema_hash,
        "existing_rules": fingerprint["existing_rules"],
        "phase": "env_scanner_complete",
    }
