"""Phase 1 — Environment Scanner: fingerprints the live Splunk environment."""
import hashlib
import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from core.splunk.mcp_client import SplunkMCPClient
from db.models import EnvSnapshot

logger = logging.getLogger(__name__)

# Only deeply inspect these security-relevant sourcetypes — skip everything else
SECURITY_SOURCETYPES = {
    "wineventlog:security", "xmlwineventlog:security",
    "xmlwineventlog:microsoft-windows-sysmon/operational",
    "wineventlog:system", "wineventlog:application",
    "xmlwineventlog:microsoft-windows-powershell/operational",
    "syslog", "linux:audit", "linux:syslog",
    "aws:cloudtrail", "aws:cloudwatchlogs", "aws:cloudwatchlogs:vpcflow",
    "cisco:asa", "cisco:firepower", "palo:traffic", "palo:threat",
    "stream:http", "stream:dns", "stream:tcp", "stream:ip",
    "osquery:results", "zeek:conn", "bro:conn",
    "crowdstrike:events", "carbon_black:events",
    "symantec:ep:packet:file", "symantec:ep:traffic:file",
}


def run_env_scanner(state: dict, db: Session, mcp: SplunkMCPClient) -> dict:
    logger.info("[Phase 1] Environment Scanner starting — scan_id=%s", state["scan_id"])

    fingerprint: dict = {
        "scan_id": state["scan_id"],
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "splunk_version": "",
        "indexes": {},
        "existing_rules": [],
    }

    # Splunk version — one call
    try:
        info = mcp.get_splunk_info()
        results = info.get("results", [{}])
        fingerprint["splunk_version"] = results[0].get("version", "unknown") if results else "unknown"
    except Exception as e:
        logger.warning("Could not get Splunk info: %s", e)

    # Index inventory — get all indexes, then get sourcetypes per index in one batch
    try:
        indexes = mcp.get_indexes()
        for idx in indexes:
            if idx.name.startswith("_"):
                continue

            # Single query to get ALL sourcetypes for this index
            sourcetypes_raw = mcp.get_sourcetypes_for_index(idx.name)
            sourcetype_details: dict = {}

            for st in sourcetypes_raw:
                st_lower = st.lower()
                if st_lower in SECURITY_SOURCETYPES:
                    # Deep inspect: get fields (one MCP call)
                    fields = mcp.get_fields_for_sourcetype(st, idx.name)
                    sourcetype_details[st] = {"fields": fields[:50], "security_relevant": True}
                else:
                    # Shallow: just record it exists, no extra MCP call
                    sourcetype_details[st] = {"fields": [], "security_relevant": False}

            fingerprint["indexes"][idx.name] = {
                "sourcetypes": sourcetype_details,
                "total_event_count": idx.total_event_count,
                "current_size_mb": idx.current_size_mb,
            }

        logger.info("Scanned %d indexes, %d total sourcetypes",
                    len(fingerprint["indexes"]),
                    sum(len(v["sourcetypes"]) for v in fingerprint["indexes"].values()))
    except Exception as e:
        logger.error("Index scan failed: %s", e)
        state.setdefault("errors", []).append(f"env_scanner index scan: {e}")

    # Existing saved searches — one call
    try:
        kos = mcp.discover_knowledge_objects()
        fingerprint["existing_rules"] = [
            {"name": ko.name, "spl": ko.spl, "enabled": ko.enabled, "description": ko.description}
            for ko in kos if ko.spl
        ]
        logger.info("Found %d existing saved searches", len(fingerprint["existing_rules"]))
    except Exception as e:
        logger.error("KO discovery failed: %s", e)
        state.setdefault("errors", []).append(f"env_scanner ko discovery: {e}")

    schema_hash = hashlib.md5(json.dumps(fingerprint, sort_keys=True).encode()).hexdigest()
    fingerprint["schema_hash"] = schema_hash

    snapshot = EnvSnapshot(scan_id=state["scan_id"], fingerprint=fingerprint, schema_hash=schema_hash)
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
