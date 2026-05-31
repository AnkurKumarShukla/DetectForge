"""Auto-installs all DetectForge dashboards and KV Store collections into Splunk."""
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.config import get_settings

STUDIO_DIR = Path(__file__).parent / "splunk_studio"
APP = "search"

DASHBOARDS = [
    ("detectforge_coverage_heatmap",  "coverage_heatmap.json"),
    ("detectforge_attack_paths",       "attack_paths.json"),
    ("detectforge_financial_risk",     "financial_risk.json"),
    ("detectforge_rule_health",        "rule_health.json"),
]

KV_COLLECTIONS = [
    "detectforge_gaps",
    "detectforge_rules",
    "detectforge_coverage",
    "detectforge_drift_events",
    "detectforge_actor_chains",
]


def setup(splunk_url: str, auth: tuple):
    print("Setting up DetectForge dashboards in Splunk...")

    # 1. Create KV Store collections
    for collection in KV_COLLECTIONS:
        url = f"{splunk_url}/servicesNS/nobody/{APP}/storage/collections/config"
        r = httpx.post(url, data={"name": collection, "output_mode": "json"}, auth=auth, verify=False)
        if r.status_code in (200, 201, 409):
            status = "OK" if r.status_code != 409 else "already exists"
            print(f"  KV collection {collection}: {status}")
        else:
            print(f"  KV collection {collection}: FAILED ({r.status_code}) {r.text[:100]}")

    # 2. Install Dashboard Studio dashboards
    for name, filename in DASHBOARDS:
        path = STUDIO_DIR / filename
        if not path.exists():
            print(f"  Dashboard {filename}: file not found, skipping")
            continue

        definition = json.loads(path.read_text(encoding="utf-8"))

        dashboard_xml = f"""<dashboard version="2" theme="dark">
  <definition><![CDATA[{json.dumps(definition)}]]></definition>
</dashboard>"""

        # Check if dashboard exists
        url = f"{splunk_url}/servicesNS/nobody/{APP}/data/ui/views/{name}"
        r = httpx.get(url, params={"output_mode": "json"}, auth=auth, verify=False)

        if r.status_code == 200:
            # Update existing
            r2 = httpx.post(url, data={"eai:data": dashboard_xml, "output_mode": "json"}, auth=auth, verify=False)
            action = "updated"
        else:
            # Create new
            create_url = f"{splunk_url}/servicesNS/nobody/{APP}/data/ui/views"
            r2 = httpx.post(create_url, data={
                "name": name,
                "eai:data": dashboard_xml,
                "output_mode": "json",
            }, auth=auth, verify=False)
            action = "created"

        if r2.status_code in (200, 201):
            print(f"  Dashboard {name}: {action}")
        else:
            print(f"  Dashboard {name}: FAILED ({r2.status_code}) {r2.text[:150]}")

    print("\nDone. Open Splunk → Dashboards to see DetectForge panels.")
    print("Note: Dashboards use KV Store lookups — run a scan first to populate data.")


def push_scan_results_to_kv(scan_summary: dict, db_session):
    """After each scan, push results to KV Store so dashboards stay live."""
    settings = get_settings()
    auth = (settings.splunk_username, settings.splunk_password)
    base = settings.splunk_url

    from db.models import Gap, Rule, CoverageHistory, DriftEvent
    db = db_session

    # Push gaps
    gaps = db.query(Gap).filter(Gap.scan_id == scan_summary["scan_id"]).all()
    gap_records = [
        {
            "technique_id": g.technique_id, "technique_name": g.technique_name,
            "tactic": g.tactic, "status": g.status, "industry": g.industry,
            "financial_exposure_usd": g.financial_exposure_usd or 0,
            "priority_score": g.priority_score,
        }
        for g in gaps
    ]
    _batch_upsert(base, auth, "detectforge_gaps", gap_records, key="technique_id")

    # Push rules
    rules = db.query(Rule).filter(Rule.scan_id == scan_summary["scan_id"]).all()
    rule_records = [
        {
            "technique_id": r.technique_id, "technique_name": r.technique_name,
            "tactic": r.tactic, "status": r.status, "industry": r.industry,
            "hits_per_day": r.hits_per_day or 0,
            "false_pos_estimate": r.false_pos_estimate or "",
            "tuning_rounds": r.tuning_rounds,
            "splunk_search_name": r.splunk_search_name or "",
            "deployed_at": r.deployed_at.isoformat() if r.deployed_at else "",
        }
        for r in rules
    ]
    _batch_upsert(base, auth, "detectforge_rules", rule_records, key="technique_id")

    # Push coverage summary
    cov_record = [{
        "scan_id": scan_summary["scan_id"],
        "coverage_pct": scan_summary.get("coverage_after_pct", 0),
        "financial_exposure_usd": scan_summary.get("total_financial_exposure_usd", 0),
        "industry": scan_summary.get("industry", ""),
        "measured_at": scan_summary.get("started_at", ""),
    }]
    _batch_upsert(base, auth, "detectforge_coverage", cov_record, key="scan_id")

    print(f"Pushed {len(gap_records)} gaps, {len(rule_records)} rules to KV Store")


def _batch_upsert(base: str, auth: tuple, collection: str, records: list, key: str):
    if not records:
        return
    url = f"{base}/servicesNS/nobody/search/storage/collections/data/{collection}/batch_save"
    r = httpx.post(url, json=records, auth=auth, verify=False, timeout=30)
    if r.status_code not in (200, 201):
        print(f"  KV upsert {collection}: {r.status_code} {r.text[:100]}")


if __name__ == "__main__":
    settings = get_settings()
    setup(settings.splunk_url, (settings.splunk_username, settings.splunk_password))
