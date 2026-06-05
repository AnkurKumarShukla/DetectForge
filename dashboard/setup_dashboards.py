"""Auto-installs DetectForge dashboards and publishes scan data to Splunk.

Data flow (reliable on single-instance Splunk Enterprise):
  DB rows -> CSV text (built in Python)
          -> | makeresults format=csv data="<csv>" | outputlookup <name>.csv

This uses Splunk's own engine to materialise CSV lookup files on the search
head. It deliberately avoids KV Store: on this instance KV collections surface
`stats count` but NOT row-level data to `| inputlookup` (rows come back empty),
which silently breaks every dashboard panel. makeresults+outputlookup builds
the rows on the search head, so they always land in the CSV the dashboards read.
"""
import csv
import io
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.config import get_settings

STUDIO_DIR = Path(__file__).parent / "splunk_studio"
APP = "search"

DASHBOARDS = [
    ("detectforge_coverage_heatmap", "coverage_heatmap.json"),
    ("detectforge_attack_paths",      "attack_paths.json"),
    ("detectforge_financial_risk",    "financial_risk.json"),
    ("detectforge_rule_health",       "rule_health.json"),
]

# (dataset key, csv lookup the dashboards inputlookup from)
DATASETS = [
    ("detectforge_gaps",         "detectforge_gaps.csv"),
    ("detectforge_rules",        "detectforge_rules.csv"),
    ("detectforge_coverage",     "detectforge_coverage.csv"),
    ("detectforge_drift_events", "detectforge_drift_events.csv"),
    ("detectforge_actor_chains", "detectforge_actor_chains.csv"),
    ("detectforge_tactic_coverage", "detectforge_tactic_coverage.csv"),
]


def setup(splunk_url: str, auth: tuple):
    print("Setting up DetectForge dashboards in Splunk...")
    _install_dashboards(splunk_url, auth)
    print("\nDone. Open Splunk > Dashboards to see DetectForge panels.")
    print("Run a scan (or push_scan_results_to_csv) to populate data.")


def _install_dashboards(splunk_url: str, auth: tuple):
    for name, filename in DASHBOARDS:
        path = STUDIO_DIR / filename
        if not path.exists():
            print(f"  Dashboard {filename}: file not found, skipping")
            continue

        definition = json.loads(path.read_text(encoding="utf-8"))
        dashboard_xml = (
            '<dashboard version="2" theme="dark">\n'
            f'  <definition><![CDATA[{json.dumps(definition)}]]></definition>\n'
            '</dashboard>'
        )

        url = f"{splunk_url}/servicesNS/nobody/{APP}/data/ui/views/{name}"
        exists = httpx.get(url, params={"output_mode": "json"}, auth=auth, verify=False).status_code == 200

        if exists:
            r = httpx.post(url, data={"eai:data": dashboard_xml, "output_mode": "json"}, auth=auth, verify=False)
            action = "updated"
        else:
            create_url = f"{splunk_url}/servicesNS/nobody/{APP}/data/ui/views"
            r = httpx.post(create_url, data={
                "name": name, "eai:data": dashboard_xml, "output_mode": "json",
            }, auth=auth, verify=False)
            action = "created"

        if r.status_code in (200, 201):
            print(f"  Dashboard {name}: {action}")
        else:
            print(f"  Dashboard {name}: FAILED ({r.status_code}) {r.text[:150]}")


# ── data publishing ────────────────────────────────────────────────────────

def _records_to_csv(records: list[dict]) -> str:
    """Serialize records to RFC4180 CSV text. Empty -> a single header-only row
    so the lookup still exists (dashboards show 'no results' rather than error)."""
    if not records:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(records[0].keys()), lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return buf.getvalue()


def _write_csv_lookup(splunk_url: str, auth: tuple, csv_name: str, records: list[dict]) -> int:
    """Materialise a CSV lookup via | makeresults format=csv | outputlookup.

    Builds the rows on the search head from literal CSV text, so it is immune to
    the KV-Store row-retrieval problem. Returns rows written.
    """
    csv_text = _records_to_csv(records)
    if not csv_text:
        print(f"  {csv_name}: no records, skipped")
        return 0

    # Escape for embedding inside SPL  data="..."  (backslash then quote order matters)
    escaped = csv_text.replace("\\", "\\\\").replace('"', '\\"')
    fields = list(records[0].keys())
    spl = (
        f'| makeresults format=csv data="{escaped}" '
        f'| table {" ".join(fields)} '
        f'| outputlookup {csv_name}'
    )

    url = f"{splunk_url}/servicesNS/nobody/{APP}/search/jobs"
    r = httpx.post(url, data={
        "search": spl,
        "exec_mode": "oneshot",
        "output_mode": "json",
    }, auth=auth, verify=False, timeout=60)
    if r.status_code not in (200, 201):
        print(f"  {csv_name}: FAILED ({r.status_code}) {r.text[:150]}")
        return 0
    try:
        body = r.json()
    except Exception:
        body = {}
    fatal = [m.get("text", "") for m in body.get("messages", []) if m.get("type") == "FATAL"]
    if fatal:
        print(f"  {csv_name}: FATAL {fatal[0][:150]}")
        return 0

    written = len(body.get("results", []))
    _set_global(splunk_url, auth, csv_name)
    return written


def _set_global(splunk_url: str, auth: tuple, csv_name: str):
    """Share the CSV lookup globally so dashboards (run as any user) can read it."""
    acl_url = f"{splunk_url}/servicesNS/nobody/{APP}/data/lookup-table-files/{csv_name}/acl"
    httpx.post(acl_url, data={
        "sharing": "global", "owner": "nobody", "perms.read": "*", "output_mode": "json",
    }, auth=auth, verify=False, timeout=15)


def refresh_dashboards(db_session):
    """Re-push CSV lookups using the latest scan, so a deploy/approve made
    OUTSIDE a scan (e.g. analyst approves on the control panel) is reflected on
    the Splunk dashboards — turning the attack-path node RED->GREEN live."""
    from db.models import CoverageHistory
    latest = (
        db_session.query(CoverageHistory)
        .order_by(CoverageHistory.measured_at.desc())
        .first()
    )
    if not latest:
        return
    push_scan_results_to_csv({
        "scan_id": latest.scan_id,
        "industry": latest.industry_profile,
        "started_at": latest.measured_at.isoformat() if latest.measured_at else "",
        "coverage_after_pct": latest.coverage_pct,
        "total_financial_exposure_usd": latest.financial_exposure_usd or 0,
    }, db_session)


def push_scan_results_to_csv(scan_summary: dict, db_session):
    """Export DB data -> CSV lookups so dashboards reflect latest state."""
    settings = get_settings()
    auth = (settings.splunk_username, settings.splunk_password)
    base = settings.splunk_url

    datasets = _build_records(scan_summary, db_session, settings)
    for key, csv_name in DATASETS:
        written = _write_csv_lookup(base, auth, csv_name, datasets.get(key, []))
        print(f"  {csv_name}: {written} rows written")


def _build_records(scan_summary: dict, db, settings) -> dict:
    from db.models import Gap, Rule, DriftEvent, RuleClassification
    from core.intelligence.attack_loader import get_attack_loader
    from core.intelligence.kill_chain_mapper import score_all_actors

    scan_id = scan_summary["scan_id"]
    industry = scan_summary.get("industry", settings.industry_profile)

    gaps = db.query(Gap).filter(Gap.scan_id == scan_id).all()
    gap_records = [{
        "technique_id": g.technique_id, "technique_name": g.technique_name,
        "tactic": g.tactic, "status": g.status, "industry": g.industry,
        "financial_exposure_usd": g.financial_exposure_usd or 0,
        "priority_score": g.priority_score,
    } for g in gaps]

    rules = db.query(Rule).all()
    rule_records = [{
        "technique_id": r.technique_id, "technique_name": r.technique_name,
        "tactic": r.tactic, "status": r.status, "industry": r.industry,
        "hits_per_day": r.hits_per_day or 0,
        "false_pos_estimate": r.false_pos_estimate or "",
        "tuning_rounds": r.tuning_rounds,
        "splunk_search_name": r.splunk_search_name or "",
        "deployed_at": r.deployed_at.isoformat() if r.deployed_at else "",
    } for r in rules]

    cov_records = [{
        "scan_id": scan_id,
        "coverage_pct": scan_summary.get("coverage_after_pct", 0),
        "financial_exposure_usd": scan_summary.get("total_financial_exposure_usd", 0),
        "industry": industry,
        "measured_at": scan_summary.get("started_at", ""),
    }]

    drift_events = db.query(DriftEvent).all()
    drift_records = [{
        "event_id": d.id, "rule_id": d.rule_id, "drift_type": d.drift_type,
        "detail": d.detail,
        "detected_at": d.detected_at.isoformat() if d.detected_at else "",
        "resolved_at": d.resolved_at.isoformat() if d.resolved_at else "",
        "resolution": d.resolution or "",
    } for d in drift_events]

    # actor chains scored against current coverage
    latest_class = (
        db.query(RuleClassification.scan_id)
        .order_by(RuleClassification.classified_at.desc()).first()
    )
    coverage_map = {}
    if latest_class:
        rows = db.query(RuleClassification).filter(
            RuleClassification.scan_id == latest_class[0],
            RuleClassification.technique_id.isnot(None),
        ).all()
        coverage_map = {r.technique_id: {"rule_name": r.search_name} for r in rows}
    for rule in db.query(Rule).filter(Rule.status == "DEPLOYED").all():
        coverage_map[rule.technique_id] = {"rule_name": rule.splunk_search_name or rule.technique_name}
    broken = {r.technique_id for r in db.query(Rule).filter(Rule.status == "BROKEN").all()}

    loader = get_attack_loader()
    actor_results = score_all_actors(industry, coverage_map, broken, loader)
    chain_records = []
    for result in actor_results:
        for step in result.chain:
            chain_records.append({
                "actor": result.actor, "step": step.step,
                "technique_id": step.technique_id, "technique_name": step.technique_name,
                "tactic": step.tactic, "status": step.status,
                "coverage_pct": result.coverage_pct,
                "longest_blind_window": result.longest_blind_window,
                "total_steps": result.total_steps,
            })

    # Coverage by MITRE tactic — covered vs open, the meaningful per-phase view.
    # "Total" per tactic = covered techniques + open gaps in that tactic.
    tactic_covered: dict[str, int] = {}
    for tid in coverage_map:
        tech = loader.get_technique(tid)
        tac = (tech.tactics[0] if tech and tech.tactics else "Unknown")
        tactic_covered[tac] = tactic_covered.get(tac, 0) + 1
    tactic_gaps: dict[str, int] = {}
    for g in gaps:
        tactic_gaps[g.tactic] = tactic_gaps.get(g.tactic, 0) + 1
    tactic_records = []
    for tac in sorted(set(tactic_covered) | set(tactic_gaps)):
        cov = tactic_covered.get(tac, 0)
        gp = tactic_gaps.get(tac, 0)
        total = cov + gp
        tactic_records.append({
            "tactic": tac,
            "covered": cov,
            "gaps": gp,
            "coverage_pct": round(cov / total * 100, 1) if total else 0.0,
        })

    return {
        "detectforge_gaps": gap_records,
        "detectforge_rules": rule_records,
        "detectforge_coverage": cov_records,
        "detectforge_drift_events": drift_records,
        "detectforge_actor_chains": chain_records,
        "detectforge_tactic_coverage": tactic_records,
    }


if __name__ == "__main__":
    settings = get_settings()
    setup(settings.splunk_url, (settings.splunk_username, settings.splunk_password))
