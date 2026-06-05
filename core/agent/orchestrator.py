"""LangGraph orchestrator — the main DetectForge agent pipeline."""
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from core.agent.nodes.auto_tuner import tune_rule
from core.agent.nodes.deployer import deploy_rule
from core.agent.nodes.env_scanner import run_env_scanner
from core.agent.nodes.gap_prioritizer import run_gap_prioritizer
from core.agent.nodes.rule_classifier import run_rule_classifier
from core.agent.nodes.spl_generator import run_spl_generator
from core.agent.nodes.validator import validate_spl, STATUS_GOOD, STATUS_DATA_ABSENT, STATUS_NOISY, STATUS_VERY_NOISY, STATUS_QUERY_ERROR
from core.config import get_settings
from core.models.foundation_sec import FoundationSecClient
from core.splunk.agent_logger import get_agent_logger
from core.splunk.mcp_client import SplunkMCPClient
from core.splunk.rest_client import SplunkRestClient
from dashboard.setup_dashboards import push_scan_results_to_csv
from db.models import CoverageHistory, ReviewQueue, Rule

logger = logging.getLogger(__name__)


class DetectForgeOrchestrator:
    def __init__(self, db: Session):
        self.db = db
        self.mcp = SplunkMCPClient()
        self.rest = SplunkRestClient()
        self.foundation_sec = FoundationSecClient()
        self.settings = get_settings()
        self.activity = get_agent_logger()

    def run(self, industry: str | None = None, max_gaps: int = 20) -> dict:
        """Execute the full 6-phase pipeline. Returns a summary dict."""
        scan_id = str(uuid.uuid4())
        industry = industry or self.settings.industry_profile
        started_at = datetime.now(timezone.utc).isoformat()

        state: dict = {
            "scan_id": scan_id,
            "industry": industry,
            "started_at": started_at,
            "errors": [],
            "generated_rules": [],
            "review_queue_ids": [],
            "deployed_rule_ids": [],
        }

        logger.info("=== DetectForge scan started — scan_id=%s industry=%s ===", scan_id, industry)
        self.activity.log("scan_started", scan_id=scan_id, phase="orchestrator",
                          detail=f"industry={industry}", severity="info")

        # Phase 1: Environment Scanner
        self.activity.log("env_scan", scan_id=scan_id, phase="1-env_scanner",
                          detail="Fingerprinting Splunk indexes/sourcetypes/fields")
        state = run_env_scanner(state, self.db, self.mcp)
        self.activity.log("env_scan_complete", scan_id=scan_id, phase="1-env_scanner",
                          status="done",
                          detail=f"{len(state.get('env_fingerprint', {}).get('indexes', {}))} indexes fingerprinted")

        # Phase 2a: Rule Classifier
        self.activity.log("classify", scan_id=scan_id, phase="2a-rule_classifier",
                          detail="Classifying existing detections -> ATT&CK")
        state = run_rule_classifier(state, self.db, self.foundation_sec)
        self.activity.log("classify_complete", scan_id=scan_id, phase="2a-rule_classifier",
                          status="done",
                          detail=f"{len(state.get('coverage_map', {}))} techniques already covered")

        # Phase 2b: Gap Prioritizer
        state = run_gap_prioritizer(state, self.db)
        self.activity.log("prioritize_complete", scan_id=scan_id, phase="2b-gap_prioritizer",
                          status="done",
                          detail=f"{len(state.get('all_gaps', []))} gaps, "
                                 f"{len(state.get('prioritized_gaps', []))} closable, "
                                 f"coverage_before={state.get('coverage_before_pct', 0)}%")

        gaps = state.get("prioritized_gaps", [])[:max_gaps]
        logger.info("Processing %d closable gaps", len(gaps))

        # Phase 3-5: Per-gap loop
        for gap in gaps:
            self._process_gap(gap, state)

        # Record final coverage
        coverage_after = self._calculate_coverage_pct(state)
        self._record_coverage(scan_id, industry, state, coverage_after)

        summary = {
            "scan_id": scan_id,
            "industry": industry,
            "started_at": started_at,
            "coverage_before_pct": state.get("coverage_before_pct", 0.0),
            "coverage_after_pct": coverage_after,
            "total_gaps_found": len(state.get("all_gaps", [])),
            "closable_gaps": len(gaps),
            "rules_generated": len(state.get("generated_rules", [])),
            "rules_queued_for_review": len(state.get("review_queue_ids", [])),
            "rules_deployed": len(state.get("deployed_rule_ids", [])),
            "total_financial_exposure_usd": state.get("total_financial_exposure_usd", 0.0),
            "errors": state.get("errors", []),
        }
        logger.info("=== DetectForge scan complete: %s ===", summary)
        self.activity.log("scan_complete", scan_id=scan_id, phase="orchestrator", status="done",
                          detail=f"generated={summary['rules_generated']} "
                                 f"queued={summary['rules_queued_for_review']} "
                                 f"deployed={summary['rules_deployed']}",
                          coverage_after_pct=coverage_after,
                          coverage_before_pct=summary["coverage_before_pct"], severity="info")

        try:
            push_scan_results_to_csv(summary, self.db)
        except Exception as e:
            logger.warning("CSV lookup push failed (dashboards may be stale): %s", e)

        return summary

    def _process_gap(self, gap: dict, state: dict) -> None:
        technique_id = gap["technique_id"]
        scan_id = state["scan_id"]
        industry = state["industry"]

        logger.info("[Gap] Processing %s — %s (score=%.3f exposure=$%.0f)",
                    technique_id, gap["technique_name"],
                    gap["priority_score"], gap.get("financial_exposure_usd", 0))
        self.activity.log("gap_selected", scan_id=scan_id, phase="3-spl_generator",
                          technique_id=technique_id, technique_name=gap["technique_name"],
                          detail=f"priority={gap['priority_score']:.3f} "
                                 f"exposure=${gap.get('financial_exposure_usd', 0):,.0f} "
                                 f"tactic={gap.get('tactic', '')}",
                          priority_score=gap["priority_score"],
                          financial_exposure_usd=gap.get("financial_exposure_usd", 0))

        # Phase 3: Generate SPL
        gen_result = run_spl_generator(gap, state.get("env_fingerprint", {}), self.mcp, self.foundation_sec)
        spl = gen_result.get("spl", "")
        if not spl:
            state["errors"].append(f"{technique_id}: SPL generation produced no output")
            self.activity.log("generate_failed", scan_id=scan_id, phase="3-spl_generator",
                              technique_id=technique_id, status="error",
                              detail="SPL generation produced no output", severity="error")
            return
        self.activity.log("spl_generated", scan_id=scan_id, phase="3-spl_generator",
                          technique_id=technique_id, technique_name=gap["technique_name"],
                          status="generated",
                          detail=f"confidence={gen_result['confidence']:.2f} "
                                 f"attempts={gen_result['generation_attempts']}",
                          confidence=gen_result["confidence"], spl=spl)

        # Persist rule to DB
        index_name, sourcetype = self._infer_index_sourcetype(gap, state.get("env_fingerprint", {}))
        rule = Rule(
            scan_id=scan_id,
            technique_id=technique_id,
            technique_name=gap["technique_name"],
            tactic=gap["tactic"],
            spl=spl,
            confidence_score=gen_result["confidence"],
            generation_attempts=gen_result["generation_attempts"],
            industry=industry,
            index_name=index_name,
            sourcetype=sourcetype,
            status="PENDING_REVIEW",
        )
        self.db.add(rule)
        self.db.commit()

        # Phase 4: Validate
        validation = validate_spl(spl, index_name or "main", sourcetype or "*", self.mcp)
        rule.hits_per_day = validation["hits_per_day"]
        rule.false_pos_estimate = validation.get("false_pos_estimate")
        self.db.commit()

        status = validation["status"]
        self.activity.log("spl_validated", scan_id=scan_id, phase="4-validator",
                          technique_id=technique_id, status=status,
                          detail=f"{validation['hits_per_day']:.1f} hits/day on real data",
                          hits_per_day=validation["hits_per_day"],
                          severity="warning" if status == STATUS_QUERY_ERROR else "info")

        # Self-correction: the rule ran against real data and returned 0 hits while
        # data exists → likely invented EventCodes / over-specific filters. Give the
        # agent one chance to broaden, then let the human decide (HITL never drops).
        if status == STATUS_QUERY_ERROR:
            logger.info("[Validate] %s returned 0 hits on real data — regenerating with feedback", technique_id)
            feedback = (
                "Your previous SPL returned 0 results against real data even though the "
                "sourcetype has events. Broaden it: target an EventCode that actually exists "
                "in this environment, drop rare literal values (registry paths, hashes, exact "
                "access masks), lower or remove thresholds, and never call count()/values() "
                "inside where."
            )
            regen = run_spl_generator(gap, state.get("env_fingerprint", {}), self.mcp, self.foundation_sec, validation_feedback=feedback)
            if regen.get("spl"):
                spl = regen["spl"]
                rule.spl = spl
                rule.confidence_score = regen["confidence"]
                rule.generation_attempts = rule.generation_attempts + regen["generation_attempts"]
                gen_result = regen
                self.db.commit()
                validation = validate_spl(spl, index_name or "main", sourcetype or "*", self.mcp)
                rule.hits_per_day = validation["hits_per_day"]
                rule.false_pos_estimate = validation.get("false_pos_estimate")
                self.db.commit()
                status = validation["status"]
                logger.info("[Validate] %s after regeneration -> %s (%.2f hits/day)",
                            technique_id, status, validation["hits_per_day"])

        if status in (STATUS_NOISY, STATUS_VERY_NOISY):
            logger.info("[Validate] %s is noisy (%.1f/day), auto-tuning", technique_id, validation["hits_per_day"])
            validation = tune_rule(rule, self.mcp, self.db)
            status = validation["status"]

        # Phase 5: Human Review Queue — every generated detection reaches a human.
        # Mandatory review when confidence is low OR validation is uncertain
        # (0 hits / data-absent / still-erroring), so analysts scrutinise those.
        uncertain = status in (STATUS_QUERY_ERROR, STATUS_DATA_ABSENT)
        mandatory = (gen_result["confidence"] < self.settings.confidence_mandatory_review_threshold) or uncertain
        review_entry = ReviewQueue(
            rule_id=rule.id,
            mandatory=mandatory,
            decision="PENDING",
        )
        self.db.add(review_entry)
        self.db.commit()

        state["generated_rules"].append({
            "rule_id": rule.id,
            "technique_id": technique_id,
            "spl": spl,
            "confidence": gen_result["confidence"],
            "validation_status": validation["status"],
            "hits_per_day": validation["hits_per_day"],
        })
        state["review_queue_ids"].append(review_entry.id)
        logger.info("[Gap] %s -> queued for review (mandatory=%s)", technique_id, mandatory)
        self.activity.log("queued_for_review", scan_id=scan_id, phase="5-review_queue",
                          technique_id=technique_id, technique_name=gap["technique_name"],
                          status="pending_review",
                          detail=f"mandatory={mandatory} confidence={gen_result['confidence']:.2f} "
                                 f"validation={validation['status']}",
                          confidence=gen_result["confidence"],
                          hits_per_day=validation["hits_per_day"],
                          severity="info")

    def _infer_index_sourcetype(self, gap: dict, env_fingerprint: dict) -> tuple[str, str]:
        """Pick a security-relevant index/sourcetype for this gap.

        Used both to tag the rule and as the baseline for the validator's
        data-existence check, so it must reflect a sourcetype the generated SPL
        would plausibly target — not just the first one in the fingerprint
        (which would make every 0-hit rule look like a QUERY_ERROR).
        """
        indexes = env_fingerprint.get("indexes", {})
        if not indexes:
            return "main", "*"
        # Prefer botsv3, then any index with a security-relevant sourcetype.
        ordered = (["botsv3"] if "botsv3" in indexes else []) + [i for i in indexes if i != "botsv3"]
        fallback: tuple[str, str] | None = None
        for idx in ordered:
            sourcetypes = indexes[idx].get("sourcetypes", {})
            for st, st_data in sourcetypes.items():
                if st_data.get("security_relevant") or st_data.get("fields"):
                    return idx, st
                if fallback is None:
                    fallback = (idx, st)
        return fallback or (next(iter(indexes)), "*")

    def _calculate_coverage_pct(self, state: dict) -> float:
        from core.intelligence.attack_loader import get_attack_loader
        loader = get_attack_loader()
        total = len(loader.get_all_techniques())
        if total == 0:
            return 0.0
        covered = len(state.get("coverage_map", {})) + len(state.get("deployed_rule_ids", []))
        return round(min(covered / total * 100, 100.0), 1)

    def _record_coverage(self, scan_id: str, industry: str, state: dict, coverage_after: float) -> None:
        entry = CoverageHistory(
            scan_id=scan_id,
            industry_profile=industry,
            coverage_pct=coverage_after,
            techniques_covered=len(state.get("coverage_map", {})),
            techniques_total=len(state.get("all_gaps", [])) + len(state.get("coverage_map", {})),
            financial_exposure_usd=state.get("total_financial_exposure_usd", 0.0),
        )
        self.db.add(entry)
        self.db.commit()
