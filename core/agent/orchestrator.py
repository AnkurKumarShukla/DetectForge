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
from core.splunk.mcp_client import SplunkMCPClient
from core.splunk.rest_client import SplunkRestClient
from db.models import CoverageHistory, ReviewQueue, Rule

logger = logging.getLogger(__name__)


class DetectForgeOrchestrator:
    def __init__(self, db: Session):
        self.db = db
        self.mcp = SplunkMCPClient()
        self.rest = SplunkRestClient()
        self.foundation_sec = FoundationSecClient()
        self.settings = get_settings()

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

        # Phase 1: Environment Scanner
        state = run_env_scanner(state, self.db, self.mcp)

        # Phase 2a: Rule Classifier
        state = run_rule_classifier(state, self.db, self.foundation_sec)

        # Phase 2b: Gap Prioritizer
        state = run_gap_prioritizer(state, self.db)

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
        return summary

    def _process_gap(self, gap: dict, state: dict) -> None:
        technique_id = gap["technique_id"]
        scan_id = state["scan_id"]
        industry = state["industry"]

        logger.info("[Gap] Processing %s — %s (score=%.3f exposure=$%.0f)",
                    technique_id, gap["technique_name"],
                    gap["priority_score"], gap.get("financial_exposure_usd", 0))

        # Phase 3: Generate SPL
        gen_result = run_spl_generator(gap, state.get("env_fingerprint", {}), self.mcp, self.foundation_sec)
        spl = gen_result.get("spl", "")
        if not spl:
            state["errors"].append(f"{technique_id}: SPL generation produced no output")
            return

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

        if status == STATUS_QUERY_ERROR:
            logger.warning("[Validate] %s QUERY_ERROR — rule has logic issues", technique_id)
            state["errors"].append(f"{technique_id}: validation QUERY_ERROR — {validation['note']}")
            return

        if status in (STATUS_NOISY, STATUS_VERY_NOISY):
            logger.info("[Validate] %s is noisy (%.1f/day), auto-tuning", technique_id, validation["hits_per_day"])
            validation = tune_rule(rule, self.mcp, self.db)

        # Phase 5: Human Review Queue
        mandatory = gen_result["confidence"] < self.settings.confidence_mandatory_review_threshold
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
        logger.info("[Gap] %s → queued for review (mandatory=%s)", technique_id, mandatory)

    def _infer_index_sourcetype(self, gap: dict, env_fingerprint: dict) -> tuple[str, str]:
        """Pick the most relevant index and sourcetype for this gap based on data sources."""
        indexes = env_fingerprint.get("indexes", {})
        if not indexes:
            return "main", "*"
        first_index = next(iter(indexes))
        first_sourcetypes = list(indexes[first_index].get("sourcetypes", {}).keys())
        return first_index, (first_sourcetypes[0] if first_sourcetypes else "*")

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
