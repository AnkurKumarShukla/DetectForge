"""LangGraph state schema for the DetectForge agent pipeline."""
from typing import TypedDict, Any


class DetectForgeState(TypedDict, total=False):
    # Scan metadata
    scan_id: str
    industry: str
    started_at: str

    # Phase 1 output
    env_fingerprint: dict[str, Any]
    splunk_version: str
    schema_hash: str

    # Phase 2 output
    existing_rules: list[dict]          # classified saved searches
    coverage_map: dict[str, dict]       # technique_id → classification
    all_gaps: list[dict]                # all uncovered techniques with scores
    prioritized_gaps: list[dict]        # sorted closable gaps

    # Phase 3–5 output (per gap, accumulated)
    generated_rules: list[dict]         # rules that passed generation + validation
    review_queue_ids: list[str]         # DB IDs of rules queued for review
    deployed_rule_ids: list[str]        # DB IDs of deployed rules

    # Coverage stats
    coverage_before_pct: float
    coverage_after_pct: float
    total_financial_exposure_usd: float

    # Control flow
    current_gap_index: int
    errors: list[str]
    phase: str                          # current phase name for logging
