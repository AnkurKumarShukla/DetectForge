"""Phase 3 — SPL Generator: generates environment-aware detection rules."""
import logging
from pathlib import Path

from core.config import get_settings
from core.models.foundation_sec import FoundationSecClient
from core.splunk.mcp_client import SplunkMCPClient

logger = logging.getLogger(__name__)

SEEDS_DIR = Path(__file__).parent.parent.parent.parent / "knowledge" / "spl_seeds"

GENERATION_PROMPT_TEMPLATE = """Generate a production-ready Splunk SPL detection rule.

TECHNIQUE: {technique_id} — {technique_name}
TACTIC: {tactic}
WHAT TO DETECT: {detection_guidance}

ENVIRONMENT (use ONLY these exact field names and values):
  Available indexes: {index_list}
  Available sourcetypes: {sourcetype_list}
  Sample fields: {field_list}

REQUIREMENTS:
1. Use ONLY the field names and sourcetypes listed above — never invent field names
2. Include statistical aggregation where appropriate (stats, timechart)
3. Set time windows appropriate for this technique's typical execution speed
4. End with: | eval rule_name="{technique_id} - {technique_name}"
5. Keep it under 20 lines

OUTPUT: SPL query only. No explanation. No markdown fences. No comments."""


def build_generation_context(gap: dict, env_fingerprint: dict) -> dict:
    """Extract environment details relevant to this gap from the fingerprint."""
    indexes = list(env_fingerprint.get("indexes", {}).keys())
    all_sourcetypes: list[str] = []
    all_fields: set[str] = set()

    for idx_data in env_fingerprint.get("indexes", {}).values():
        for st, st_data in idx_data.get("sourcetypes", {}).items():
            all_sourcetypes.append(st)
            all_fields.update(st_data.get("fields", []))

    return {
        "index_list": ", ".join(indexes[:10]) or "main",
        "sourcetype_list": ", ".join(all_sourcetypes[:15]) or "any",
        "field_list": ", ".join(sorted(all_fields)[:40]) or "standard fields",
    }


def load_seed_template(tactic: str) -> str | None:
    tactic_slug = tactic.lower().replace(" ", "_")
    seed_path = SEEDS_DIR / tactic_slug / "base.spl"
    if seed_path.exists():
        return seed_path.read_text(encoding="utf-8")
    return None


def run_spl_generator(
    gap: dict,
    env_fingerprint: dict,
    mcp: SplunkMCPClient,
    foundation_sec: FoundationSecClient,
) -> dict:
    """
    Generate + review SPL for one gap. Returns a dict with keys:
    spl, confidence, generation_attempts, used_seed
    """
    settings = get_settings()
    max_attempts = settings.max_spl_generation_attempts
    min_confidence = settings.confidence_generation_min

    technique_id = gap["technique_id"]
    technique_name = gap["technique_name"]
    tactic = gap["tactic"]
    detection_guidance = gap.get("detection", gap.get("description", ""))[:600]

    ctx = build_generation_context(gap, env_fingerprint)
    prompt = GENERATION_PROMPT_TEMPLATE.format(
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        detection_guidance=detection_guidance,
        **ctx,
    )

    last_spl = ""
    last_confidence = 0.0
    feedback = ""

    for attempt in range(1, max_attempts + 1):
        full_prompt = prompt if not feedback else f"{prompt}\n\nPrevious attempt was rejected.\nFeedback: {feedback}\nPlease fix these issues."

        try:
            spl = mcp.generate_spl(full_prompt)
            if not spl.strip():
                logger.warning("[SPL Gen] Attempt %d/%d: empty response", attempt, max_attempts)
                continue

            review = foundation_sec.review_spl_logic(spl, technique_id, technique_name, tactic)
            confidence = review["confidence"]
            last_spl = spl
            last_confidence = confidence

            logger.info(
                "[SPL Gen] %s attempt %d/%d confidence=%.2f approved=%s",
                technique_id, attempt, max_attempts, confidence, review["approved"],
            )

            if review["approved"] and confidence >= min_confidence:
                return {
                    "spl": spl,
                    "confidence": confidence,
                    "generation_attempts": attempt,
                    "used_seed": False,
                    "review_issues": [],
                }

            feedback = "; ".join(review.get("issues", []) + review.get("suggestions", []))

        except Exception as e:
            logger.error("[SPL Gen] %s attempt %d failed: %s", technique_id, attempt, e)
            feedback = str(e)

    # All attempts failed — try Sigma seed template
    seed = load_seed_template(tactic)
    if seed:
        logger.info("[SPL Gen] %s falling back to seed template", technique_id)
        filled = seed.replace("{TECHNIQUE_ID}", technique_id).replace("{TECHNIQUE_NAME}", technique_name)
        return {
            "spl": filled,
            "confidence": 0.55,
            "generation_attempts": max_attempts,
            "used_seed": True,
            "review_issues": ["Used seed template — manual review required"],
        }

    # Last resort: return best attempt with low confidence
    logger.warning("[SPL Gen] %s no valid SPL generated after %d attempts", technique_id, max_attempts)
    return {
        "spl": last_spl,
        "confidence": last_confidence,
        "generation_attempts": max_attempts,
        "used_seed": False,
        "review_issues": ["Max attempts reached without Foundation-sec approval"],
    }
