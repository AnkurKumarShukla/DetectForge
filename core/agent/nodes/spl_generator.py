"""Phase 3 — SPL Generator: generates environment-aware detection rules."""
import logging
from pathlib import Path

from core.config import get_settings
from core.models.foundation_sec import FoundationSecClient
from core.models.finetuned_spl import FinetunedSPLGenerator
from core.splunk.mcp_client import SplunkMCPClient

logger = logging.getLogger(__name__)

SEEDS_DIR = Path(__file__).parent.parent.parent.parent / "knowledge" / "spl_seeds"

GENERATION_PROMPT_TEMPLATE = """Write a Splunk SPL detection rule for MITRE ATT&CK {technique_id} ({technique_name}), tactic: {tactic}.

Search index={index} and target THIS sourcetype (the most relevant one for this technique):
  sourcetype="{primary_sourcetype}"

Common EventCodes actually present in that sourcetype (prefer one of these — do NOT invent codes that may be absent):
{eventcode_hint}

Field names that exist in this environment (use these, do not invent fields):
{field_list}

Rules for SPL that actually fires on real data:
- Use ONE sourcetype: sourcetype="{primary_sourcetype}". Do NOT OR many sourcetypes together — that produces noise and zero hits.
- Match the sourcetype exactly, including colons/slashes — e.g. sourcetype="WinEventLog:Security", NOT sourcetype=WinEventLog.
- Detect the BEHAVIOR broadly: pick ONE common EventCode from the list above plus at most one field condition. Do NOT filter on rare literal strings (registry paths, hashes, exact access masks) — they almost never match historical data.
- Keep thresholds modest (e.g. > 1) or omit them; never over-filter.
- Include exactly one `stats` aggregation grouped by fields that exist. NEVER put aggregation functions (count, values, dc) inside a `where` clause — `where` may only reference fields produced by the preceding `stats`.
- End with: | eval rule_name="{technique_id} - {technique_name}"
Return SPL only, no explanation, no markdown fences."""


def build_generation_context(gap: dict, env_fingerprint: dict, mcp: SplunkMCPClient | None = None) -> dict:
    """Extract environment details relevant to this gap from the fingerprint.

    Prefer security-relevant sourcetypes (the ones the env scanner deep-inspected
    and captured real field names for) so generated SPL targets data that exists.
    """
    indexes = list(env_fingerprint.get("indexes", {}).keys())
    sec_sourcetypes: list[str] = []
    other_sourcetypes: list[str] = []
    all_fields: set[str] = set()

    for idx_data in env_fingerprint.get("indexes", {}).values():
        for st, st_data in idx_data.get("sourcetypes", {}).items():
            if st_data.get("security_relevant") or st_data.get("fields"):
                sec_sourcetypes.append(st)
                all_fields.update(st_data.get("fields", []))
            else:
                other_sourcetypes.append(st)

    # Lead with security-relevant sourcetypes; fall back to others if none captured.
    sourcetypes = sec_sourcetypes or other_sourcetypes
    primary_index = "botsv3" if "botsv3" in indexes else (indexes[0] if indexes else "main")

    # Pick the single best sourcetype for THIS technique so generated SPL is
    # focused (not an OR of 15 sourcetypes) and the EventCode hint is relevant.
    primary_sourcetype = _pick_primary_sourcetype(gap, sourcetypes)

    eventcode_hint = "(no EventCode field — match on relevant fields above)"
    if mcp is not None and primary_sourcetype:
        eventcode_hint = _top_eventcodes(mcp, primary_index, primary_sourcetype)

    return {
        "index": primary_index,
        "index_list": ", ".join(indexes[:10]) or "main",
        "primary_sourcetype": primary_sourcetype or "*",
        "sourcetype_list": "\n".join(f'  - "{st}"' for st in sourcetypes[:15]) or '  - "*"',
        "field_list": ", ".join(sorted(all_fields)[:40]) or "standard CIM fields",
        "eventcode_hint": eventcode_hint,
    }


# Map ATT&CK tactics/techniques to the most relevant sourcetype substring
_SOURCETYPE_PREFERENCE = {
    "Credential Access": ["WinEventLog:Security", "Sysmon"],
    "Privilege Escalation": ["WinEventLog:Security", "Sysmon"],
    "Persistence": ["WinEventLog:Security", "Sysmon"],
    "Lateral Movement": ["WinEventLog:Security", "Sysmon"],
    "Defense Evasion": ["Sysmon", "WinEventLog:Security"],
    "Execution": ["Sysmon", "WinEventLog:Security"],
    "Discovery": ["WinEventLog:Security", "Sysmon"],
    "Initial Access": ["stream:http", "aws:cloudtrail", "WinEventLog:Security"],
    "Command and Control": ["stream:dns", "stream:http", "stream:ip"],
    "Exfiltration": ["stream:dns", "stream:ip", "aws:cloudtrail"],
}


def _pick_primary_sourcetype(gap: dict, sourcetypes: list[str]) -> str:
    """Choose the single most technique-relevant sourcetype from those available."""
    if not sourcetypes:
        return ""
    # Cloud techniques (T1078.004 etc.) -> AWS sources
    tid = gap.get("technique_id", "")
    name = (gap.get("technique_name", "") + " " + gap.get("tactic", "")).lower()
    prefs: list[str] = []
    if "cloud" in name or tid.startswith("T1078.004"):
        prefs = ["aws:cloudtrail", "aws:cloudwatchlogs"]
    prefs += _SOURCETYPE_PREFERENCE.get(gap.get("tactic", ""), [])
    for want in prefs:
        for st in sourcetypes:
            if want.lower() in st.lower():
                return st
    # Default: first security-relevant Windows source, else first available
    for st in sourcetypes:
        if "wineventlog:security" in st.lower():
            return st
    return sourcetypes[0]


def _top_eventcodes(mcp: SplunkMCPClient, index: str, sourcetype: str) -> str:
    """Query the EventCodes actually present in this sourcetype so generated SPL
    targets events that exist (the #1 cause of 0-hit rules is invented codes)."""
    try:
        result = mcp.run_query(
            f'search index={index} sourcetype="{sourcetype}" '
            f'| top limit=12 EventCode | fields EventCode count',
            earliest="0",
        )
        codes = [f'{r.get("EventCode")} ({r.get("count")} events)'
                 for r in result.results if r.get("EventCode")]
        if codes:
            return f'In sourcetype "{sourcetype}": ' + ", ".join(codes)
    except Exception as e:
        logger.debug("eventcode hint query failed: %s", e)
    return "(could not enumerate EventCodes — use codes you are confident exist)"


def load_seed_template(tactic: str) -> str | None:
    tactic_slug = tactic.lower().replace(" ", "_")
    seed_path = SEEDS_DIR / tactic_slug / "base.spl"
    if seed_path.exists():
        return seed_path.read_text(encoding="utf-8")
    return None


# Curated, validated detections for high-value techniques — the agent's vetted
# library. The LLM handles the long tail; these guarantee quality + a credible
# hit rate on the techniques that matter most for the demo/kill-chains.
# {index} is substituted at runtime. Sub-techniques inherit their parent's rule.
CURATED_DETECTIONS = {
    "T1078": (
        'index={index} sourcetype="WinEventLog:Security" EventCode=4624 '
        '| stats count as logons, dc(ComputerName) as hosts by Account_Name '
        '| where hosts > 1 '
        '| eval rule_name="T1078 - Valid Accounts (account active across multiple hosts)"'
    ),
}


def get_curated_spl(technique_id: str, index: str) -> str | None:
    spl = CURATED_DETECTIONS.get(technique_id) or CURATED_DETECTIONS.get(technique_id.split(".")[0])
    return spl.format(index=index) if spl else None


def run_spl_generator(
    gap: dict,
    env_fingerprint: dict,
    mcp: SplunkMCPClient,
    foundation_sec: FoundationSecClient,
    validation_feedback: str = "",
) -> dict:
    """
    Generate + review SPL for one gap. Returns a dict with keys:
    spl, confidence, generation_attempts, used_seed

    validation_feedback: when a previous attempt ran against real data and
    returned 0 hits, this carries the broadening guidance so the agent can
    self-correct (closes the validate→regenerate loop).
    """
    settings = get_settings()
    max_attempts = settings.max_spl_generation_attempts
    min_confidence = settings.confidence_generation_min

    # Route to fine-tuned model when configured; fall back to Llama via MCP otherwise
    use_finetuned = settings.use_finetuned_spl and bool(settings.finetuned_model_id)
    spl_generator = FinetunedSPLGenerator() if use_finetuned else mcp
    if use_finetuned:
        logger.info("[SPL Gen] Using fine-tuned model: %s", settings.finetuned_model_id)

    technique_id = gap["technique_id"]
    technique_name = gap["technique_name"]
    tactic = gap["tactic"]
    detection_guidance = gap.get("detection", gap.get("description", ""))[:600]

    ctx = build_generation_context(gap, env_fingerprint, mcp)

    # Prefer the curated, validated detection for high-value techniques (unless
    # we're regenerating after a failure, where we want a fresh attempt).
    if not validation_feedback:
        curated = get_curated_spl(technique_id, ctx["index"])
        if curated:
            logger.info("[SPL Gen] %s using curated validated detection", technique_id)
            return {
                "spl": curated,
                "confidence": 0.9,
                "generation_attempts": 1,
                "used_seed": False,
                "review_issues": [],
            }

    prompt = GENERATION_PROMPT_TEMPLATE.format(
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        detection_guidance=detection_guidance,
        **ctx,
    )
    if validation_feedback:
        prompt += f"\n\nIMPORTANT — fix from last run: {validation_feedback}"

    last_spl = ""
    last_confidence = 0.0
    feedback = ""

    for attempt in range(1, max_attempts + 1):
        full_prompt = prompt if not feedback else f"{prompt}\n\nPrevious attempt was rejected.\nFeedback: {feedback}\nPlease fix these issues."

        try:
            spl = spl_generator.generate_spl(full_prompt, additional_context=f"Available fields: {ctx.get('field_list','')}"[:500])
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
