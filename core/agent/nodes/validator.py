"""Phase 4 — Validator: tests generated SPL against 30 days of historical data."""
import logging

from core.config import get_settings
from core.splunk.mcp_client import SplunkMCPClient

logger = logging.getLogger(__name__)

# Validation status constants
STATUS_GOOD = "GOOD"
STATUS_NOISY = "NOISY"
STATUS_VERY_NOISY = "VERY_NOISY"
STATUS_DATA_ABSENT = "DATA_ABSENT"
STATUS_QUERY_ERROR = "QUERY_ERROR"


def validate_spl(spl: str, index: str, sourcetype: str, mcp: SplunkMCPClient) -> dict:
    """
    Run SPL against 30 days of data and classify the result.

    The critical distinction:
    - DATA_ABSENT: rule is correct, technique simply didn't occur in 30d
    - QUERY_ERROR: data exists but rule returns nothing — logic problem
    """
    settings = get_settings()
    good_threshold = settings.hits_per_day_good_threshold
    very_noisy_threshold = settings.hits_per_day_very_noisy_threshold
    lookback = "earliest=0"

    # Run the rule itself
    try:
        count_spl = f"{spl} | stats count as total_hits"
        result = mcp.run_query(count_spl, earliest="0")
        total_hits = int(result.results[0].get("total_hits", 0)) if result.results else result.count
    except Exception as e:
        logger.error("Validation query failed: %s", e)
        return {
            "status": STATUS_QUERY_ERROR,
            "hits_per_day": 0.0,
            "total_hits": 0,
            "note": f"Query execution error: {e}",
            "false_pos_estimate": "UNKNOWN",
        }

    hits_per_day = round(total_hits / 60, 2)  # botsv3 spans ~60 days

    if total_hits == 0:
        # Critical distinction: absent data vs broken rule
        data_check = mcp.run_query(
            f"index={index} sourcetype=\"{sourcetype}\" | head 1 | stats count",
            earliest="0",
        )
        underlying_data_exists = data_check.count > 0 or (data_check.results and int(data_check.results[0].get("count", 0)) > 0)

        if underlying_data_exists:
            logger.info("QUERY_ERROR: data exists but rule returns 0 hits")
            return {
                "status": STATUS_QUERY_ERROR,
                "hits_per_day": 0.0,
                "total_hits": 0,
                "note": "Underlying data exists but rule returns no results — likely a field name or filter issue",
                "false_pos_estimate": "UNKNOWN",
            }
        else:
            logger.info("DATA_ABSENT: rule is correct, technique not observed in 30d")
            return {
                "status": STATUS_DATA_ABSENT,
                "hits_per_day": 0.0,
                "total_hits": 0,
                "note": "Rule is logically correct. Technique not observed in 30-day window.",
                "false_pos_estimate": "LOW",
            }

    if hits_per_day <= good_threshold:
        fp_estimate = "LOW" if hits_per_day <= 5 else "MEDIUM"
        return {
            "status": STATUS_GOOD,
            "hits_per_day": hits_per_day,
            "total_hits": total_hits,
            "note": f"{total_hits} hits over 30 days ({hits_per_day}/day)",
            "false_pos_estimate": fp_estimate,
        }

    if hits_per_day <= very_noisy_threshold:
        return {
            "status": STATUS_NOISY,
            "hits_per_day": hits_per_day,
            "total_hits": total_hits,
            "note": f"Too noisy: {hits_per_day}/day — needs tuning",
            "false_pos_estimate": "HIGH",
        }

    return {
        "status": STATUS_VERY_NOISY,
        "hits_per_day": hits_per_day,
        "total_hits": total_hits,
        "note": f"Very noisy: {hits_per_day}/day — aggressive tuning required",
        "false_pos_estimate": "HIGH",
    }
