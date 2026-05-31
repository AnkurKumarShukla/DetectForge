"""Industry threat profiles and FAIR financial exposure model."""
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

PROFILES_DIR = Path(__file__).parent.parent.parent / "knowledge" / "profiles"

# Technique frequency in the wild (fraction of intrusions where technique appears)
# Source: Verizon DBIR 2025 + Red Canary Threat Detection Report 2025
TECHNIQUE_FREQUENCY: dict[str, float] = {
    "T1078": 0.82,  "T1003": 0.71,  "T1486": 0.68,  "T1059": 0.75,
    "T1021": 0.64,  "T1566": 0.79,  "T1055": 0.52,  "T1070": 0.61,
    "T1562": 0.48,  "T1190": 0.58,  "T1105": 0.45,  "T1036": 0.43,
    "T1110": 0.67,  "T1133": 0.39,  "T1204": 0.55,  "T1083": 0.38,
    "T1082": 0.41,  "T1016": 0.37,  "T1057": 0.35,  "T1012": 0.33,
    "T1003.001": 0.68, "T1059.001": 0.72, "T1059.003": 0.61,
    "T1021.001": 0.55, "T1021.002": 0.49, "T1110.001": 0.58,
    "T1547.001": 0.44, "T1053.005": 0.41,
}

# Blast radius score — impact if technique succeeds (0-1)
BLAST_RADIUS: dict[str, float] = {
    "T1003": 0.95, "T1003.001": 0.95, "T1486": 1.0, "T1078": 0.85,
    "T1021": 0.80, "T1055": 0.75, "T1562": 0.70, "T1070": 0.65,
    "T1059": 0.70, "T1566": 0.60, "T1190": 0.75, "T1110": 0.65,
    "T1133": 0.80, "T1105": 0.55, "T1036": 0.60, "T1204": 0.60,
}

# Industry-specific threat actor scores per technique (how much actors targeting this sector use it)
INDUSTRY_TECHNIQUE_SCORES: dict[str, dict[str, float]] = {
    "healthcare": {
        "T1078": 0.95, "T1003": 0.90, "T1003.001": 0.90, "T1486": 0.92,
        "T1021": 0.85, "T1566": 0.88, "T1055": 0.75, "T1070": 0.80,
        "T1562": 0.78, "T1110": 0.82, "T1133": 0.70, "T1059": 0.72,
    },
    "finance": {
        "T1078": 0.92, "T1059": 0.88, "T1059.001": 0.90, "T1055": 0.85,
        "T1190": 0.82, "T1566": 0.85, "T1003": 0.80, "T1021": 0.78,
        "T1070": 0.75, "T1110": 0.85, "T1133": 0.65, "T1036": 0.72,
    },
    "energy": {
        "T1133": 0.95, "T1078": 0.92, "T1562": 0.90, "T1070": 0.88,
        "T1190": 0.85, "T1105": 0.82, "T1059": 0.75, "T1021": 0.78,
        "T1003": 0.72, "T1036": 0.70, "T1083": 0.68, "T1082": 0.65,
    },
    "technology": {
        "T1078": 0.88, "T1190": 0.90, "T1059": 0.85, "T1055": 0.82,
        "T1003": 0.78, "T1070": 0.75, "T1562": 0.72, "T1566": 0.80,
        "T1133": 0.68, "T1021": 0.72, "T1036": 0.75, "T1110": 0.78,
    },
}

# Simplified FAIR model: avg breach cost by industry + data sensitivity (USD)
# Source: IBM Cost of a Data Breach Report 2025
BREACH_COST_USD: dict[str, float] = {
    "healthcare": 9_800_000,
    "finance": 6_100_000,
    "energy": 5_300_000,
    "technology": 4_900_000,
}

# Threat events per year by industry (fraction of orgs breached annually)
THREAT_EVENT_FREQUENCY: dict[str, float] = {
    "healthcare": 0.45,
    "finance": 0.38,
    "energy": 0.32,
    "technology": 0.35,
}

# Org size factor (fraction of sector attacks that land on a given org)
ORG_SIZE_FACTOR = 0.08


def get_industry_score(technique_id: str, industry: str) -> float:
    industry = industry.lower()
    scores = INDUSTRY_TECHNIQUE_SCORES.get(industry, {})

    # Try exact match, then parent technique
    score = scores.get(technique_id)
    if score is None and "." in technique_id:
        score = scores.get(technique_id.split(".")[0])
    return score if score is not None else 0.30


def get_technique_frequency(technique_id: str) -> float:
    freq = TECHNIQUE_FREQUENCY.get(technique_id)
    if freq is None and "." in technique_id:
        freq = TECHNIQUE_FREQUENCY.get(technique_id.split(".")[0])
    return freq if freq is not None else 0.20


def get_blast_radius(technique_id: str) -> float:
    br = BLAST_RADIUS.get(technique_id)
    if br is None and "." in technique_id:
        br = BLAST_RADIUS.get(technique_id.split(".")[0])
    return br if br is not None else 0.30


def calculate_priority_score(
    technique_id: str,
    industry: str,
    data_availability_score: float,
) -> float:
    freq = get_technique_frequency(technique_id)
    industry_score = get_industry_score(technique_id, industry)
    blast = get_blast_radius(technique_id)

    return (
        freq * 0.30
        + industry_score * 0.30
        + data_availability_score * 0.25
        + blast * 0.15
    )


def calculate_annual_exposure(technique_id: str, industry: str) -> float:
    industry = industry.lower()
    tef = THREAT_EVENT_FREQUENCY.get(industry, 0.30)
    breach_cost = BREACH_COST_USD.get(industry, 5_000_000)
    industry_score = get_industry_score(technique_id, industry)

    # Annualised Loss Expectancy = threat event freq × org size × industry relevance × breach cost
    ale = tef * ORG_SIZE_FACTOR * industry_score * breach_cost
    return round(ale, 2)


def load_industry_profile(industry: str) -> dict:
    path = PROFILES_DIR / f"{industry.lower()}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    logger.warning("Industry profile not found: %s, using defaults", industry)
    return {"threat_actors": [], "top_techniques": [], "sector_context": ""}
