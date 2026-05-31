"""ATT&CK classification and SPL review — powered by Together AI (Llama 3.3 70B).

Foundation-sec is not available on Splunk Enterprise; Llama 3.3 70B handles
the same jobs: SPL → ATT&CK mapping and security logic validation.
"""
import json
import logging
import re

from openai import OpenAI

from core.config import get_settings

logger = logging.getLogger(__name__)

TOGETHER_BASE_URL = "https://api.together.xyz/v1"

CLASSIFY_SYSTEM = """You are a security detection engineer with deep expertise in MITRE ATT&CK v15.
Given a Splunk saved search name and SPL query, identify which ATT&CK technique it detects.
Respond ONLY with valid JSON — no explanation, no markdown fences:
{
  "technique_id": "T1234" or "T1234.001" or null,
  "technique_name": "Name of technique" or null,
  "tactic": "Tactic name" or null,
  "confidence": 0.0-1.0,
  "reasoning": "One sentence explaining the mapping",
  "coverage_quality": "high|medium|low",
  "coverage_gaps": "What this rule misses (brief)"
}"""

REVIEW_SYSTEM = """You are a security detection engineer reviewing SPL detection logic.
Assess whether the given SPL correctly detects the specified MITRE ATT&CK technique.
Respond ONLY with valid JSON — no explanation, no markdown fences:
{
  "approved": true or false,
  "confidence": 0.0-1.0,
  "issues": ["issue1", "issue2"],
  "suggestions": ["improvement1"]
}"""


class FoundationSecClient:
    """ATT&CK classification and SPL review via Together AI Llama 3.3 70B."""

    def __init__(self):
        settings = get_settings()
        self._client = OpenAI(
            api_key=settings.together_api_key,
            base_url=TOGETHER_BASE_URL,
        )
        self._model = settings.together_model

    def _call(self, system: str, user_content: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_content},
            ],
            max_tokens=512,
            temperature=0.1,
        )
        return response.choices[0].message.content

    def _parse_json(self, raw: str) -> dict:
        raw = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if match:
                return json.loads(match.group())
            raise ValueError(f"Could not parse JSON: {raw[:200]}")

    def classify_rule(self, name: str, spl: str) -> dict:
        """Map an existing Splunk saved search to a MITRE ATT&CK technique."""
        try:
            raw = self._call(CLASSIFY_SYSTEM, f"Search name: {name}\n\nSPL:\n{spl}")
            result = self._parse_json(raw)
            return {
                "technique_id": result.get("technique_id"),
                "technique_name": result.get("technique_name"),
                "tactic": result.get("tactic"),
                "confidence": float(result.get("confidence", 0.0)),
                "reasoning": result.get("reasoning", ""),
                "coverage_quality": result.get("coverage_quality", "unknown"),
                "coverage_gaps": result.get("coverage_gaps", ""),
            }
        except Exception as e:
            logger.error("classify_rule failed for '%s': %s", name, e)
            return {
                "technique_id": None, "technique_name": None, "tactic": None,
                "confidence": 0.0, "reasoning": f"Failed: {e}",
                "coverage_quality": "unknown", "coverage_gaps": "",
            }

    def review_spl_logic(self, spl: str, technique_id: str, technique_name: str, tactic: str) -> dict:
        """Validate that generated SPL correctly targets the specified ATT&CK technique."""
        user_content = (
            f"Technique: {technique_id} — {technique_name}\n"
            f"Tactic: {tactic}\n\nSPL:\n{spl}"
        )
        try:
            raw = self._call(REVIEW_SYSTEM, user_content)
            result = self._parse_json(raw)
            return {
                "approved": bool(result.get("approved", False)),
                "confidence": float(result.get("confidence", 0.0)),
                "issues": result.get("issues", []),
                "suggestions": result.get("suggestions", []),
            }
        except Exception as e:
            logger.error("review_spl_logic failed: %s", e)
            return {
                "approved": False, "confidence": 0.0,
                "issues": [f"Review failed: {e}"], "suggestions": [],
            }
