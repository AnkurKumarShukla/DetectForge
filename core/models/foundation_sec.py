"""Foundation-sec-1.1-8b-instruct client via Splunk Hosted Models."""
import json
import logging
import re

import httpx

from core.config import get_settings

logger = logging.getLogger(__name__)

CLASSIFY_SYSTEM = """You are a security detection engineer with deep expertise in MITRE ATT&CK.
Given a Splunk saved search name and SPL query, identify which ATT&CK technique it detects.
Respond ONLY with valid JSON matching this exact schema:
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
Respond ONLY with valid JSON:
{
  "approved": true or false,
  "confidence": 0.0-1.0,
  "issues": ["issue1", "issue2"],
  "suggestions": ["improvement1"]
}"""


class FoundationSecClient:
    """Client for Foundation-sec-1.1-8b-instruct via Splunk Hosted Models API."""

    def __init__(self):
        settings = get_settings()
        self._mcp_endpoint = settings.mcp_endpoint.rstrip("/")
        self._token = settings.mcp_token
        self._timeout = 60.0

    def _call_model(self, system: str, user_content: str) -> str:
        """Call Foundation-sec via the Splunk hosted models endpoint."""
        payload = {
            "model": "foundation-sec-1.1-8b-instruct",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_content},
            ],
            "max_tokens": 512,
            "temperature": 0.1,
        }
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                f"{self._mcp_endpoint}/models/chat",
                json=payload,
                headers=headers,
            )
        resp.raise_for_status()
        data = resp.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    def _parse_json_response(self, raw: str) -> dict:
        # Strip markdown fences if present
        raw = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # Try to extract JSON object
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if match:
                return json.loads(match.group())
            raise ValueError(f"Could not parse JSON from Foundation-sec response: {raw[:200]}")

    def classify_rule(self, name: str, spl: str) -> dict:
        """Map an existing Splunk saved search to a MITRE ATT&CK technique."""
        user_content = f"Search name: {name}\n\nSPL:\n{spl}"
        try:
            raw = self._call_model(CLASSIFY_SYSTEM, user_content)
            result = self._parse_json_response(raw)
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
            logger.error("Foundation-sec classify_rule failed for '%s': %s", name, e)
            return {
                "technique_id": None,
                "technique_name": None,
                "tactic": None,
                "confidence": 0.0,
                "reasoning": f"Classification failed: {e}",
                "coverage_quality": "unknown",
                "coverage_gaps": "",
            }

    def review_spl_logic(self, spl: str, technique_id: str, technique_name: str, tactic: str) -> dict:
        """Validate that generated SPL correctly targets the specified ATT&CK technique."""
        user_content = (
            f"Technique: {technique_id} — {technique_name}\n"
            f"Tactic: {tactic}\n\n"
            f"SPL to review:\n{spl}"
        )
        try:
            raw = self._call_model(REVIEW_SYSTEM, user_content)
            result = self._parse_json_response(raw)
            return {
                "approved": bool(result.get("approved", False)),
                "confidence": float(result.get("confidence", 0.0)),
                "issues": result.get("issues", []),
                "suggestions": result.get("suggestions", []),
            }
        except Exception as e:
            logger.error("Foundation-sec review_spl_logic failed: %s", e)
            return {
                "approved": False,
                "confidence": 0.0,
                "issues": [f"Review failed: {e}"],
                "suggestions": [],
            }
