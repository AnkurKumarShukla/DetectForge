"""NL interface — Claude (Anthropic Agent SDK) for conversational coverage Q&A."""
import json
import logging
from typing import AsyncIterator

import anthropic

from core.config import get_settings
from core.splunk.mcp_client import SplunkMCPClient

logger = logging.getLogger(__name__)

NL_SYSTEM_PROMPT = """You are DetectForge, an autonomous detection engineering assistant embedded in a Splunk SIEM.
You have access to the user's current ATT&CK coverage data and can query their Splunk environment.

When answering questions:
- Be specific and actionable — name exact technique IDs, tactics, and financial exposure numbers
- Use the provided coverage_context to give accurate answers
- If you can detect gaps or blind spots, explain the real-world attack scenario they enable
- Always offer to generate detection rules for identified gaps

Respond in plain, direct language. No markdown headers. Keep it under 300 words unless the user asks for detail."""


class NLCoverageResponder:
    def __init__(self, mcp: SplunkMCPClient):
        self.mcp = mcp
        settings = get_settings()
        self.client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    def _build_coverage_context(self, coverage_map: dict, gaps: list[dict], industry: str) -> str:
        covered_count = len(coverage_map)
        top_gaps = gaps[:10]
        total_exposure = sum(g.get("financial_exposure_usd", 0) for g in top_gaps)

        lines = [
            f"Industry: {industry}",
            f"Techniques covered: {covered_count}",
            f"Top gaps by exposure:",
        ]
        for g in top_gaps:
            lines.append(
                f"  - {g['technique_id']} ({g['technique_name']}): "
                f"${g.get('financial_exposure_usd', 0):,.0f}/yr exposure, "
                f"status={g.get('status', 'UNKNOWN')}"
            )
        lines.append(f"Total annual exposure for top gaps: ${total_exposure:,.0f}")
        return "\n".join(lines)

    def answer(
        self,
        question: str,
        coverage_map: dict,
        gaps: list[dict],
        industry: str,
        conversation_history: list[dict] | None = None,
    ) -> str:
        coverage_ctx = self._build_coverage_context(coverage_map, gaps, industry)
        system_with_context = f"{NL_SYSTEM_PROMPT}\n\nCURRENT COVERAGE CONTEXT:\n{coverage_ctx}"

        messages = list(conversation_history or [])
        messages.append({"role": "user", "content": question})

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=600,
                system=system_with_context,
                messages=messages,
            )
            answer_text = response.content[0].text
            logger.info("NL answer generated for question: %s...", question[:60])
            return answer_text
        except Exception as e:
            logger.error("NL interface failed: %s", e)
            return f"I encountered an error answering that question: {e}"

    async def answer_stream(
        self,
        question: str,
        coverage_map: dict,
        gaps: list[dict],
        industry: str,
        conversation_history: list[dict] | None = None,
    ) -> AsyncIterator[str]:
        coverage_ctx = self._build_coverage_context(coverage_map, gaps, industry)
        system_with_context = f"{NL_SYSTEM_PROMPT}\n\nCURRENT COVERAGE CONTEXT:\n{coverage_ctx}"

        messages = list(conversation_history or [])
        messages.append({"role": "user", "content": question})

        with self.client.messages.stream(
            model="claude-sonnet-4-6",
            max_tokens=600,
            system=system_with_context,
            messages=messages,
        ) as stream:
            for text in stream.text_stream:
                yield text
