"""NL interface — Together AI (OpenAI-compatible) for conversational coverage Q&A."""
import logging
from typing import Iterator

from openai import OpenAI

from core.config import get_settings
from core.splunk.mcp_client import SplunkMCPClient

logger = logging.getLogger(__name__)

TOGETHER_BASE_URL = "https://api.together.xyz/v1"

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
        self.client = OpenAI(
            api_key=settings.together_api_key,
            base_url=TOGETHER_BASE_URL,
        )
        self.model = settings.together_model

    def _build_coverage_context(self, coverage_map: dict, gaps: list[dict], industry: str) -> str:
        covered_count = len(coverage_map)
        top_gaps = gaps[:10]
        total_exposure = sum(g.get("financial_exposure_usd", 0) for g in top_gaps)

        lines = [
            f"Industry: {industry}",
            f"Techniques currently covered: {covered_count}",
            "Top gaps by financial exposure:",
        ]
        for g in top_gaps:
            lines.append(
                f"  - {g['technique_id']} ({g['technique_name']}): "
                f"${g.get('financial_exposure_usd', 0):,.0f}/yr exposure, "
                f"status={g.get('status', 'UNKNOWN')}"
            )
        lines.append(f"Total annual exposure for top gaps: ${total_exposure:,.0f}")
        return "\n".join(lines)

    def _build_messages(
        self,
        question: str,
        coverage_map: dict,
        gaps: list[dict],
        industry: str,
        conversation_history: list[dict] | None,
    ) -> list[dict]:
        coverage_ctx = self._build_coverage_context(coverage_map, gaps, industry)
        system_content = f"{NL_SYSTEM_PROMPT}\n\nCURRENT COVERAGE CONTEXT:\n{coverage_ctx}"

        messages = [{"role": "system", "content": system_content}]
        messages.extend(conversation_history or [])
        messages.append({"role": "user", "content": question})
        return messages

    def answer(
        self,
        question: str,
        coverage_map: dict,
        gaps: list[dict],
        industry: str,
        conversation_history: list[dict] | None = None,
    ) -> str:
        messages = self._build_messages(question, coverage_map, gaps, industry, conversation_history)
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=600,
                temperature=0.3,
            )
            answer_text = response.choices[0].message.content
            logger.info("NL answer generated for: %s...", question[:60])
            return answer_text
        except Exception as e:
            logger.error("NL interface (Together AI) failed: %s", e)
            return f"I encountered an error answering that question: {e}"

    def answer_stream(
        self,
        question: str,
        coverage_map: dict,
        gaps: list[dict],
        industry: str,
        conversation_history: list[dict] | None = None,
    ) -> Iterator[str]:
        messages = self._build_messages(question, coverage_map, gaps, industry, conversation_history)
        try:
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=600,
                temperature=0.3,
                stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    yield delta
        except Exception as e:
            logger.error("NL stream (Together AI) failed: %s", e)
            yield f"Error: {e}"
