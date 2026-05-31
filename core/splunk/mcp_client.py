"""Single MCP client for all Splunk MCP Server tool calls."""
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from core.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class QueryResult:
    count: int
    results: list[dict] = field(default_factory=list)
    messages: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class IndexInfo:
    name: str
    sourcetypes: list[str] = field(default_factory=list)
    total_event_count: int = 0
    current_size_mb: float = 0.0
    metadata: dict = field(default_factory=dict)


@dataclass
class KnowledgeObject:
    name: str
    spl: str
    type: str = "savedsearch"
    enabled: bool = True
    description: str = ""
    metadata: dict = field(default_factory=dict)


class SplunkMCPClient:
    """Thin wrapper around the Splunk MCP Server HTTP API."""

    def __init__(self):
        settings = get_settings()
        self._endpoint = settings.mcp_endpoint.rstrip("/")
        self._token = settings.mcp_token
        self._timeout = 120.0

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _call(self, tool: str, params: dict) -> dict:
        payload = {"tool": tool, "params": params}
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(
                    f"{self._endpoint}/call",
                    json=payload,
                    headers=self._headers(),
                )
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException:
            logger.error("MCP timeout calling %s", tool)
            raise
        except httpx.HTTPStatusError as e:
            logger.error("MCP HTTP error %s calling %s: %s", e.response.status_code, tool, e.response.text)
            raise

    # ── Core MCP tools ──────────────────────────────────────────────────────

    def run_query(self, spl: str, earliest: str = "-30d", latest: str = "now", max_results: int = 10000) -> QueryResult:
        raw = self._call("splunk_run_splunk_query", {
            "query": spl,
            "earliest_time": earliest,
            "latest_time": latest,
            "max_count": max_results,
        })
        results = raw.get("results", [])
        return QueryResult(
            count=int(raw.get("result_count", len(results))),
            results=results,
            messages=raw.get("messages", []),
            raw=raw,
        )

    def get_indexes(self) -> list[IndexInfo]:
        raw = self._call("splunk_get_indexes", {})
        indexes = []
        for item in raw.get("indexes", []):
            indexes.append(IndexInfo(
                name=item.get("name", ""),
                total_event_count=item.get("totalEventCount", 0),
                current_size_mb=item.get("currentSizeMB", 0.0),
                metadata=item,
            ))
        return indexes

    def get_splunk_info(self) -> dict:
        return self._call("splunk_get_splunk_info", {})

    def discover_knowledge_objects(self, ko_type: str = "savedsearches", filter_tag: str = "") -> list[KnowledgeObject]:
        params: dict[str, Any] = {"type": ko_type}
        if filter_tag:
            params["filter"] = f'tags="{filter_tag}"'
        raw = self._call("splunk_discover_knowledge_objects", params)
        objects = []
        for item in raw.get("objects", []):
            objects.append(KnowledgeObject(
                name=item.get("name", ""),
                spl=item.get("search", item.get("spl", "")),
                type=ko_type,
                enabled=item.get("disabled", "0") == "0",
                description=item.get("description", ""),
                metadata=item,
            ))
        return objects

    # ── AI Assistant tools (saia_* namespace) ───────────────────────────────

    def generate_spl(self, prompt: str, context: dict | None = None) -> str:
        params = {"prompt": prompt}
        if context:
            params["context"] = context
        raw = self._call("saia_generate_spl", params)
        return raw.get("spl", raw.get("result", ""))

    def explain_spl(self, spl: str) -> str:
        raw = self._call("saia_explain_spl", {"spl": spl})
        return raw.get("explanation", raw.get("result", ""))

    def optimize_spl(self, spl: str, issue: str, hits_per_day: float) -> str:
        raw = self._call("saia_optimize_spl", {
            "spl": spl,
            "issue": issue,
            "hits_per_day": hits_per_day,
        })
        return raw.get("optimized_spl", raw.get("result", spl))

    def ask_question(self, question: str, context: dict | None = None) -> str:
        params = {"question": question}
        if context:
            params["context"] = context
        raw = self._call("saia_ask_splunk_question", params)
        return raw.get("answer", raw.get("result", ""))

    # ── Convenience query helpers ─────────────────────────────────────────

    def check_sourcetype_exists(self, sourcetype: str, index: str = "*", lookback: str = "-30d") -> bool:
        result = self.run_query(
            f"| metadata type=sourcetypes index={index} "
            f"| where sourcetype=\"{sourcetype}\"",
            earliest=lookback,
        )
        return result.count > 0

    def check_field_exists(self, field: str, sourcetype: str, index: str, lookback: str = "-1h") -> bool:
        result = self.run_query(
            f"index={index} sourcetype=\"{sourcetype}\" {field}=* earliest={lookback} | head 1 | stats count",
            earliest=lookback,
        )
        return result.count > 0

    def get_sourcetypes_for_index(self, index: str) -> list[str]:
        result = self.run_query(
            f"| metadata type=sourcetypes index={index} | fields sourcetype",
            earliest="-30d",
        )
        return [r.get("sourcetype", "") for r in result.results if r.get("sourcetype")]

    def get_fields_for_sourcetype(self, sourcetype: str, index: str, sample_size: int = 100) -> list[str]:
        result = self.run_query(
            f"index={index} sourcetype=\"{sourcetype}\" | head {sample_size} | fieldsummary | fields field",
            earliest="-7d",
        )
        return [r.get("field", "") for r in result.results if r.get("field")]
