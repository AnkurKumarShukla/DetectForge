"""Single MCP client — Splunk MCP Server v1.2 using JSON-RPC 2.0 over HTTP."""
import logging
import uuid
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
    """MCP client using JSON-RPC 2.0 as required by Splunk MCP Server v1.2."""

    def __init__(self):
        settings = get_settings()
        self._endpoint = settings.mcp_endpoint.rstrip("/")
        self._token = settings.mcp_token
        self._timeout = 120.0

    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._token}",
        }

    def _call(self, tool_name: str, arguments: dict) -> dict:
        """Call a tool via JSON-RPC 2.0 (MCP tools/call method)."""
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        try:
            with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
                resp = client.post(
                    self._endpoint,
                    json=payload,
                    headers=self._headers(),
                )
            resp.raise_for_status()
            data = resp.json()

            if "error" in data:
                raise RuntimeError(f"MCP error {data['error'].get('code')}: {data['error'].get('message')}")

            return data.get("result", {})
        except httpx.TimeoutException:
            logger.error("MCP timeout calling %s", tool_name)
            raise
        except httpx.HTTPStatusError as e:
            logger.error("MCP HTTP %s calling %s: %s", e.response.status_code, tool_name, e.response.text[:300])
            raise

    def list_tools(self) -> list[dict]:
        """List all available MCP tools — use to verify connection and see what's available."""
        payload = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "tools/list", "params": {}}
        with httpx.Client(timeout=30, follow_redirects=False) as client:
            resp = client.post(self._endpoint, json=payload, headers=self._headers())
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")
        return data.get("result", {}).get("tools", [])

    # ── Core MCP tools ──────────────────────────────────────────────────────

    def run_query(self, spl: str, earliest: str = "-30d", latest: str = "now", max_results: int = 10000) -> QueryResult:
        raw = self._call("splunk_run_splunk_query", {
            "query": spl,
            "earliest_time": earliest,
            "latest_time": latest,
            "max_count": max_results,
        })
        # MCP result comes back as content array — extract the data
        content = raw.get("content", [])
        result_data = {}
        for item in content:
            if item.get("type") == "text":
                import json as _json
                try:
                    result_data = _json.loads(item["text"])
                except Exception:
                    pass

        results = result_data.get("results", [])
        return QueryResult(
            count=int(result_data.get("result_count", len(results))),
            results=results,
            messages=result_data.get("messages", []),
            raw=result_data,
        )

    def get_indexes(self) -> list[IndexInfo]:
        raw = self._call("splunk_get_indexes", {})
        content = _extract_content(raw)
        indexes = []
        for item in content.get("indexes", []):
            indexes.append(IndexInfo(
                name=item.get("name", ""),
                total_event_count=item.get("totalEventCount", 0),
                current_size_mb=item.get("currentSizeMB", 0.0),
                metadata=item,
            ))
        return indexes

    def get_splunk_info(self) -> dict:
        raw = self._call("splunk_get_splunk_info", {})
        return _extract_content(raw)

    def discover_knowledge_objects(self, ko_type: str = "savedsearches", filter_tag: str = "") -> list[KnowledgeObject]:
        args: dict[str, Any] = {"type": ko_type}
        if filter_tag:
            args["filter"] = f'tags="{filter_tag}"'
        raw = self._call("splunk_discover_knowledge_objects", args)
        content = _extract_content(raw)
        objects = []
        for item in content.get("objects", []):
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
        args = {"prompt": prompt}
        if context:
            args["context"] = context
        raw = self._call("saia_generate_spl", args)
        content = _extract_content(raw)
        return content.get("spl", content.get("result", ""))

    def explain_spl(self, spl: str) -> str:
        raw = self._call("saia_explain_spl", {"spl": spl})
        content = _extract_content(raw)
        return content.get("explanation", content.get("result", ""))

    def optimize_spl(self, spl: str, issue: str, hits_per_day: float) -> str:
        raw = self._call("saia_optimize_spl", {
            "spl": spl,
            "issue": issue,
            "hits_per_day": hits_per_day,
        })
        content = _extract_content(raw)
        return content.get("optimized_spl", content.get("result", spl))

    def ask_question(self, question: str, context: dict | None = None) -> str:
        args = {"question": question}
        if context:
            args["context"] = context
        raw = self._call("saia_ask_splunk_question", args)
        content = _extract_content(raw)
        return content.get("answer", content.get("result", ""))

    # ── Convenience helpers ───────────────────────────────────────────────

    def check_sourcetype_exists(self, sourcetype: str, index: str = "*", lookback: str = "-30d") -> bool:
        result = self.run_query(
            f'| metadata type=sourcetypes index={index} | where sourcetype="{sourcetype}"',
            earliest=lookback,
        )
        return result.count > 0

    def check_field_exists(self, field: str, sourcetype: str, index: str, lookback: str = "-1h") -> bool:
        result = self.run_query(
            f'index={index} sourcetype="{sourcetype}" {field}=* | head 1 | stats count',
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
            f'index={index} sourcetype="{sourcetype}" | head {sample_size} | fieldsummary | fields field',
            earliest="-7d",
        )
        return [r.get("field", "") for r in result.results if r.get("field")]


def _extract_content(raw: dict) -> dict:
    """Extract JSON data from MCP content array response."""
    import json as _json
    content = raw.get("content", [])
    for item in content:
        if item.get("type") == "text":
            try:
                return _json.loads(item["text"])
            except Exception:
                pass
    return raw
