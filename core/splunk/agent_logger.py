"""Agent activity logger — ships DetectForge agent actions to Splunk via HEC.

Every phase the agent runs (scan, classify, prioritise, generate, validate,
tune, queue, deploy, drift) emits a structured event to the `detectforge`
index. The "DetectForge — Agent Activity" dashboard then shows live agent
reasoning/actions *inside Splunk* — the core "agentic ops" demo story.

Design constraints:
- Fire-and-forget and FAIL-SAFE: HEC being down, unconfigured, or slow must
  never break or stall the detection pipeline. Every send is best-effort and
  swallows its own errors (mirrored to the local logger so nothing is lost).
- Zero new dependencies — reuses httpx, already used by the REST client.
"""
import logging
import time
from datetime import datetime, timezone

import httpx

from core.config import get_settings

logger = logging.getLogger(__name__)


class AgentActivityLogger:
    """Best-effort HEC emitter for agent activity events."""

    def __init__(self):
        s = get_settings()
        self._enabled = s.hec_enabled and bool(s.hec_token)
        self._url = s.hec_url.rstrip("/") + "/services/collector/event"
        self._token = s.hec_token
        self._index = s.hec_index
        self._sourcetype = s.hec_sourcetype
        self._verify_ssl = s.splunk_verify_ssl
        self._timeout = 3.0  # short — never stall the pipeline on logging
        if not self._enabled:
            logger.info(
                "Agent activity HEC logger disabled (hec_enabled=%s, token set=%s). "
                "Events will be logged locally only.",
                s.hec_enabled, bool(s.hec_token),
            )

    def log(
        self,
        action: str,
        *,
        scan_id: str = "",
        phase: str = "",
        technique_id: str = "",
        technique_name: str = "",
        status: str = "",
        detail: str = "",
        severity: str = "info",
        **fields,
    ) -> None:
        """Emit one agent activity event. Never raises."""
        event = {
            "action": action,
            "phase": phase,
            "scan_id": scan_id,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "status": status,
            "detail": detail,
            "severity": severity,
            "ts": datetime.now(timezone.utc).isoformat(),
            **{k: v for k, v in fields.items() if v is not None},
        }
        # Always mirror locally so activity is captured even when HEC is off.
        logger.info("[agent-activity] %s %s %s %s",
                    phase or "-", action, technique_id or "-", status or "")

        if not self._enabled:
            return

        payload = {
            "time": time.time(),
            "host": "detectforge",
            "source": "detectforge:agent",
            "sourcetype": self._sourcetype,
            "index": self._index,
            "event": event,
        }
        try:
            with httpx.Client(verify=self._verify_ssl, timeout=self._timeout) as client:
                resp = client.post(
                    self._url,
                    json=payload,
                    headers={"Authorization": f"Splunk {self._token}"},
                )
            if resp.status_code >= 400:
                logger.warning("HEC rejected event (%s): %s", resp.status_code, resp.text[:200])
        except Exception as e:  # noqa: BLE001 — logging must never break the agent
            logger.debug("HEC send failed (non-fatal): %s", e)


_logger_singleton: AgentActivityLogger | None = None


def get_agent_logger() -> AgentActivityLogger:
    """Process-wide singleton so config is read once."""
    global _logger_singleton
    if _logger_singleton is None:
        _logger_singleton = AgentActivityLogger()
    return _logger_singleton
