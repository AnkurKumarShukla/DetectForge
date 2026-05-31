"""Splunk REST API client for deployment operations."""
import logging
import urllib.parse

import httpx

from core.config import get_settings

logger = logging.getLogger(__name__)

SPLUNK_SEARCH_APP = "search"


class SplunkRestClient:
    """Thin wrapper around the Splunk REST API for creating/managing saved searches."""

    def __init__(self):
        settings = get_settings()
        self._base_url = settings.splunk_url.rstrip("/")
        self._token = settings.splunk_token
        self._username = settings.splunk_username
        self._password = settings.splunk_password
        self._verify_ssl = settings.splunk_verify_ssl
        self._timeout = 60.0

    def _auth(self):
        if self._token:
            return None  # use bearer token header
        return (self._username, self._password)

    def _headers(self) -> dict:
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{self._base_url}{path}"
        params = {**(params or {}), "output_mode": "json"}
        with httpx.Client(verify=self._verify_ssl, timeout=self._timeout) as client:
            resp = client.get(url, params=params, auth=self._auth(), headers={"Authorization": f"Bearer {self._token}"} if self._token else {})
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: dict) -> dict:
        url = f"{self._base_url}{path}"
        data["output_mode"] = "json"
        with httpx.Client(verify=self._verify_ssl, timeout=self._timeout) as client:
            resp = client.post(url, data=data, auth=self._auth(), headers=self._headers() if not self._token else {"Authorization": f"Bearer {self._token}", "Content-Type": "application/x-www-form-urlencoded"})
        resp.raise_for_status()
        return resp.json()

    def _delete(self, path: str) -> dict:
        url = f"{self._base_url}{path}"
        with httpx.Client(verify=self._verify_ssl, timeout=self._timeout) as client:
            resp = client.delete(url, auth=self._auth(), params={"output_mode": "json"})
        resp.raise_for_status()
        return resp.json()

    def create_saved_search(
        self,
        name: str,
        spl: str,
        description: str = "",
        technique_id: str = "",
        tactic: str = "",
        severity: str = "medium",
        industry: str = "",
        app: str = SPLUNK_SEARCH_APP,
    ) -> dict:
        """Deploy a detection rule as a saved search with DetectForge metadata tags."""
        tags = ["detectforge"]
        if technique_id:
            tags.append(f"mitre_{technique_id.lower().replace('.', '_')}")
        if tactic:
            tags.append(f"tactic_{tactic.lower().replace(' ', '_')}")
        tags.append(f"severity_{severity}")
        if industry:
            tags.append(f"industry_{industry}")

        data = {
            "name": name,
            "search": spl,
            "description": description,
            "is_scheduled": "1",
            "cron_schedule": "*/15 * * * *",
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "actions": "",
            "tags": ",".join(tags),
            "dispatch.earliest_time": "-15m",
            "dispatch.latest_time": "now",
        }
        path = f"/servicesNS/nobody/{app}/saved/searches"
        logger.info("Deploying saved search: %s", name)
        return self._post(path, data)

    def update_saved_search(self, name: str, spl: str, app: str = SPLUNK_SEARCH_APP) -> dict:
        encoded = urllib.parse.quote(name, safe="")
        path = f"/servicesNS/nobody/{app}/saved/searches/{encoded}"
        return self._post(path, {"search": spl})

    def delete_saved_search(self, name: str, app: str = SPLUNK_SEARCH_APP) -> dict:
        encoded = urllib.parse.quote(name, safe="")
        path = f"/servicesNS/nobody/{app}/saved/searches/{encoded}"
        return self._delete(path)

    def get_saved_search(self, name: str, app: str = SPLUNK_SEARCH_APP) -> dict | None:
        encoded = urllib.parse.quote(name, safe="")
        path = f"/servicesNS/nobody/{app}/saved/searches/{encoded}"
        try:
            return self._get(path)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise

    def list_saved_searches(self, app: str = SPLUNK_SEARCH_APP) -> list[dict]:
        path = f"/servicesNS/nobody/{app}/saved/searches"
        raw = self._get(path, {"count": 0})
        return raw.get("entry", [])

    def test_connectivity(self) -> bool:
        try:
            self._get("/services/server/info")
            return True
        except Exception as e:
            logger.error("Splunk REST connectivity test failed: %s", e)
            return False
