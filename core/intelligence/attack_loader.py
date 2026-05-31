"""MITRE ATT&CK loader — downloads enterprise-attack.json and indexes it."""
import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

ATTACK_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
LOCAL_CACHE = Path(__file__).parent.parent.parent / "knowledge" / "attack" / "enterprise-attack.json"


@dataclass
class Technique:
    id: str
    name: str
    tactics: list[str]
    description: str
    data_sources: list[str]
    platforms: list[str]
    is_subtechnique: bool
    parent_id: str | None
    url: str
    detection: str = ""
    kill_chain_phases: list[str] = field(default_factory=list)


class AttackLoader:
    def __init__(self):
        self._techniques: dict[str, Technique] = {}
        self._by_tactic: dict[str, list[Technique]] = {}
        self._loaded = False

    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        data = self._load_json()
        self._parse(data)
        self._loaded = True
        logger.info("ATT&CK loaded: %d techniques", len(self._techniques))

    def _load_json(self) -> dict:
        if LOCAL_CACHE.exists():
            logger.info("Loading ATT&CK from local cache: %s", LOCAL_CACHE)
            return json.loads(LOCAL_CACHE.read_text(encoding="utf-8"))

        logger.info("Downloading ATT&CK JSON from MITRE CTI...")
        LOCAL_CACHE.parent.mkdir(parents=True, exist_ok=True)
        with httpx.Client(timeout=120) as client:
            resp = client.get(ATTACK_JSON_URL)
        resp.raise_for_status()
        LOCAL_CACHE.write_bytes(resp.content)
        logger.info("ATT&CK JSON saved to %s", LOCAL_CACHE)
        return resp.json()

    def _parse(self, data: dict) -> None:
        objects = data.get("objects", [])

        tactic_names: dict[str, str] = {}
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                short = obj.get("x_mitre_shortname", "")
                name = obj.get("name", "")
                tactic_names[short] = name

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            ext_refs = obj.get("external_references", [])
            technique_id = next(
                (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"), None
            )
            if not technique_id:
                continue

            kill_chain = obj.get("kill_chain_phases", [])
            tactics = [tactic_names.get(p["phase_name"], p["phase_name"]) for p in kill_chain]
            tactic_shorts = [p["phase_name"] for p in kill_chain]

            is_sub = "." in technique_id
            parent_id = technique_id.split(".")[0] if is_sub else None

            data_sources = obj.get("x_mitre_data_sources", [])
            platforms = obj.get("x_mitre_platforms", [])

            url = next((r.get("url", "") for r in ext_refs if r.get("source_name") == "mitre-attack"), "")

            tech = Technique(
                id=technique_id,
                name=obj.get("name", ""),
                tactics=tactics,
                description=obj.get("description", ""),
                data_sources=data_sources,
                platforms=platforms,
                is_subtechnique=is_sub,
                parent_id=parent_id,
                url=url,
                detection=obj.get("x_mitre_detection", ""),
                kill_chain_phases=tactic_shorts,
            )
            self._techniques[technique_id] = tech
            for tactic in tactics:
                self._by_tactic.setdefault(tactic, []).append(tech)

    # ── Public API ────────────────────────────────────────────────────────

    def get_all_techniques(self) -> list[Technique]:
        self.ensure_loaded()
        return list(self._techniques.values())

    def get_technique(self, technique_id: str) -> Technique | None:
        self.ensure_loaded()
        return self._techniques.get(technique_id)

    def get_techniques_by_tactic(self, tactic: str) -> list[Technique]:
        self.ensure_loaded()
        return self._by_tactic.get(tactic, [])

    def get_all_tactic_names(self) -> list[str]:
        self.ensure_loaded()
        return list(self._by_tactic.keys())

    def technique_ids(self) -> set[str]:
        self.ensure_loaded()
        return set(self._techniques.keys())

    def get_technique_hash(self) -> str:
        self.ensure_loaded()
        ids = sorted(self._techniques.keys())
        return hashlib.md5("|".join(ids).encode()).hexdigest()


# Module-level singleton
_loader: AttackLoader | None = None


def get_attack_loader() -> AttackLoader:
    global _loader
    if _loader is None:
        _loader = AttackLoader()
    return _loader
