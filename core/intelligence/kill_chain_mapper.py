"""Kill chain mapper — threat actor chains per industry, coverage scoring."""
from dataclasses import dataclass, field

THREAT_ACTOR_CHAINS: dict[str, dict[str, list[str]]] = {
    "healthcare": {
        "ALPHV/BlackCat": ["T1566", "T1078", "T1021", "T1003", "T1486"],
        "Vice Society":   ["T1566", "T1204", "T1059", "T1003", "T1486"],
        "TA505":          ["T1566", "T1204", "T1059", "T1055", "T1021"],
    },
    "finance": {
        "FIN7":           ["T1566", "T1059.001", "T1055", "T1003", "T1021"],
        "Lazarus Group":  ["T1190", "T1059", "T1078", "T1070", "T1105"],
        "Carbanak":       ["T1566", "T1059", "T1021", "T1003", "T1070"],
    },
    "energy": {
        "Volt Typhoon":   ["T1190", "T1133", "T1078", "T1562", "T1070", "T1105"],
        "Sandworm":       ["T1190", "T1059", "T1562", "T1070", "T1486"],
    },
    "technology": {
        "APT41":          ["T1190", "T1059", "T1078", "T1055", "T1070", "T1021"],
        "UNC3944":        ["T1078", "T1566", "T1110", "T1059", "T1021"],
    },
}


@dataclass
class ChainStep:
    technique_id: str
    technique_name: str
    step: int
    status: str          # COVERED | GAP | BROKEN
    tactic: str = ""


@dataclass
class ActorChainResult:
    actor: str
    industry: str
    chain: list[ChainStep]
    coverage_pct: float
    covered_count: int
    total_steps: int
    longest_blind_window: int   # consecutive GAP steps
    min_viable_detection: str | None   # first GAP technique_id
    critical_path: list[str]    # longest consecutive GAP sequence


def score_actor_chain(
    actor: str,
    industry: str,
    coverage_map: dict,
    broken_rule_techniques: set[str],
    attack_loader,
) -> ActorChainResult:
    chain_techniques = THREAT_ACTOR_CHAINS.get(industry, {}).get(actor, [])
    steps: list[ChainStep] = []

    for i, tid in enumerate(chain_techniques, start=1):
        tech = attack_loader.get_technique(tid)
        name = tech.name if tech else tid
        tactic = (tech.tactics[0] if tech and tech.tactics else "")

        if tid in broken_rule_techniques:
            status = "BROKEN"
        elif tid in coverage_map:
            status = "COVERED"
        else:
            status = "GAP"

        steps.append(ChainStep(
            technique_id=tid,
            technique_name=name,
            step=i,
            status=status,
            tactic=tactic,
        ))

    covered = sum(1 for s in steps if s.status == "COVERED")
    total = len(steps)
    coverage_pct = round(covered / total * 100, 1) if total else 0.0

    # Find longest consecutive GAP window
    max_window = 0
    current = 0
    critical_start = 0
    best_start = 0
    for s in steps:
        if s.status == "GAP":
            current += 1
            if current > max_window:
                max_window = current
                best_start = critical_start
        else:
            current = 0
            critical_start = s.step  # next index

    critical_path = [
        s.technique_id for s in steps
        if s.step > best_start and s.status == "GAP"
    ][:max_window]

    min_viable = next((s.technique_id for s in steps if s.status == "GAP"), None)

    return ActorChainResult(
        actor=actor,
        industry=industry,
        chain=steps,
        coverage_pct=coverage_pct,
        covered_count=covered,
        total_steps=total,
        longest_blind_window=max_window,
        min_viable_detection=min_viable,
        critical_path=critical_path,
    )


def score_all_actors(
    industry: str,
    coverage_map: dict,
    broken_rule_techniques: set[str],
    attack_loader,
) -> list[ActorChainResult]:
    actors = THREAT_ACTOR_CHAINS.get(industry, {})
    results = []
    for actor in actors:
        result = score_actor_chain(actor, industry, coverage_map, broken_rule_techniques, attack_loader)
        results.append(result)
    results.sort(key=lambda r: r.coverage_pct)
    return results
