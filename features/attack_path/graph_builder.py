"""Attack path graph — networkx directed graph from ATT&CK kill chains."""
from dataclasses import dataclass, field

import networkx as nx

from core.intelligence.kill_chain_mapper import (
    THREAT_ACTOR_CHAINS,
    ActorChainResult,
    score_all_actors,
)

NODE_COLORS = {
    "COVERED": "#2ecc71",   # green
    "GAP":     "#e74c3c",   # red
    "BROKEN":  "#f39c12",   # orange
}


@dataclass
class GraphNode:
    technique_id: str
    technique_name: str
    tactic: str
    status: str
    color: str
    actors: list[str] = field(default_factory=list)


@dataclass
class AttackPathGraph:
    industry: str
    nodes: dict[str, GraphNode]
    edges: list[tuple[str, str, str]]    # (src, dst, actor)
    actor_results: list[ActorChainResult]
    coverage_pct: float
    total_exposure_usd: float


def build_attack_graph(
    industry: str,
    coverage_map: dict,
    broken_rule_techniques: set[str],
    gap_list: list[dict],
    attack_loader,
) -> AttackPathGraph:
    actor_results = score_all_actors(industry, coverage_map, broken_rule_techniques, attack_loader)

    nodes: dict[str, GraphNode] = {}
    edges: list[tuple[str, str, str]] = []

    exposure_by_tech = {g["technique_id"]: g.get("financial_exposure_usd", 0) for g in gap_list}

    for result in actor_results:
        prev_id = None
        for step in result.chain:
            tid = step.technique_id
            if tid not in nodes:
                nodes[tid] = GraphNode(
                    technique_id=tid,
                    technique_name=step.technique_name,
                    tactic=step.tactic,
                    status=step.status,
                    color=NODE_COLORS.get(step.status, "#95a5a6"),
                    actors=[result.actor],
                )
            else:
                if result.actor not in nodes[tid].actors:
                    nodes[tid].actors.append(result.actor)
                # Downgrade: COVERED < BROKEN < GAP
                if step.status == "GAP" or (step.status == "BROKEN" and nodes[tid].status == "COVERED"):
                    nodes[tid].status = step.status
                    nodes[tid].color = NODE_COLORS.get(step.status, "#95a5a6")

            if prev_id:
                edges.append((prev_id, tid, result.actor))
            prev_id = tid

    G = nx.DiGraph()
    G.add_nodes_from(nodes.keys())
    G.add_edges_from([(e[0], e[1]) for e in edges])

    covered = sum(1 for n in nodes.values() if n.status == "COVERED")
    total = len(nodes)
    coverage_pct = round(covered / total * 100, 1) if total else 0.0
    total_exposure = sum(exposure_by_tech.get(tid, 0) for tid, n in nodes.items() if n.status == "GAP")

    return AttackPathGraph(
        industry=industry,
        nodes=nodes,
        edges=edges,
        actor_results=actor_results,
        coverage_pct=coverage_pct,
        total_exposure_usd=total_exposure,
    )


def to_api_dict(graph: AttackPathGraph) -> dict:
    return {
        "industry": graph.industry,
        "coverage_pct": graph.coverage_pct,
        "total_gap_exposure_usd": graph.total_exposure_usd,
        "nodes": [
            {
                "id": n.technique_id,
                "name": n.technique_name,
                "tactic": n.tactic,
                "status": n.status,
                "color": n.color,
                "actors": n.actors,
            }
            for n in graph.nodes.values()
        ],
        "edges": [
            {"source": e[0], "target": e[1], "actor": e[2]}
            for e in graph.edges
        ],
        "actors": [
            {
                "name": r.actor,
                "coverage_pct": r.coverage_pct,
                "covered": r.covered_count,
                "total_steps": r.total_steps,
                "longest_blind_window": r.longest_blind_window,
                "min_viable_detection": r.min_viable_detection,
                "critical_path": r.critical_path,
                "chain": [
                    {
                        "step": s.step,
                        "technique_id": s.technique_id,
                        "technique_name": s.technique_name,
                        "tactic": s.tactic,
                        "status": s.status,
                    }
                    for s in r.chain
                ],
            }
            for r in graph.actor_results
        ],
    }
