# -*- coding: utf-8 -*-
"""공격 경로 엔진 (SPEC 10장).

**단순 최단 경로가 아니다** (SPEC 10.1). 각 엣지의 전제조건을 **능력 상태 전이**로
평가한다. 탐색 상태는 `(노드, 보유 능력 집합)` 이며, 같은 노드라도 능력이 다르면
다른 상태다.

**ADR-014**: 경로의 모든 엣지가 observed 일 때만 도달성이 확정(TRUE)된다.
추론 엣지가 섞이면 경로는 존재하되 상태는 UNKNOWN 이다.

경로 확신도 = **가장 약한 핵심 엣지** × 증거 신선도 (SPEC 10.1).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from .capability import CONTROL_WRITE, NETWORK, describe
from .logic import Tri
from .model import parse_ts
from .topology import INFERRED, OBSERVED, UNKNOWN, Edge, Node, Topology

MAX_HOPS = 5      # NFR-PERF-002 의 전제
MAX_PATHS = 500   # 경로 열거는 지수적이다 — 결정적으로 자른다 (R11 그래프 과밀)

# 경로 상태 — 엣지 상태에서 파생된다
PATH_CONFIRMED = "confirmed"    # 모든 엣지 observed
PATH_INFERRED = "inferred"      # inferred 가 섞임
PATH_UNKNOWN = "unknown"        # unknown 엣지가 섞임

PATH_PHRASES = {
    PATH_CONFIRMED: "확인된 경로",
    PATH_INFERRED: "추론 경로",
    PATH_UNKNOWN: "정보 부족 경로",
}


@dataclass(frozen=True)
class Hop:
    edge: Edge
    caps_after: FrozenSet[str]

    def describe(self) -> str:
        return "%s --%s--> %s  [%s]  능력: %s" % (
            self.edge.src, self.edge.label, self.edge.dst,
            self.edge.status, describe(self.caps_after),
        )


@dataclass(frozen=True)
class AttackPath:
    entry: str
    target: str
    hops: Tuple[Hop, ...]
    status: str
    confidence: float
    weakest: Optional[Edge]

    @property
    def edge_keys(self) -> Tuple[str, ...]:
        return tuple(h.edge.key for h in self.hops)

    @property
    def nodes(self) -> Tuple[str, ...]:
        return (self.entry,) + tuple(h.edge.dst for h in self.hops)

    @property
    def is_confirmed(self) -> bool:
        return self.status == PATH_CONFIRMED


def _freshness(edge: Edge, as_of_date: Optional[date]) -> float:
    """증거가 오래될수록 확신도를 깎는다 (SPEC 10.1)."""
    obs = parse_ts(edge.evidence.get("observed_at"))
    if obs is None or as_of_date is None:
        return 0.5
    days = (as_of_date - obs).days
    if days <= 30:
        return 1.0
    if days <= 90:
        return 0.9
    if days <= 365:
        return 0.7
    return 0.4


def _path_status(edges: Sequence[Edge]) -> str:
    if any(e.status == UNKNOWN for e in edges):
        return PATH_UNKNOWN
    if any(e.status == INFERRED for e in edges):
        return PATH_INFERRED
    return PATH_CONFIRMED


def _score(edges: Sequence[Edge], as_of_date) -> Tuple[float, Optional[Edge]]:
    """가장 약한 핵심 엣지가 경로 확신도를 결정한다."""
    worst, worst_edge = 1.0, None
    for e in edges:
        base = float(e.evidence.get("confidence", 0.0) or 0.0)
        val = base * _freshness(e, as_of_date)
        if val <= worst:
            worst, worst_edge = val, e
    return round(worst, 4), worst_edge


def find_paths(
    topo: Topology,
    target_id: str,
    as_of: Optional[str] = None,
    max_hops: int = MAX_HOPS,
    entry_ids: Optional[Sequence[str]] = None,
    max_paths: int = MAX_PATHS,
    stop_on_confirmed: bool = False,
) -> Tuple[AttackPath, ...]:
    """진입점에서 target 까지의 공격 경로를 능력 상태 전이로 탐색한다.

    `stop_on_confirmed=True` 면 확인 경로를 하나 찾는 즉시 멈춘다 — 도달성
    판정에는 존재 여부만 필요하고 전수 열거는 필요 없다.
    """
    as_of_date = parse_ts(as_of) if as_of else None
    entries = [topo.nodes[e] for e in entry_ids] if entry_ids else list(topo.entry_points)

    results: List[AttackPath] = []
    for entry in sorted(entries, key=lambda n: n.node_id):
        # 상한·조기 종료는 진입점 루프 바깥에서도 지켜져야 한다
        if len(results) >= max_paths:
            break
        if stop_on_confirmed and any(p.is_confirmed for p in results):
            break
        # 상태 = (노드, 능력) — 같은 노드도 능력이 다르면 다시 방문한다
        start = (entry.node_id, frozenset({NETWORK}))
        stack: List[Tuple[Tuple[str, FrozenSet[str]], List[Hop]]] = [(start, [])]
        seen = {start}

        while stack:
            (node_id, caps), hops = stack.pop()
            if len(hops) >= max_hops:
                continue

            for edge in topo.out_edges(node_id):  # 인덱스가 key 순으로 정렬해 둔다
                # 전제조건: 요구 능력을 이미 갖고 있어야 지나갈 수 있다
                if not set(edge.requires) <= caps:
                    continue
                if any(h.edge.key == edge.key for h in hops):
                    continue  # 같은 엣지 재사용 금지 (순환 방지)

                new_caps = caps | set(edge.grants)
                new_hops = hops + [Hop(edge, frozenset(new_caps))]

                if edge.dst == target_id:
                    edges = [h.edge for h in new_hops]
                    conf, weakest = _score(edges, as_of_date)
                    status = _path_status(edges)
                    results.append(
                        AttackPath(
                            entry=entry.node_id,
                            target=target_id,
                            hops=tuple(new_hops),
                            status=status,
                            confidence=conf,
                            weakest=weakest,
                        )
                    )
                    if stop_on_confirmed and status == PATH_CONFIRMED:
                        stack = []
                        break
                    if len(results) >= max_paths:
                        stack = []
                        break
                    continue

                state = (edge.dst, frozenset(new_caps))
                if state not in seen:
                    seen.add(state)
                    stack.append((state, new_hops))

    # 결정적 정렬: 확인된 경로 우선, 짧은 것 우선, 확신도 높은 것 우선
    order = {PATH_CONFIRMED: 0, PATH_INFERRED: 1, PATH_UNKNOWN: 2}
    return tuple(sorted(
        results,
        key=lambda p: (order[p.status], len(p.hops), -p.confidence, p.edge_keys),
    ))


# --------------------------------------------------------------------------
# 도달성 평가 — 슬라이스 2 의 P? 를 푸는 자리 (ADR-014)
# --------------------------------------------------------------------------
@dataclass
class Reachability:
    verdict: Tri
    confirmed_paths: Tuple[AttackPath, ...]
    unconfirmed_paths: Tuple[AttackPath, ...]
    blocking_edges: Tuple[Edge, ...]
    reason: str


def evaluate_reachability(
    topo: Optional[Topology],
    asset_id: str,
    as_of: Optional[str] = None,
    require_capability: Optional[str] = None,
) -> Reachability:
    """자산이 진입점에서 도달 가능한가.

    ADR-014 의 반환 규칙:
      모든 엣지 observed 경로 있음                 → TRUE
      경로는 있으나 inferred/unknown 섞임          → UNKNOWN (막는 엣지 지목)
      그래프에 자산이 있고 어떤 경로도 없음          → FALSE
      그래프에 자산이 아예 없음                     → UNKNOWN  ← false safe 방지
    """
    if topo is None:
        return Reachability(Tri.UNKNOWN, (), (), (), "토폴로지가 로드되지 않음")

    node = topo.node_for_asset(asset_id)
    if node is None:
        return Reachability(
            Tri.UNKNOWN, (), (), (),
            "이 자산이 토폴로지에 없습니다 — 도달 불가로 단정하지 않습니다",
        )

    paths = find_paths(topo, node.node_id, as_of=as_of)
    if require_capability:
        paths = tuple(
            p for p in paths
            if p.hops and require_capability in p.hops[-1].caps_after
        )

    confirmed = tuple(p for p in paths if p.is_confirmed)
    others = tuple(p for p in paths if not p.is_confirmed)

    if confirmed:
        return Reachability(
            Tri.TRUE, confirmed, others, (),
            "관측 엣지만으로 이루어진 경로 %d개" % len(confirmed),
        )
    if others:
        blocking = []
        for p in others:
            for h in p.hops:
                if h.edge.status != OBSERVED and h.edge not in blocking:
                    blocking.append(h.edge)
        return Reachability(
            Tri.UNKNOWN, (), others, tuple(blocking),
            "경로 %d개가 있으나 모두 추론·미상 엣지를 포함합니다 (추론은 확정으로 승격하지 않습니다)"
            % len(others),
        )
    return Reachability(
        Tri.FALSE, (), (), (),
        "토폴로지상 진입점에서 도달하는 경로가 없습니다",
    )


# --------------------------------------------------------------------------
# 가상 차단 (FR-PATH-003, ADR-017)
# --------------------------------------------------------------------------
@dataclass
class BlockingCandidate:
    edge: Edge
    paths_cut: int
    paths_remaining: int
    legitimate_flows_broken: int

    def describe(self) -> str:
        return "%s : 공격 경로 %d개 차단, 정상 통신 %d개 영향" % (
            self.edge.key, self.paths_cut, self.legitimate_flows_broken)


def blocking_candidates(
    topo: Topology,
    target_ids: Sequence[str],
    as_of: Optional[str] = None,
    top: int = 3,
) -> Tuple[BlockingCandidate, ...]:
    """엣지 하나를 끊었을 때 사라지는 공격 경로와 깨지는 정상 통신을 센다.

    **점수를 만들지 않는다** (설계 원칙 P6). 정수 두 개가 "왜 이 차단점인가"에
    직접 답한다 — 가중 합산 점수는 답하지 못한다.
    """
    baseline: Dict[str, Tuple[AttackPath, ...]] = {
        t: find_paths(topo, t, as_of=as_of) for t in target_ids
    }
    total_before = sum(len(v) for v in baseline.values())
    if total_before == 0:
        return ()

    # 후보는 실제로 어떤 공격 경로에 등장하는 엣지뿐이다
    used = []
    for paths in baseline.values():
        for p in paths:
            for h in p.hops:
                if h.edge.key not in [e.key for e in used]:
                    used.append(h.edge)

    out: List[BlockingCandidate] = []
    for edge in used:
        pruned = topo.without(edge.key)
        after = sum(len(find_paths(pruned, t, as_of=as_of)) for t in target_ids)
        broken = 1 if edge.legitimate else 0
        out.append(
            BlockingCandidate(
                edge=edge,
                paths_cut=total_before - after,
                paths_remaining=after,
                legitimate_flows_broken=broken,
            )
        )

    out.sort(key=lambda c: (-c.paths_cut, c.legitimate_flows_broken, c.edge.key))
    return tuple(out[:top])
