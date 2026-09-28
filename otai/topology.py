# -*- coding: utf-8 -*-
"""토폴로지 그래프 모델 (표 21 관계, 표 20 입력).

엣지 상태 3종 — SPEC 10.1 / 그림 5 의 표시 규칙과 1:1 대응한다:
  observed  실선   실제 관측(PCAP·방화벽 설정·직접 확인)
  inferred  점선   규칙·도면에서 추론
  unknown   회색   정보 부족

**ADR-014**: 도달성은 모든 엣지가 observed 인 경로에서만 확정된다.
추론 엣지가 섞이면 UNKNOWN 을 유지한다 — 추론을 확정으로 승격시키는 것이
경로판 거짓 확신(R06)이다.

토폴로지는 합성이다 (ADR-013). 픽스처의 `provenance` 블록이 그 사실과 근거를
함께 싣는다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .safeio import bounded_json_load

OBSERVED = "observed"
INFERRED = "inferred"
UNKNOWN = "unknown"

EDGE_STATUS_PHRASES = {
    OBSERVED: "확인됨",
    INFERRED: "규칙 추론",
    UNKNOWN: "정보 부족",
}

# 표 21 의 관계
EDGE_TYPES = ("can_reach", "administers", "trusts", "controls", "depends_on")


@dataclass(frozen=True)
class Node:
    node_id: str
    node_type: str                  # external | network | server | workstation | plc | cell
    #: 5.0 4.0 3.5 3.0 2.0 1.0 0.0 — **`None` 은 미상이다.**
    #: 0.0 으로 기본값을 주면 모르는 노드가 전부 물리 제어 계층이 되고,
    #: `critical_nodes()` 가 그것을 안전 핵심 표적으로 센다. 캡처에서 만든
    #: 노드는 레벨을 모르므로 이 구분이 없으면 그래프가 거짓말을 한다.
    purdue_level: Optional[float]
    zone: Optional[str]
    label: str
    asset_id: Optional[str] = None          # 자산 픽스처와의 연결
    safety_criticality: Optional[str] = None
    is_entry_point: bool = False
    #: 이 노드를 어떻게 알게 됐는가. `Edge` 와 같은 자리다 — 캡처에서 온 노드는
    #: 제조사 단서와 종류 **힌트**를 여기 싣는다. 힌트를 `node_type` 으로
    #: 올리지 않는다 (추측을 사실로 만들지 않는다).
    evidence: dict = field(default_factory=dict)
    vendor_hint: Optional[str] = None

    @property
    def is_critical(self) -> bool:
        return self.safety_criticality == "high"


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    edge_type: str
    status: str                     # observed | inferred | unknown
    protocol: Optional[str] = None
    port: Optional[int] = None
    requires: Tuple[str, ...] = ()  # 지나려면 필요한 능력
    grants: Tuple[str, ...] = ()    # 지나면 얻는 능력
    controls: Tuple[str, ...] = ()  # ACL, MFA 등 통제
    legitimate: bool = False        # 정상 업무 통신인가 (차단 영향 계산용)
    evidence: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return "%s->%s:%s" % (self.src, self.dst, self.edge_type)

    @property
    def label(self) -> str:
        base = self.edge_type
        if self.protocol:
            base += " %s" % self.protocol
            if self.port:
                base += "/%d" % self.port
        return base


@dataclass
class Topology:
    nodes: Dict[str, Node]
    edges: Tuple[Edge, ...]
    provenance: dict
    source_path: str = ""
    _out: Optional[Dict[str, Tuple[Edge, ...]]] = None
    _in: Optional[Dict[str, Tuple[Edge, ...]]] = None

    # ---- 인덱스 ----------------------------------------------------------
    def _build_index(self):
        """인접 인덱스를 한 번만 만든다.

        엣지 전체를 선형 탐색하면 10만 엣지에서 경로 탐색이 사실상 멈춘다
        (scripts/bench_paths.py 가 이 문제를 잡았다). 엣지는 key 순으로
        정렬해 둬 탐색 순서가 결정적으로 유지되게 한다.
        """
        out: Dict[str, list] = {}
        inn: Dict[str, list] = {}
        for e in sorted(self.edges, key=lambda e: e.key):
            out.setdefault(e.src, []).append(e)
            inn.setdefault(e.dst, []).append(e)
        self._out = {k: tuple(v) for k, v in out.items()}
        self._in = {k: tuple(v) for k, v in inn.items()}

    def out_edges(self, node_id: str) -> Tuple[Edge, ...]:
        if self._out is None:
            self._build_index()
        return self._out.get(node_id, ())

    def in_edges(self, node_id: str) -> Tuple[Edge, ...]:
        if self._in is None:
            self._build_index()
        return self._in.get(node_id, ())

    @property
    def entry_points(self) -> Tuple[Node, ...]:
        return tuple(sorted((n for n in self.nodes.values() if n.is_entry_point),
                            key=lambda n: n.node_id))

    def node_for_asset(self, asset_id: str) -> Optional[Node]:
        for n in self.nodes.values():
            if n.asset_id == asset_id:
                return n
        return None

    def critical_nodes(self) -> Tuple[Node, ...]:
        """공정 영향의 종착점 — 안전 중요 자산 또는 물리 셀을 제어하는 노드."""
        out = set()
        for n in self.nodes.values():
            if n.is_critical:
                out.add(n.node_id)
        for e in self.edges:
            if e.edge_type == "controls" and e.dst in self.nodes:
                lvl = self.nodes[e.dst].purdue_level
                # 레벨 미상은 '제어 계층이 아니다' 도 '맞다' 도 아니다. 세지 않는다.
                # 세면 캡처에서 온 모든 노드가 안전 핵심 표적이 된다.
                if lvl is not None and lvl <= 0.0:
                    out.add(e.src)
        return tuple(sorted((self.nodes[i] for i in out), key=lambda n: n.node_id))

    def without(self, edge_key: str) -> "Topology":
        """가상 차단 — 엣지 하나를 제거한 사본 (FR-PATH-003)."""
        return Topology(
            nodes=self.nodes,
            edges=tuple(e for e in self.edges if e.key != edge_key),
            provenance=self.provenance,
            source_path=self.source_path,
        )


def unknown_level_nodes(topo: "Topology") -> Tuple[Node, ...]:
    """레벨 또는 구역을 모르는 노드. 화면이 '무엇을 물어야 하나' 로 쓴다."""
    return tuple(sorted((n for n in topo.nodes.values()
                         if n.purdue_level is None or not n.zone),
                        key=lambda n: n.node_id))


def load_topology(path) -> Topology:
    path = Path(path)
    # **`safeio` 를 거친다** (ADR-039). 캡처에서 만든 토폴로지를 사용자가 손으로
    # 고쳐 되돌려주는 흐름이 생겼으므로, 이 파일은 더 이상 1차 자료가 아니다.
    data = bounded_json_load(path)

    nodes = {}
    for n in data.get("nodes", ()):
        nodes[n["node_id"]] = Node(
            node_id=n["node_id"],
            node_type=n.get("node_type", ""),
            purdue_level=(None if n.get("purdue_level") is None
                          else float(n["purdue_level"])),
            zone=n.get("zone") or None,
            label=n.get("label", n["node_id"]),
            asset_id=n.get("asset_id"),
            safety_criticality=n.get("safety_criticality"),
            is_entry_point=bool(n.get("is_entry_point")),
            evidence=n.get("evidence") or {},
            vendor_hint=n.get("vendor_hint"),
        )

    edges = []
    for e in data.get("edges", ()):
        status = e.get("status", UNKNOWN)
        if status not in (OBSERVED, INFERRED, UNKNOWN):
            raise ValueError("알 수 없는 엣지 상태: %r" % status)
        edges.append(
            Edge(
                src=e["src"],
                dst=e["dst"],
                edge_type=e.get("edge_type", "can_reach"),
                status=status,
                protocol=e.get("protocol"),
                port=e.get("port"),
                requires=tuple(e.get("requires") or ()),
                grants=tuple(e.get("grants") or ()),
                controls=tuple(e.get("controls") or ()),
                legitimate=bool(e.get("legitimate")),
                evidence=e.get("evidence") or {},
            )
        )

    missing = {e.src for e in edges} | {e.dst for e in edges}
    missing -= set(nodes)
    if missing:
        raise ValueError("엣지가 참조하는 노드가 없습니다: %s" % sorted(missing))

    return Topology(
        nodes=nodes,
        edges=tuple(edges),
        provenance=data.get("provenance", {}),
        source_path=path.name,
    )
