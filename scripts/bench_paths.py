# -*- coding: utf-8 -*-
"""NFR-PERF-002 실측: 5홉 / 10만 엣지 / p95 5초 이내.

ADR-002 의 Neo4j 미도입 결정에는 재검토 트리거가 걸려 있다 —
"실제 벤치마크에서 10만 엣지 5홉 p95 가 5초를 넘거나, 엣지가 100만 규모로 커질 때".
이 스크립트가 그 트리거를 실측으로 확인한다.

테스트가 아니라 스크립트다: wall-clock 을 읽으므로 otai/ 안에 둘 수 없다
(tests/test_store_and_determinism.py 의 가드가 otai/ 만 스캔한다).
"""
from __future__ import annotations

import io
import statistics
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from otai.paths import find_paths  # noqa: E402
from otai.topology import Edge, Node, Topology  # noqa: E402

LEVELS = [5.0, 4.0, 3.5, 3.0, 2.0, 1.0]


def build(n_edges: int) -> Topology:
    """계층형 합성 그래프. 레벨 간 팬아웃으로 엣지 수를 채운다."""
    per_level = 400
    nodes = {}
    for li, lvl in enumerate(LEVELS):
        for i in range(per_level):
            nid = "n%d_%d" % (li, i)
            nodes[nid] = Node(
                node_id=nid, node_type="server", purdue_level=lvl,
                zone="Z%d" % li, label=nid,
                is_entry_point=(li == 0 and i < 3),
                safety_criticality="high" if li == len(LEVELS) - 1 else None,
            )

    edges = []
    ev = {"method": "pcap", "observed_at": "2026-08-20T00:00:00Z", "confidence": 0.9}
    fanout = max(1, n_edges // (per_level * (len(LEVELS) - 1)))
    for li in range(len(LEVELS) - 1):
        for i in range(per_level):
            for k in range(fanout):
                dst = (i * 7 + k * 13) % per_level
                edges.append(Edge(
                    src="n%d_%d" % (li, i), dst="n%d_%d" % (li + 1, dst),
                    edge_type="can_reach", status="observed", protocol="tcp",
                    requires=("network",), grants=("network",), evidence=ev,
                ))
                if len(edges) >= n_edges:
                    break
            if len(edges) >= n_edges:
                break
        if len(edges) >= n_edges:
            break

    return Topology(nodes=nodes, edges=tuple(edges), provenance={"synthetic": True},
                    source_path="bench")


def main() -> int:
    for n_edges in (10_000, 50_000, 100_000):
        topo = build(n_edges)
        target = "n%d_%d" % (len(LEVELS) - 1, 0)
        samples = []
        for _ in range(5):
            t0 = time.perf_counter()
            paths = find_paths(topo, target, as_of="2026-09-09", max_hops=5)
            samples.append(time.perf_counter() - t0)
        p95 = sorted(samples)[int(len(samples) * 0.95) - 1]
        verdict = "OK" if p95 <= 5.0 else "초과 — ADR-002 재검토"
        print("엣지 %7d | 경로 %5d | p95 %6.2fs | %s"
              % (len(topo.edges), len(paths), p95, verdict))
    print()
    print("기준: NFR-PERF-002 = 5홉 / 10만 엣지 / p95 5초 이내")
    return 0


if __name__ == "__main__":
    sys.exit(main())
