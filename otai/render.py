# -*- coding: utf-8 -*-
"""정적 HTML/SVG 렌더링 (ADR-016).

**JS 라이브러리를 쓰지 않는다.** force-directed 레이아웃은 비결정적이라 두 슬라이스
동안 지켜온 바이트 동일 게이트를 깨뜨린다. Purdue 모델은 본래 계층 구조이므로
레벨=행 레이아웃이 자연스럽고, 좌표가 완전히 결정적이다.

표시 규칙 (SPEC 10.1, 그림 5) — 색 이외의 수단으로도 구분한다 (NFR-A11Y-001):
  확인(observed)  실선   ───
  추론(inferred)  점선   ─ ─
  정보 부족       회색 점선 + 물음표

wall-clock 을 읽지 않는다. 문서에 등장하는 시각은 as_of 뿐이다.
"""
from __future__ import annotations

import html
from typing import Dict, Optional, Sequence, Tuple

from .paths import AttackPath, BlockingCandidate
from .topology import INFERRED, OBSERVED, UNKNOWN, Edge, Node, Topology

# 레이아웃 상수 — 전부 고정. 난수도 물리 시뮬레이션도 없다.
NODE_W, NODE_H = 168, 44
COL_GAP, ROW_GAP = 34, 96
MARGIN_X, MARGIN_Y = 40, 74

LEVEL_LABELS = {
    5.0: "L5 인터넷 / 외부",
    4.0: "L4 전사 IT",
    3.5: "L3.5 IDMZ",
    3.0: "L3 사이트 운영",
    2.0: "L2 감시 제어",
    1.0: "L1 기본 제어",
    0.0: "L0 물리 공정",
}

EDGE_STYLE = {
    OBSERVED: ("#1f4e79", "none", "확인됨"),
    INFERRED: ("#a06a00", "7,4", "규칙 추론"),
    UNKNOWN: ("#8a8a8a", "2,5", "정보 부족"),
}

NODE_FILL = {
    "external": "#f4d7d7",
    "network": "#e8e8f0",
    "server": "#e2eef6",
    "workstation": "#e6f0e2",
    "plc": "#fdf0d5",
    "cell": "#eeeeee",
}


#: 레벨 미상 노드를 놓을 행. 실제 레벨(0.0~5.0)보다 아래에 온다.
_UNKNOWN_ROW = -1.0

def _layout(topo: Topology) -> Dict[str, Tuple[int, int]]:
    """레벨=행, 같은 행 안에서는 zone → node_id 순. 완전히 결정적이다."""
    rows: Dict[float, list] = {}
    for n in topo.nodes.values():
        # 레벨 미상은 맨 아래 별도 행으로. 0.0 에 섞으면 제어 계층으로 보인다.
        rows.setdefault(n.purdue_level if n.purdue_level is not None
                        else _UNKNOWN_ROW, []).append(n)

    pos: Dict[str, Tuple[int, int]] = {}
    for row_index, level in enumerate(sorted(rows, reverse=True)):
        nodes = sorted(rows[level], key=lambda n: (n.zone, n.node_id))
        y = MARGIN_Y + row_index * (NODE_H + ROW_GAP)
        for col, n in enumerate(nodes):
            x = MARGIN_X + col * (NODE_W + COL_GAP)
            pos[n.node_id] = (x, y)
    return pos


def _canvas(topo: Topology, pos) -> Tuple[int, int]:
    w = max((x for x, _ in pos.values()), default=0) + NODE_W + MARGIN_X
    h = max((y for _, y in pos.values()), default=0) + NODE_H + MARGIN_Y
    return w, h


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _edge_svg(e: Edge, pos, highlight: set) -> str:
    if e.src not in pos or e.dst not in pos:
        return ""
    x1, y1 = pos[e.src]
    x2, y2 = pos[e.dst]
    sx, sy = x1 + NODE_W // 2, y1 + NODE_H
    ex, ey = x2 + NODE_W // 2, y2
    if y2 < y1:  # 위로 가는 엣지는 반대편에서 출발
        sy, ey = y1, y2 + NODE_H

    color, dash, phrase = EDGE_STYLE[e.status]
    on_path = e.key in highlight
    width = 3.2 if on_path else 1.4
    if on_path:
        color = "#c1121f"

    mid_x, mid_y = (sx + ex) // 2, (sy + ey) // 2
    tip = "%s → %s\n%s\n상태: %s\n증거: %s (%s)" % (
        e.src, e.dst, e.label, phrase,
        e.evidence.get("method", "-"), e.evidence.get("observed_at", "시점 미상"),
    )
    dash_attr = "" if dash == "none" else ' stroke-dasharray="%s"' % dash
    return (
        '<g class="edge"><title>%s</title>'
        '<path d="M %d %d C %d %d, %d %d, %d %d" fill="none" stroke="%s" '
        'stroke-width="%.1f"%s marker-end="url(#arrow)"/>'
        '<text x="%d" y="%d" class="elabel">%s</text></g>'
        % (_esc(tip), sx, sy, sx, mid_y, ex, mid_y, ex, ey, color, width, dash_attr,
           mid_x + 6, mid_y, _esc(e.protocol or e.edge_type))
    )


def _node_svg(n: Node, pos, on_path: set) -> str:
    x, y = pos[n.node_id]
    fill = NODE_FILL.get(n.node_type, "#ffffff")
    stroke = "#c1121f" if n.node_id in on_path else "#444444"
    width = 2.4 if n.node_id in on_path else 1.0
    crit = " ⚠" if n.is_critical else ""
    entry = "▶ " if n.is_entry_point else ""
    tip = "%s\nzone=%s  level=L%s\n자산=%s\n안전중요도=%s" % (
        n.label, n.zone or "미상",
        "미상" if n.purdue_level is None else n.purdue_level,
        n.asset_id or "-", n.safety_criticality or "미상")
    return (
        '<g class="node"><title>%s</title>'
        '<rect x="%d" y="%d" width="%d" height="%d" rx="6" fill="%s" stroke="%s" stroke-width="%.1f"/>'
        '<text x="%d" y="%d" class="nlabel">%s%s%s</text>'
        '<text x="%d" y="%d" class="nsub">%s</text></g>'
        % (_esc(tip), x, y, NODE_W, NODE_H, fill, stroke, width,
           x + 8, y + 19, _esc(entry), _esc(n.label[:22]), _esc(crit),
           x + 8, y + 35, _esc(n.zone))
    )


def render_svg(topo: Topology, highlight_path: Optional[AttackPath] = None) -> str:
    pos = _layout(topo)
    w, h = _canvas(topo, pos)
    hl_edges = set(highlight_path.edge_keys) if highlight_path else set()
    hl_nodes = set(highlight_path.nodes) if highlight_path else set()

    parts = [
        '<svg viewBox="0 0 %d %d" width="%d" height="%d" xmlns="http://www.w3.org/2000/svg" '
        'role="img" aria-label="공격 경로 그래프">' % (w, h, w, h),
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        'markerHeight="7" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#666"/></marker></defs>',
    ]

    # 레벨 띠와 라벨
    rows = sorted({n.purdue_level if n.purdue_level is not None else _UNKNOWN_ROW
                   for n in topo.nodes.values()}, reverse=True)
    for i, level in enumerate(rows):
        y = MARGIN_Y + i * (NODE_H + ROW_GAP)
        parts.append('<text x="8" y="%d" class="level">%s</text>'
                     % (y - 8, _esc(LEVEL_LABELS.get(level, "L%s" % level))))
        parts.append('<line x1="0" y1="%d" x2="%d" y2="%d" stroke="#eeeeee"/>'
                     % (y - 4, w, y - 4))

    for e in sorted(topo.edges, key=lambda e: e.key):
        parts.append(_edge_svg(e, pos, hl_edges))
    for n in sorted(topo.nodes.values(), key=lambda n: n.node_id):
        parts.append(_node_svg(n, pos, hl_nodes))

    parts.append("</svg>")
    return "\n".join(parts)


CSS = """
body{font-family:'Malgun Gothic','Segoe UI',sans-serif;margin:0;padding:24px;color:#1a1a1a;background:#fff}
h1{font-size:19px;margin:0 0 4px}h2{font-size:15px;margin:26px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}
.meta{color:#666;font-size:12px;margin-bottom:16px}
.warn{background:#fff8e1;border-left:4px solid #f0ad4e;padding:10px 14px;font-size:12.5px;margin:14px 0}
svg{border:1px solid #e0e0e0;border-radius:6px;background:#fcfcfc;max-width:100%;height:auto}
.level{font-size:10.5px;fill:#999}
.nlabel{font-size:11.5px;font-weight:600;fill:#111}
.nsub{font-size:9.5px;fill:#777}
.elabel{font-size:9px;fill:#888}
table{border-collapse:collapse;font-size:12.5px;margin-top:6px;width:100%}
th,td{border:1px solid #e2e2e2;padding:5px 9px;text-align:left;vertical-align:top}
th{background:#f6f6f6;font-weight:600}
code{background:#f2f2f2;padding:1px 4px;border-radius:3px;font-size:11.5px}
.legend span{display:inline-block;margin-right:18px;font-size:12px}
ol.path{font-size:12.5px;line-height:1.6}
"""


def render_html(
    topo: Topology,
    paths: Sequence[AttackPath],
    blocks: Sequence[BlockingCandidate],
    as_of: str,
    target_label: str,
    attack_catalog=None,
) -> str:
    best = paths[0] if paths else None
    prov = topo.provenance

    out = ["<!doctype html><html lang='ko'><head><meta charset='utf-8'>",
           "<title>공격 경로 — %s</title><style>%s</style></head><body>" % (_esc(target_label), CSS)]
    out.append("<h1>공격 경로 — %s</h1>" % _esc(target_label))
    out.append("<div class='meta'>as_of=%s · 토폴로지=%s · 경로 %d개</div>"
               % (_esc(as_of), _esc(topo.source_path), len(paths)))

    if prov.get("synthetic"):
        out.append("<div class='warn'><b>합성 토폴로지</b> — %s<br>근거: %s</div>"
                   % (_esc(prov.get("warning", "")), _esc(prov.get("basis", ""))))

    out.append("<div class='legend'><span>── 확인됨(observed)</span>"
               "<span>─ ─ 규칙 추론(inferred)</span>"
               "<span>· · 정보 부족(unknown)</span>"
               "<span>▶ 진입점</span><span>⚠ 안전 중요</span></div>")
    out.append(render_svg(topo, best))

    if best:
        out.append("<h2>최우선 경로 (%s, 확신도 %.2f)</h2>" % (_esc(best.status), best.confidence))
        out.append("<ol class='path'>")
        for hop in best.hops:
            techs = ""
            if attack_catalog is not None:
                names = ["%s %s" % (t.technique_id, t.name) for t in attack_catalog.for_edge(hop.edge)]
                if names:
                    techs = " · ATT&amp;CK: %s <i>(내부 매핑)</i>" % _esc(", ".join(names))
            out.append("<li><code>%s</code> → <code>%s</code> (%s, %s) — 획득 능력: %s%s</li>"
                       % (_esc(hop.edge.src), _esc(hop.edge.dst), _esc(hop.edge.label),
                          _esc(EDGE_STYLE[hop.edge.status][2]),
                          _esc(", ".join(sorted(hop.caps_after))), techs))
        out.append("</ol>")
        if best.weakest is not None:
            out.append("<div class='meta'>가장 약한 엣지: <code>%s</code> — 경로 확신도는 이 엣지가 결정합니다.</div>"
                       % _esc(best.weakest.key))

    if blocks:
        out.append("<h2>차단 후보</h2>")
        out.append("<table><tr><th>엣지</th><th>끊기는 공격 경로</th>"
                   "<th>영향받는 정상 통신</th><th>남는 경로</th></tr>")
        for b in blocks:
            out.append("<tr><td><code>%s</code></td><td>%d</td><td>%d</td><td>%d</td></tr>"
                       % (_esc(b.edge.key), b.paths_cut, b.legitimate_flows_broken, b.paths_remaining))
        out.append("</table>")
        out.append("<div class='meta'>점수 대신 정수 두 개로 제시합니다 — "
                   "\"경로 N개를 끊고 정상 통신 M개를 끊습니다\" (설계 원칙 P6).</div>")

    out.append("</body></html>")
    return "\n".join(out)
