# -*- coding: utf-8 -*-
"""점검 항목 근거 렌더링 (ADR-043 · ADR-044).

**이 화면이 말하지 않는 것**: 준수 여부. 「양호」·「취약」은 평가기관의 어휘이고
우리 어휘는 근거 있음 / 근거 없음 / 도구가 답할 수 없음 셋이다.

**답하지 못한 항목을 숨기지 않는다.** 기본값은 답할 수 있다고 적은 항목만 펼치지만,
답할 수 없는 항목의 수를 머리에 항상 함께 싣는다 — 20개만 보여주고 260개를 빼면
안내서가 아니라 홍보물이 된다.

색을 쓰지 않는다. 글리프(`● ◐ ○`)로 구분한다 (NFR-A11Y-001).
wall-clock 을 읽지 않는다 — 시각은 as_of 뿐이다.
"""
from __future__ import annotations

from typing import Optional, Sequence, Tuple

from .controls import (ABSENT, NOT_ASSESSABLE, PRESENT, SCOPE_KO, STATUS_KO,
                       ControlSet, Evidence, summarize)

#: 색 이외의 수단으로도 상태를 구분한다 (NFR-A11Y-001).
GLYPH = {PRESENT: "●", ABSENT: "◐", NOT_ASSESSABLE: "○"}

_RULE = "=" * 78
_THIN = "─" * 78


def render_controls(reports: Sequence[Tuple[ControlSet, Sequence[Evidence]]],
                    asset_id: str, as_of: str, show_all: bool = False,
                    inputs: Optional[Sequence[str]] = None) -> str:
    L = [_RULE,
         "점검 항목 근거   자산=%s   as_of=%s" % (asset_id, as_of),
         _RULE,
         "**준수 여부 판정이 아닙니다.** 취약점 분석·평가는 정보통신기반 보호법에",
         "따라 자격을 갖춘 평가기관이 수행합니다. 이 화면은 그 평가에 **낼 수 있는",
         "근거**를 모아 보여줍니다."]
    if inputs:
        L.append("")
        L.append("무엇을 보고 답했나: %s" % " · ".join(inputs))

    for cs, evs in reports:
        s = summarize(evs)
        L.append("")
        L.append(_THIN)
        L.append(cs.standard.get("title", cs.standard_id))
        sub = cs.standard.get("chapter") or cs.standard.get("edition")
        if sub:
            L.append("  %s" % sub)
        L.append("  항목 %d개 중 — %s %s %d · %s %s %d · %s %s %d"
                 % (len(cs.controls),
                    GLYPH[PRESENT], STATUS_KO[PRESENT], s[PRESENT],
                    GLYPH[ABSENT], STATUS_KO[ABSENT], s[ABSENT],
                    GLYPH[NOT_ASSESSABLE], STATUS_KO[NOT_ASSESSABLE],
                    s[NOT_ASSESSABLE]))
        L.append("")

        shown = [e for e in evs if show_all or e.status != NOT_ASSESSABLE]
        for e in shown:
            c = e.control
            head = "  %s %-7s" % (GLYPH[e.status], c.code)
            if c.severity:
                head += " %s" % c.severity
            head += "  %-14s %s" % (STATUS_KO[e.status], c.gist or c.name or "")
            L.append(head.rstrip())
            for b in e.basis:
                L.append("        · %s" % b)
            for p in e.pointers:
                L.append("        → %s" % p)
            if c.quote:
                L.append('        원문: "%s"' % c.quote)
            L.append("")

        if not show_all and s[NOT_ASSESSABLE]:
            L.append("  %s 나머지 %d개는 정책·절차·물리·교육 항목입니다 — 도구가 답할 수"
                     % (GLYPH[NOT_ASSESSABLE], s[NOT_ASSESSABLE]))
            L.append("     없습니다. **통과도 미달도 아닙니다.** `--all` 로 전부 봅니다.")
            L.append("")

    L.append(_THIN)
    L.append("'근거 없음' 은 **미달이 아닙니다** — 필요한 입력이 없을 수 있습니다.")
    L.append("표준 본문은 싣지 않습니다. 항목 요약은 우리가 쓴 것입니다 (ADR-043/044).")
    return "\n".join(L)
