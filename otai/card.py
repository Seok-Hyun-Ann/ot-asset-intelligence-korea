# -*- coding: utf-8 -*-
"""판정 카드 렌더링 (표 26 정보 계층).

  1 적용성 배지    2 권장 행동(슬라이스 2)   3 결론 이유
  4 일치 조건      5 외부 신호(슬라이스 2)   6 근거   7 이력

**결정성**: 이 모듈은 wall-clock 을 읽지 않는다. 출력에 등장하는 시각은
as_of 와 observed_at 뿐이다.
"""
from __future__ import annotations

from .applicability import Decision

# 색 이외의 수단으로도 상태를 구분한다 (NFR-A11Y-001)
BADGE = {
    "affected_confirmed": "[!!]",
    "affected_likely": "[! ]",
    "candidate": "[? ]",
    "insufficient_information": "[--]",
    "not_affected_confirmed": "[ok]",
    "fixed": "[ok]",
    "conflicting_evidence": "[><]",
    "stale": "[..]",
    "no_known_match": "[--]",
}


def render_text(d: Decision) -> str:
    L = []
    L.append("=" * 72)
    L.append("%s %s  (%s)" % (BADGE.get(d.status, "[  ]"), d.phrase_ko, d.status))
    L.append("=" * 72)
    L.append("자산        : %s" % d.asset_id)
    L.append("권고        : %s — %s" % (d.evidence["advisory_id"], d.evidence["advisory_title"]))
    L.append("공급자      : %s (%s)" % (d.evidence["publisher"], d.evidence["publisher_category"]))
    if d.identity_level:
        L.append("식별 수준   : %s (확신 %.2f)" % (d.identity_level, d.identity_confidence))

    L.append("")
    L.append("[결론을 바꾼 조건]")
    for c in d.decisive_conditions:
        L.append("  · %s" % c)

    L.append("")
    L.append("[조건 대조]")
    for key, label in (("matched", "일치"), ("mismatched", "불일치"), ("missing", "누락")):
        vals = d.fields.get(key) or []
        L.append("  %-6s: %s" % (label, ", ".join(vals) if vals else "-"))

    if d.next_best_question:
        L.append("")
        L.append("[다음 최적 질문]")
        L.append("  %s" % d.next_best_question)

    L.append("")
    L.append("[근거]")
    if d.evidence.get("raw_expression") is not None:
        L.append("  영향 범위 원문 : %r" % d.evidence["raw_expression"])
    L.append("  권고 원문 해시 : %s" % d.evidence["advisory_sha256"])
    L.append("  권고 개정일    : %s" % (d.evidence.get("current_release_date") or "-"))

    L.append("")
    L.append("[재현 정보]")
    L.append("  as_of=%s  rule=%s  parser=%s" % (d.as_of, d.rule_version, d.parser_version))
    L.append("  input_hash=%s" % d.input_hash)
    return "\n".join(L)
