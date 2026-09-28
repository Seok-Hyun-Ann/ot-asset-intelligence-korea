# -*- coding: utf-8 -*-
"""행동 큐 렌더링 (표 25: 기본 홈은 위험 점수가 아니라 '해야 할 일').

정렬: P0 → P? → P1 → P2 → P3 → P4
`P?` 는 '낮은 우선순위' 가 아니라 **막힌 P0/P1** 이다 (ADR-007). 그래서 P1 보다 앞에 온다.

wall-clock 을 읽지 않는다 — 시각은 as_of 뿐이다.
"""
from __future__ import annotations

from typing import Sequence

from .priority import BUCKET_PHRASES, QueueItem

BADGE = {
    "P0": "[!!!]",
    "P?": "[ ? ]",
    "P1": "[!! ]",
    "P2": "[!  ]",
    "P3": "[ ~ ]",
    "P4": "[ok ]",
}


def render_queue(items: Sequence[QueueItem], lens: str, kev_snapshot=None) -> str:
    L = []
    L.append("=" * 78)
    L.append("행동 큐   렌즈=%s   as_of=%s   KEV=%s"
             % (lens, items[0].as_of if items else "-", kev_snapshot or "미로드"))
    L.append("=" * 78)

    if not items:
        L.append("항목 없음")
        return "\n".join(L)

    current = None
    for it in items:
        if it.bucket != current:
            current = it.bucket
            L.append("")
            L.append("── %s %s — %s %s" % (
                BADGE[it.bucket], it.bucket, BUCKET_PHRASES[it.bucket], "─" * 20))
        head = "  %-26s %-24s" % (it.asset_id, it.status)
        if it.bucket == "P?":
            head += "확정 시 최소 %s" % it.floor_if_confirmed
        elif it.fired_rules:
            head += "강제규칙 %s" % ",".join(it.fired_rules)
        L.append(head)

        if it.kev_cves:
            L.append("      KEV: %s" % ", ".join(it.kev_cves[:3]))
        for p in it.pending_escalations:
            L.append("      보류 %s → %s : %s 미확인"
                     % (p.rule_id, p.floor_if_confirmed, ", ".join(p.missing)))

    L.append("")
    L.append("─" * 78)
    n_pending = sum(1 for i in items if i.bucket == "P?")
    if n_pending:
        L.append("확인 필요 %d건 — 전제조건이 미상이라 강제규칙을 보류했습니다." % n_pending)
        L.append("경로 엔진(슬라이스 3)이 붙으면 이 항목들이 실제 등급으로 확정됩니다.")
    L.append("정책=%s  렌즈는 같은 버킷 안의 정렬만 바꿉니다 (SPEC 11.3)."
             % items[0].policy_version)
    return "\n".join(L)
