# -*- coding: utf-8 -*-
"""시간 축: 그 시점에 **알려져 있던 것만** 으로 판정한다 (ADR-037).

`--as-of` 는 처음부터 있었지만 권고문 목록에는 걸리지 않았다. 2026-02-01 기준으로
판정하면서 2026-08 에 나온 권고문을 함께 보고 있었다는 뜻이다. 재현성(불변 규칙 4)의
구멍이다 — 같은 스냅샷·같은 규칙이라도 '언제 알려졌는가' 를 빼면 과거를 재현한 것이
아니라 오늘의 지식으로 과거를 다시 읽은 것이다.

같은 결함이 KEV 에도 있다. KEV 항목은 `dateAdded` 를 갖는데, 2026-09 스냅샷을
2월 판정에 그대로 쓰면 그때는 악용이 알려지지 않았던 CVE 에 H01 이 발화한다.

**배제는 `false` 일 때만 한다.** 날짜를 모르면(`unknown`) 남긴다 — 모르는 것을
배제하면 영향받는 항목이 조용히 사라진다. 불변 규칙 2 를 시간 축에서 어기는 것이다.

자산 쪽은 고정이다. 합성 자산의 `observed_at` 은 2026-09 근처이고 그것을 과거로
고쳐 쓰지 않는다 — 없는 역사를 지어내는 것이기 때문이다. 따라서 과거 시점 열은
'그때의 현장' 이 아니라 **'그 시점에 알려져 있던 권고문으로 오늘의 자산을 다시
판정한 것'** 이다. 화면과 ADR 이 이 문장을 그대로 말해야 한다.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, List, Optional, Sequence, Tuple

from .logic import Tri

#: 비교 불가를 만드는 두 가지 — 존재 여부 미상, 그리고 우리가 든 사본이 개정본인 경우
UNCERTAIN = ("존재 여부 미상", "개정본만 보유")


@dataclass(frozen=True)
class Known:
    """그 시점에 이 문서가 알려져 있었는가."""

    existed: Tri
    revision_uncertain: bool
    reason: str
    initial: Optional[str] = None
    current: Optional[str] = None

    @property
    def usable(self) -> bool:
        """판정에 넣어도 되는가. **`false` 일 때만 뺀다** — 미상은 남긴다."""
        return self.existed is not Tri.FALSE

    @property
    def certain(self) -> bool:
        """두 시점을 비교해도 되는가."""
        return self.existed is Tri.TRUE and not self.revision_uncertain


def _day(value: Optional[str]) -> str:
    return (value or "")[:10]


def known_at(advisory, as_of: str) -> Known:
    """이 권고문이 `as_of` 시점에 존재했는가 (삼진).

    `initial_release_date` 가 없으면 `unknown` 이다. 없다고 '없었다' 로 읽으면
    그 문서가 다루는 취약점이 과거 열에서 통째로 사라진다.

    개정은 존재 여부와 다른 사실이다. 2월에 나온 문서를 8월에 개정했다면 그 문서는
    2월에 **존재했지만** 우리가 든 사본은 2월의 내용이 아니다. 존재는 `true` 로,
    내용은 `revision_uncertain` 으로 따로 말한다 — 하나로 뭉치면 둘 다 못 쓴다.
    """
    day, init, cur = _day(as_of), _day(advisory.initial_release_date), \
        _day(advisory.current_release_date)
    revised = bool(cur and day and cur > day)
    if not init:
        return Known(Tri.UNKNOWN, revised,
                     "이 문서가 처음 나온 날짜가 기록되어 있지 않습니다",
                     init or None, cur or None)
    if init > day:
        return Known(Tri.FALSE, False,
                     "이 시점에는 아직 나오지 않은 문서입니다 (%s 공개)" % init,
                     init, cur or None)
    if revised:
        return Known(Tri.TRUE, True,
                     "그때 있던 문서지만, 우리가 가진 사본은 그 뒤 %s 에 "
                     "고쳐진 것입니다" % cur, init, cur)
    return Known(Tri.TRUE, False, "그 시점에 이미 나와 있던 문서입니다", init, cur or None)


def visible_at(advisories: Sequence, indexes: Sequence, as_of: str) -> List[Tuple]:
    """그 시점 판정에 넣을 (권고문, 색인, 판정) 목록.

    한 번 만들어 돌려쓴다. 순회하는 자리마다 따로 거르면 한 곳을 빠뜨렸을 때
    화면마다 숫자가 달라지는데, 그게 정확히 지금 고치는 결함이다.
    """
    out = []
    for adv, ix in zip(advisories, indexes):
        k = known_at(adv, as_of)
        if k.usable:
            out.append((adv, ix, k))
    return out


def kev_at(catalog, as_of: str):
    """그 시점까지 악용이 **알려져 있던** 항목만 남긴 KEV.

    `dateAdded` 가 비어 있으면 남긴다 (배제는 `false` 일 때만). KEV 는 정렬 신호가
    아니라 H01 의 전제조건이므로, 이걸 안 거르면 2월 열에 그때 없던 P0 가 선다.
    """
    if catalog is None:
        return None
    kept = {cve: e for cve, e in catalog.entries.items()
            if not e.date_added or _day(e.date_added) <= _day(as_of)}
    if len(kept) == len(catalog.entries):
        return catalog
    return replace(catalog, entries=kept)


# ------------------------------------------------------------------ 두 시점 비교

#: 비교 결과 4종. '등급 변경' 과 '비교 불가' 를 합치지 않는다 — 모르는 것을
#: 변화 없음으로 접으면 시간 축에서도 false safe 다.
ADDED, GONE, MOVED, UNCOMPARABLE = "새로 생김", "사라짐", "등급 변경", "비교 불가"


@dataclass(frozen=True)
class Change:
    kind: str
    asset_id: str
    advisory_id: str
    before: Optional[str]      # 버킷
    after: Optional[str]
    before_status: Optional[str]
    after_status: Optional[str]
    why: str


def _key(row) -> Tuple[str, str]:
    return (row["asset_id"], row["advisory_id"])


def diff(before: Sequence[Dict], after: Sequence[Dict],
         uncertain: Sequence[Tuple[str, str]] = ()) -> List[Change]:
    """두 시점의 판정 목록을 비교한다.

    **버킷과 상태만 본다.** 렌즈 점수는 보지 않는다 — 부동소수 잡음이 '등급 변경'
    으로 둔갑한다. 등급은 사실이고 점수는 같은 등급 안의 정렬일 뿐이다.

    `uncertain` 에 든 (자산, 권고문) 은 어느 쪽이든 시점 판단이 흐린 것이라
    변화 여부를 말하지 않는다. 말할 수 없는 것을 '변화 없음' 으로 접지 않는다.
    """
    fog = set(uncertain)
    a = {_key(r): r for r in before}
    b = {_key(r): r for r in after}
    out: List[Change] = []
    for k in sorted(set(a) | set(b)):
        x, y = a.get(k), b.get(k)
        if k in fog:
            out.append(Change(UNCOMPARABLE, k[0], k[1],
                              x["bucket"] if x else None, y["bucket"] if y else None,
                              x["status"] if x else None, y["status"] if y else None,
                              "이 문서의 시점을 확정할 수 없어 두 시점을 견줄 수 "
                              "없습니다. 변화가 없었다는 뜻이 아닙니다."))
        elif x is None:
            out.append(Change(ADDED, k[0], k[1], None, y["bucket"], None, y["status"],
                              "이 시점 뒤에 나온 권고문이 이 장비에 걸렸습니다"))
        elif y is None:
            out.append(Change(GONE, k[0], k[1], x["bucket"], None, x["status"], None,
                              "앞 시점에는 걸렸는데 뒤 시점에는 목록에 없습니다. "
                              "고쳐졌다는 뜻이 아니라 판정 입력이 달라진 것입니다."))
        elif x["bucket"] != y["bucket"] or x["status"] != y["status"]:
            out.append(Change(MOVED, k[0], k[1], x["bucket"], y["bucket"],
                              x["status"], y["status"],
                              "같은 문서인데 해야 할 일의 급이 달라졌습니다"))
    return out


#: 화면에 셀 때의 순서 — 늘어난 것이 먼저, 말할 수 없는 것이 마지막
ORDER = (ADDED, MOVED, GONE, UNCOMPARABLE)


def summarize(changes: Sequence[Change]) -> Dict[str, int]:
    counts = {k: 0 for k in ORDER}
    for c in changes:
        counts[c.kind] = counts.get(c.kind, 0) + 1
    return counts
