# -*- coding: utf-8 -*-
"""수명주기 증거 — 표 13 의 마지막 빈 칸.

    | 수명주기 | 제조사 EOL/EOS | 계약·현장 기록 | 패치 가능성과 교체 판단 |

지금까지 `lifecycle_status` 는 **자산 입력값뿐**이었다. 사용자가 "EOL" 이라고 적으면
그대로 믿고, 그 값으로 H04(지원 종료 + 원격접속 경계 + 버전 미상 → P1)가 발화했다.
표 13 이 1차 근거로 지목한 **제조사 선언**은 어디에도 들어오지 않았다.

CSAF 에 구조화된 근거가 있다. `remediation.category` 는 CSAF 2.0 이 정한 열거값이고
그중 두 개가 수명주기를 말한다:

    no_fix_planned   제조사가 **고치지 않겠다고 선언**했다 — 가장 강한 신호
    none_available   지금 쓸 수 있는 수정이 없다 — EOL 과 같지 않다

실측: 권고문 1,303건 중 181건에 수명주기 신호가 있고, `no_fix_planned` 는 166곳이다.

**없는 것을 지어내지 않는다.** 제조사가 아무 말도 하지 않으면 수명주기는 미상이다.
'수정이 없다' 를 '지원이 끝났다' 로 승격하지 않는다 — 그건 다른 사실이다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .csaf import Advisory

# 제조사가 명시적으로 선언하는 값 (CSAF 2.0 remediation category)
NO_FIX = "no_fix_planned"

# 자유 문장에서 읽어낸 신호. **구조화된 값보다 약하다** — 문구는 오독될 수 있다.
_TEXT_EOL = re.compile(
    r"end[-\s]of[-\s](life|support|sale|maintenance)|(?<![A-Za-z])EOL(?![A-Za-z])|"
    r"(?<![A-Za-z])EOS(?![A-Za-z])|no longer supported|discontinued|"
    r"end of maintenance", re.I)

# 자산이 스스로 말한 값 → 정규화
_ASSET_EOL = ("eol", "eos", "end_of_life", "end_of_sale", "end_of_support")
_ASSET_OK = ("supported", "active", "current")

# 표 13: 제조사가 1차, 현장 기록이 보조
LIFECYCLE_AUTHORITY: Tuple[str, ...] = ("vendor", "coordinator", "field", "other",
                                        "unverified")

STATES = ("end_of_life", "supported", "unknown")


@dataclass(frozen=True)
class LifecycleClaim:
    """누가 이 장비의 수명주기에 대해 무엇을 말했는가."""
    state: str            # end_of_life | supported | unknown
    source_id: str        # 권고문 id 또는 "asset"
    source_role: str      # vendor | coordinator | field | unverified
    basis: str            # 무엇을 보고 그렇게 판단했는가
    structured: bool      # CSAF 열거값에서 왔는가 (자유 문장이 아니라)


def from_asset(lifecycle_status: Optional[str]) -> Optional[LifecycleClaim]:
    """자산이 스스로 말한 값. 표 13 의 **보조** 소스다 (현장·계약 기록)."""
    v = (lifecycle_status or "").strip().lower()
    if not v:
        return None
    if v in _ASSET_EOL:
        return LifecycleClaim("end_of_life", "asset", "field",
                              "자산 입력 lifecycle_status=%s" % v, structured=True)
    if v in _ASSET_OK:
        return LifecycleClaim("supported", "asset", "field",
                              "자산 입력 lifecycle_status=%s" % v, structured=True)
    return LifecycleClaim("unknown", "asset", "field",
                          "자산 입력 lifecycle_status=%r — 해석할 수 없음" % v,
                          structured=False)


def from_advisory(adv: Advisory, product_ids: Sequence[str],
                  role: str = "vendor") -> List[LifecycleClaim]:
    """권고문이 **이 제품에 대해** 수명주기를 말하는가.

    `product_ids` 로 범위를 좁힌다 — 권고문 어딘가에 'no fix' 가 있다고 해서
    우리 제품이 그렇다는 뜻이 아니다.
    """
    want = set(product_ids)
    out: List[LifecycleClaim] = []
    for v in adv.vulnerabilities:
        for rem in v.remediations:
            cat = (rem.get("category") or "").strip()
            ids = set(rem.get("product_ids") or ())
            # product_ids 가 없으면 권고문 전체를 뜻한다 (CSAF 관행)
            scoped = (not ids) or bool(ids & want)
            if not scoped:
                continue
            details = rem.get("details") or ""
            if cat == NO_FIX:
                out.append(LifecycleClaim(
                    "end_of_life", adv.advisory_id, role,
                    "CSAF remediation category=no_fix_planned — 제조사가 수정 계획 없음을 "
                    "선언했습니다%s" % (": " + details[:120] if details else ""),
                    structured=True))
            elif _TEXT_EOL.search(details):
                out.append(LifecycleClaim(
                    "end_of_life", adv.advisory_id, role,
                    "권고문 문장에서 읽음 (구조화된 값 아님): %s" % details[:120],
                    structured=False))
    for note in adv.notes if hasattr(adv, "notes") else ():
        text = (note.get("text") or "") if isinstance(note, dict) else str(note)
        if _TEXT_EOL.search(text):
            out.append(LifecycleClaim(
                "end_of_life", adv.advisory_id, role,
                "권고문 노트에서 읽음 (구조화된 값 아님): %s" % text[:120],
                structured=False))
    # 같은 근거가 여러 취약점에 반복된다 — 한 번만 센다
    seen: Dict[Tuple[str, str, str], LifecycleClaim] = {}
    for c in out:
        seen.setdefault((c.state, c.source_id, c.basis[:60]), c)
    return list(seen.values())


@dataclass(frozen=True)
class LifecycleView:
    """표 13 권위로 정리한 결론. 모든 주장은 보존한다."""
    state: str
    winner: Optional[LifecycleClaim]
    claims: Tuple[LifecycleClaim, ...]
    conflicting: bool
    reason: str

    @property
    def vendor_confirmed(self) -> bool:
        """제조사가 **구조화된 값으로** 지원 종료를 선언했는가."""
        return any(c.state == "end_of_life" and c.structured
                   and c.source_role in ("vendor", "coordinator")
                   for c in self.claims)


def _rank(role: str) -> int:
    return (LIFECYCLE_AUTHORITY.index(role) if role in LIFECYCLE_AUTHORITY
            else len(LIFECYCLE_AUTHORITY))


def resolve(claims: Sequence[Optional[LifecycleClaim]]) -> LifecycleView:
    """표 13 대로 제조사를 먼저 본다. 값이 갈리면 보존하고 알린다.

    `None` 을 섞어 넘겨도 된다 — `from_asset()` 은 값이 없으면 None 을 준다.
    """
    claims = tuple(c for c in claims if c is not None)
    usable = [c for c in claims if c.state != "unknown"]
    if not usable:
        return LifecycleView("unknown", None, tuple(claims), False,
                             "수명주기를 말하는 근거가 없습니다. 미상입니다 — "
                             "'지원 중' 이라는 뜻이 아닙니다.")
    # 구조화된 값이 자유 문장보다 앞선다. 같은 등급이면 표 13 권위 순.
    ordered = sorted(usable, key=lambda c: (_rank(c.source_role), not c.structured,
                                            c.source_id))
    winner = ordered[0]
    states = {c.state for c in usable}
    conflicting = len(states) > 1

    if conflicting:
        reason = ("근거마다 다릅니다. 표 13 에 따라 %s(%s)를 채택하고 나머지도 "
                  "보존합니다." % (winner.source_role, winner.source_id))
    elif winner.source_role == "field":
        reason = ("현장 기록만 있습니다 — 제조사 선언으로 확인된 값이 아닙니다 "
                  "(표 13 은 제조사를 1차 근거로 둡니다).")
    else:
        reason = "제조사 측 근거로 확인했습니다."
    return LifecycleView(winner.state, winner, tuple(claims), conflicting, reason)
