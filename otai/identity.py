# -*- coding: utf-8 -*-
"""제품 엔터티 식별 (R02) — 표 18 식별 수준 사다리.

  Exact          주문번호 · SKU · PURL 일치            자동 연결 가능
  Deterministic  제조사 + 제품명 정규화 일치            충돌 없을 때 자동
  Composite      제조사 + 제품군 토큰 포함              후보 1개여도 likely
  Fuzzy          제조사 불명이나 토큰 강한 중첩          사람 확인 필수
  Inferred       (슬라이스 1 범위 밖 — 네트워크 행위)

실데이터가 이 사다리를 그대로 갈라놓는다:
  Siemens 는 model_numbers 를 주므로 Exact 도달 가능
  CISA/Mitsubishi 는 제품명 문자열뿐이라 Deterministic 이 상한
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .csaf import Advisory, ProductEntry
from .model import Asset

LEVELS = ("Exact", "Deterministic", "Composite", "Fuzzy", "Inferred")
_LEVEL_RANK = {name: i for i, name in enumerate(LEVELS)}
CONFIDENCE = {"Exact": 0.99, "Deterministic": 0.92, "Composite": 0.70, "Fuzzy": 0.45, "Inferred": 0.25}

# 표 18 정책: Exact/Deterministic 은 '일치', 그 아래는 '후보'
MATCHED_LEVELS = ("Exact", "Deterministic")

_TOKEN_RE = re.compile(r"[a-z0-9]+")
# 제품명에 흔한 무의미 토큰 — 중첩 판정에서 제외
_STOPWORDS = {"series", "firmware", "cpu", "module", "the", "and", "for"}


def _norm_id(s: Optional[str]) -> str:
    """주문번호 비교용 정규화. 하이픈은 의미가 있으므로 공백만 제거한다."""
    return re.sub(r"\s+", "", (s or "")).upper()


def _tokens(*parts: Optional[str]) -> frozenset:
    out = set()
    for p in parts:
        if p:
            out.update(_TOKEN_RE.findall(str(p).lower()))
    return frozenset(out - _STOPWORDS)


def _vendor_matches(asset_vendor: Optional[str], product_vendor: Optional[str]) -> bool:
    a, b = _tokens(asset_vendor), _tokens(product_vendor)
    if not a or not b:
        return False
    return a <= b or b <= a


@dataclass(frozen=True)
class IdentityMatch:
    product: ProductEntry
    level: str
    confidence: float
    reason: str


@dataclass(frozen=True)
class IdentityResult:
    matches: Tuple[IdentityMatch, ...]
    resolvable: bool          # 자산에 식별 시도를 할 재료가 있는가
    conflicting: bool = False

    @property
    def best_level(self) -> Optional[str]:
        if not self.matches:
            return None
        return min((m.level for m in self.matches), key=lambda lv: _LEVEL_RANK[lv])

    @property
    def confidence(self) -> float:
        return max((m.confidence for m in self.matches), default=0.0)

    @property
    def is_matched(self) -> bool:
        """'일치'(표 19) 인가, 아니면 '후보' 인가."""
        return self.best_level in MATCHED_LEVELS


def _match_one(asset: Asset, p: ProductEntry) -> Optional[IdentityMatch]:
    ident = asset.identity

    # 1) Exact - 주문번호가 벤더 제공 model_numbers 와 일치
    if ident.order_number and p.model_numbers:
        want = _norm_id(ident.order_number)
        if any(_norm_id(m) == want for m in p.model_numbers):
            return IdentityMatch(p, "Exact", CONFIDENCE["Exact"],
                                 "주문번호 %s 가 벤더 model_numbers 와 일치" % ident.order_number)

    vendor_ok = _vendor_matches(ident.vendor_raw, p.vendor)
    asset_tokens = _tokens(ident.family_raw, ident.model_raw)

    # 압축 모델 표기("R08/16/32/120PCPU")를 전개한 변형 전부와 대조하고 최선을 취한다
    best: Optional[IdentityMatch] = None

    def better(cand: Optional[IdentityMatch]) -> None:
        nonlocal best
        if cand is None:
            return
        if best is None or _LEVEL_RANK[cand.level] < _LEVEL_RANK[best.level]:
            best = cand

    for variant in (p.name_variants or (p.product_name,)):
        prod_tokens = _tokens(variant)
        if not prod_tokens:
            continue
        via = "" if variant == p.product_name else " (압축 모델 표기 전개: %s)" % variant

        # 2) Deterministic - 제조사 일치 + 제품명 정규화 완전 일치
        if vendor_ok and ident.model_raw and _tokens(ident.model_raw) == prod_tokens:
            better(IdentityMatch(p, "Deterministic", CONFIDENCE["Deterministic"],
                                 "제조사와 제품명이 정규화 후 완전 일치" + via))
            continue

        if not asset_tokens:
            continue
        overlap = len(asset_tokens & prod_tokens) / len(asset_tokens | prod_tokens)

        # 3) Composite - 제조사 일치 + 자산 토큰이 제품명에 포함
        if vendor_ok:
            if asset_tokens <= prod_tokens:
                better(IdentityMatch(p, "Composite", CONFIDENCE["Composite"],
                                     "제조사 일치, 제품군 토큰이 제품명에 포함되나 모델 특정 불가" + via))
                continue
            if overlap >= 0.5:
                better(IdentityMatch(p, "Composite", CONFIDENCE["Composite"],
                                     "제조사 일치, 제품명 토큰 중첩 %.0f%%" % (overlap * 100) + via))
                continue

        # 4) Fuzzy - 제조사 확인 불가하나 제품명 토큰이 강하게 겹침
        if overlap >= 0.6:
            better(IdentityMatch(p, "Fuzzy", CONFIDENCE["Fuzzy"],
                                 "제조사 확인 불가, 제품명 토큰 중첩 %.0f%%" % (overlap * 100) + via))

    return best


def resolve_product(asset: Asset, advisory: Advisory) -> IdentityResult:
    """자산을 권고문의 product 항목들과 대조한다.

    후보를 **하나로 좁히지 않는다.** Siemens 는 같은 주문번호에 겹치는 범위를 가진
    product_id 를 여러 개 두므로(예: `>=3.1.6` 과 `>=3.1.6|<3.1.7`), 적용성 엔진이
    각각을 평가할 수 있어야 한다.
    """
    if not asset.identity.has_any:
        return IdentityResult(matches=(), resolvable=False)

    found: List[IdentityMatch] = []
    for p in advisory.products:
        m = _match_one(asset, p)
        if m is not None:
            found.append(m)

    if not found:
        return IdentityResult(matches=(), resolvable=True)

    best = min((m.level for m in found), key=lambda lv: _LEVEL_RANK[lv])
    top = tuple(m for m in found if m.level == best)

    # 충돌: 동일 최고 수준에서 서로 다른 제품명이 잡히면 사람 검토 대상
    distinct = {m.product.product_name for m in top}
    conflicting = best in MATCHED_LEVELS and len(distinct) > 1

    return IdentityResult(matches=top, resolvable=True, conflicting=conflicting)


# --------------------------------------------------------------------------
# 사전 필터 — 규모가 커지면 자산 × 권고문 전부를 판정할 수 없다
# --------------------------------------------------------------------------
# 이 필터는 **`_match_one` 의 필요조건**이다. 위 매칭 규칙을 고칠 때 여기도 같이
# 고쳐야 하므로 일부러 같은 파일에 둔다.
#
# 건전성: `_match_one` 이 무언가를 돌려주려면 넷 중 하나여야 한다.
#   Exact         주문번호가 model_numbers 에 있음
#   Deterministic vendor_ok (벤더 토큰 부분집합 관계 → 교집합 비지 않음)
#   Composite     vendor_ok
#   Fuzzy         자산 토큰과 제품명 토큰의 중첩 ≥ 0.6 → 교집합 비지 않음
# 따라서 '주문번호 불일치 + 토큰 교집합 공집합' 이면 어떤 제품과도 일치하지 않고,
# `decide_applicability` 는 3단계에서 `no_known_match` 를 돌려준다.
#
# **식별 재료가 아예 없는 자산은 건너뛰지 않는다** — 그쪽은 `no_known_match` 가
# 아니라 `insufficient_information` 이고, 그건 '해당 없음' 이 아니라 '판단 보류' 다.

@dataclass(frozen=True)
class AdvisoryIndex:
    """권고문 한 건에서 뽑은 대조용 색인. 권고문마다 한 번만 만든다."""
    advisory_id: str
    model_numbers: frozenset
    tokens: frozenset

    @property
    def empty(self) -> bool:
        return not (self.model_numbers or self.tokens)


def index_advisory(advisory: Advisory) -> AdvisoryIndex:
    numbers, toks = set(), set()
    for p in advisory.products:
        for m in p.model_numbers or ():
            numbers.add(_norm_id(m))
        toks |= _tokens(p.vendor)
        for variant in (p.name_variants or (p.product_name,)):
            toks |= _tokens(variant)
    return AdvisoryIndex(advisory.advisory_id, frozenset(numbers), frozenset(toks))


def could_match(asset: Asset, index: AdvisoryIndex) -> bool:
    """이 자산이 이 권고문의 제품 중 **하나라도** 일치할 가능성이 있는가.

    False 면 판정을 건너뛰어도 된다 — 결과가 `no_known_match` 로 확정이다.
    `tests/test_prefilter.py` 가 전 corpus 에서 이 동치를 실제로 확인한다.
    """
    ident = asset.identity
    if not ident.has_any:
        return True                      # 결과가 insufficient_information 이다
    if ident.order_number and _norm_id(ident.order_number) in index.model_numbers:
        return True
    probe = _tokens(ident.vendor_raw, ident.family_raw, ident.model_raw)
    return bool(probe & index.tokens)
