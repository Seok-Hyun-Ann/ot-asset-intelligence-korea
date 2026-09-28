# -*- coding: utf-8 -*-
"""다중 소스 비교와 필드별 권위 (FR-SRC-005, 표 13).

**자동 덮어쓰기를 하지 않는다** — 모든 주장을 보존하고, 화면의 '현재 값' 은
권위·시점 규칙으로 **계산한 뷰**다 (불변 규칙 3).

### 실데이터로 확인된 두 가지 (2026-09-09)

1. **`publisher.category` 를 믿을 수 없다.** 같은 CISA 가 `icsa-26-036-02` 에서는
   `coordinator`, `icsa-26-071-04` 에서는 `other` 를 선언한다. 따라서 권위는
   **알려진 발행처 표**로 판단하고, 표에 없을 때만 선언 값을 쓴다. 어느 쪽을
   썼는지도 함께 기록한다 (R04: 벤더 권고 비정형).

2. **CISA 는 Siemens 문서를 그대로 재발행한다.** `ICSA-26-071-04` ↔ `SSA-452276`
   는 157개 product, 버전 범위, CVSS, 135개 주문번호가 **완전히 일치**한다.
   즉 이 경로에서 흔한 것은 모순이 아니라 **일치와 시점 차이**다.
   FR-SRC-005 는 "모순 탐지"가 아니라 "덮어쓰기 금지"이므로 기능은 그대로 성립한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .csaf import Advisory

# 알려진 발행처의 실제 역할. 선언된 category 보다 우선한다.
# 조정기관 — 권고문을 모아 재발행한다. 제품 영향의 1차 근거는 아니다 (표 13).
COORDINATORS: Tuple[str, ...] = (
    "CISA", "JPCERT", "NCSC", "CERT@VDE", "CERT-VDE", "BSI", "KrCERT",
    "ICS-CERT", "US-CERT", "CERT/CC", "NCCIC",
)

# 제품을 만드는 조직 — 자기 제품의 영향 범위에 대해 1차 권위를 갖는다 (표 13).
# 이름은 **코퍼스에 실제로 나타나는 문자열**에서 가져왔다. 지어낸 것이 아니다.
# 부분 일치로 비교하므로 "Siemens" 가 "Siemens ProductCERT" 를 잡는다.
VENDOR_ORGS: Tuple[str, ...] = (
    "Siemens", "Mitsubishi Electric", "Schneider Electric", "Rockwell Automation",
    "Hitachi Energy", "ABB", "Festo", "Mobotix", "Milesight", "AutomationDirect",
    "AVEVA", "Johnson Controls", "Delta Electronics", "WAGO", "Yealink", "PTC",
    "TP-Link", "Yokogawa", "Honeywell", "B&R Industrial Automation", "B&R",
    "Automated Logic", "Emerson", "National Instruments", "Lantronix",
    "HID Global", "Kieback", "Subnet Solutions", "Phoenix Contact", "Moxa",
    "Omron", "Beckhoff", "Pilz", "SICK", "Belden", "Hirschmann", "Advantech",
    "Red Lion", "Bosch", "Panasonic", "Fuji Electric", "Hitachi",
)

KNOWN_PUBLISHERS: Dict[str, str] = {name: "coordinator" for name in COORDINATORS}
KNOWN_PUBLISHERS.update({name: "vendor" for name in VENDOR_ORGS})

# 표에 없는 발행처. **권위를 주지 않는다** — 스스로 밝힌 값을 믿는 순간
# ADR-024 가 막으려던 일이 그대로 일어난다.
UNVERIFIED = "unverified"

# 표 13: 필드별로 이기는 소스가 다르다
FIELD_AUTHORITY: Dict[str, Tuple[str, ...]] = {
    "version_range": ("vendor", "coordinator", "other", UNVERIFIED),
    "product_status": ("vendor", "coordinator", "other", UNVERIFIED),
    "remediation": ("vendor", "coordinator", "other", UNVERIFIED),
    "cvss": ("cna", "vendor", "coordinator", "other", UNVERIFIED),
}

# 충돌 필드가 아니라 출처 정보다 — 다르다고 해서 모순이 아니다
PROVENANCE_FIELDS = ("current_release_date", "advisory_id", "revision")


def publisher_role(adv: Advisory) -> Tuple[str, str]:
    """(역할, 판단 근거). **선언 값을 믿지 않는다** (ADR-024).

    표에 있으면 표를 쓰고, 없으면 `unverified` 다. `declared_category` 로 조용히
    넘어가지 않는다 — 같은 CISA 가 파일마다 `coordinator` 와 `other` 를 섞어
    선언하는 것이 실측으로 확인됐다 (1,303건 중 565건이 `other`).

    `unverified` 는 모든 필드 권위에서 맨 뒤라, 검증되지 않은 출처가 검증된 출처를
    이기지 않는다. 값 자체는 여전히 보존되고 화면에 보인다.
    """
    name = (adv.publisher_name or "").strip()
    if not name:
        return UNVERIFIED, "발행처 이름 없음"
    if name in KNOWN_PUBLISHERS:
        return KNOWN_PUBLISHERS[name], "known_publisher_table"
    low = name.lower()
    # 조정기관을 먼저 본다 — 조정기관 이름 안에 제조사 이름이 들어가는 경우가 있다
    for known in COORDINATORS:
        if known.lower() in low:
            return "coordinator", "known_publisher_table(부분일치)"
    for known in VENDOR_ORGS:
        if known.lower() in low:
            return "vendor", "known_publisher_table(부분일치)"
    return UNVERIFIED, "표에 없는 발행처 — 선언값 %r 는 믿지 않는다" % (
        adv.publisher_category or "없음")


@dataclass(frozen=True)
class Claim:
    field: str
    value: str
    source_id: str
    source_role: str
    role_basis: str
    source_sha256: str
    released_at: Optional[str]

    def __str__(self):
        return "%s=%r (%s / %s)" % (self.field, self.value, self.source_id, self.source_role)


@dataclass
class FieldView:
    """계산된 '현재 값'. 저장된 것이 아니다."""
    field: str
    current: Claim
    claims: Tuple[Claim, ...]
    conflicting: bool
    reason: str
    # 값이 여럿이라고 다 충돌은 아니다 — 셋을 구분한다 (7.2)
    multivalued: bool = False
    disjoint: bool = False
    undecidable: bool = False
    # 실제로 부딪히는 값 쌍. '채택' 하나만 보여주면 논쟁과 무관한 값이 나올 수 있다.
    disputed: Tuple[Tuple[str, str, str, str], ...] = ()   # (값A, 출처A, 값B, 출처B)

    @property
    def corroborated_by(self) -> Tuple[str, ...]:
        return tuple(sorted(c.source_id for c in self.claims
                            if c.source_id != self.current.source_id
                            and c.value == self.current.value))

    @property
    def dissenting(self) -> Tuple[Claim, ...]:
        return tuple(c for c in self.claims if c.value != self.current.value)


def _overlaps(a_raw: str, b_raw: str) -> Optional[bool]:
    """두 버전 범위가 겹치는가. 판단할 수 없으면 None.

    겹치지 않는 두 범위는 **모순이 아니다** — 같은 제품의 다른 분기다
    (예: RTU500 의 12.7.x 와 13.5.x 는 둘 다 영향받는다).
    """
    from .versions import parse_range

    ra, rb = parse_range(a_raw), parse_range(b_raw)
    if ra.wildcard or rb.wildcard:
        return True                       # '모든 버전' 은 무엇과도 겹친다
    if not (ra.parseable and rb.parseable):
        return None                       # 모르면 모른다
    lo_a, hi_a = _bounds(ra)
    lo_b, hi_b = _bounds(rb)
    if lo_a is None or lo_b is None:
        return None
    return not (hi_a < lo_b or hi_b < lo_a)


_INF = (10 ** 9,)


def _bounds(rng):
    """(하한, 상한). 열린 쪽은 (0,) 과 _INF 로 채운다."""
    lo, hi = (0,), _INF
    for c in rng.constraints:
        if c.op in (">=", ">"):
            lo = max(lo, c.version)
        elif c.op in ("<=", "<"):
            hi = min(hi, c.version)
        elif c.op == "=":
            lo = hi = c.version
    if lo > hi:
        return None, None
    return lo, hi


def _rank(role: str, field_name: str) -> int:
    order = FIELD_AUTHORITY.get(field_name, ("vendor", "coordinator", "other"))
    return order.index(role) if role in order else len(order)


def resolve_field(field_name: str, claims: Sequence[Claim]) -> Optional[FieldView]:
    """주장들을 표 13 권위로 정리한다.

    **값이 여럿이라고 충돌이 아니다.** 한 출처가 같은 제품에 범위를 여럿 적는 것은
    흔하고 정상이다 (Siemens 가 주문번호 하나에 여러 product_id 를 두는 식).
    충돌은 *서로 다른 출처*가 *겹치는 범위*에 대해 다르게 말할 때다 (7.2).
    """
    if not claims:
        return None
    ordered = sorted(claims, key=lambda c: (_rank(c.source_role, field_name),
                                            c.released_at or "", c.source_id))
    winner = ordered[0]
    values = {c.value for c in claims}
    multivalued = len(values) > 1

    by_source: Dict[str, set] = {}
    for c in claims:
        by_source.setdefault(c.source_id, set()).add(c.value)
    sources_differ = len({frozenset(v) for v in by_source.values()}) > 1

    conflicting = disjoint = undecidable = False
    disputed: Tuple = ()
    if multivalued and sources_differ and field_name == "version_range":
        # 출처가 다르다. 범위가 실제로 겹치는지 본다.
        srcs = sorted(by_source)
        verdicts, pairs = [], []
        for i, sa in enumerate(srcs):
            for sb in srcs[i + 1:]:
                for va in sorted(by_source[sa]):
                    for vb in sorted(by_source[sb]):
                        if va == vb:
                            continue
                        verdicts.append(_overlaps(va, vb))
                        pairs.append((va, sa, vb, sb))
        if any(v is True for v in verdicts):
            conflicting = True
            disputed = tuple(d for d, v in zip(pairs, verdicts) if v is True)
        elif verdicts and all(v is False for v in verdicts):
            disjoint = True
        elif verdicts:
            undecidable = True
    elif multivalued and sources_differ:
        conflicting = True          # 범위가 아닌 필드는 값이 다르면 충돌이다

    if conflicting:
        reason = ("서로 다른 소스가 **겹치는 범위**에 대해 다르게 말합니다. "
                  "표 13 에 따라 %s 권위(%s)를 채택하고 나머지 주장도 보존합니다."
                  % (winner.source_role, winner.source_id))
    elif disjoint:
        reason = ("소스마다 값이 다르지만 **범위가 겹치지 않습니다** — 같은 제품의 "
                  "서로 다른 분기입니다. 모순이 아니므로 모두 유효합니다.")
    elif undecidable:
        reason = ("소스마다 값이 다른데 범위를 파싱하지 못해 **겹치는지 판단할 수 "
                  "없습니다.** 충돌로 단정하지 않고 사람 확인 대상으로 둡니다.")
    elif multivalued:
        reason = ("한 소스(%s)가 이 제품에 범위를 %d개 말합니다. 출처 간 불일치가 "
                  "아닙니다." % (winner.source_id, len(values)))
    else:
        others = [c.source_id for c in claims if c.source_id != winner.source_id]
        reason = ("모든 소스가 같은 값을 말합니다%s."
                  % (" (교차 확인: %s)" % ", ".join(sorted(others)) if others else ""))
    if winner.source_role == UNVERIFIED:
        reason += (" 다만 이 발행처는 **권위를 확인하지 못했습니다** — 값은 보여주되"
                   " 근거로 삼기 전에 사람이 확인해야 합니다.")
    return FieldView(field_name, winner, tuple(ordered), conflicting, reason,
                     multivalued=multivalued, disjoint=disjoint,
                     undecidable=undecidable, disputed=disputed)


# --------------------------------------------------------------------------
# 권고문 연결
# --------------------------------------------------------------------------
@dataclass
class LinkedAdvisory:
    """같은 사안을 다루는 권고문 묶음."""
    cves: Tuple[str, ...]
    advisories: Tuple[Advisory, ...]
    corroboration: Tuple[str, ...] = ()   # 참조 문자열로 확인된 근거

    @property
    def source_ids(self) -> Tuple[str, ...]:
        return tuple(a.advisory_id for a in self.advisories)

    @property
    def sha256s(self) -> Dict[str, str]:
        """양쪽 원문 해시를 모두 들고 다닌다.

        한쪽만 기록하면 **다른 쪽이 개정돼도 해시가 그대로**여서 재현성이 깨진다.
        """
        return {a.advisory_id: a.sha256 for a in self.advisories}


def link_advisories(advisories: Sequence[Advisory]) -> List[LinkedAdvisory]:
    """CVE 교집합으로 묶는다.

    제품 겹침은 근거가 약하고, 참조 문자열은 형식이 보장되지 않는다.
    CVE 는 두 소스가 반드시 공유하는 유일한 식별자다.
    """
    groups: Dict[frozenset, List[Advisory]] = {}
    for adv in advisories:
        cves = frozenset(v.cve for v in adv.vulnerabilities if v.cve)
        if not cves:
            continue
        placed = False
        for key in list(groups):
            if key & cves:
                merged = key | cves
                bucket = groups.pop(key)
                bucket.append(adv)
                groups[merged] = bucket
                placed = True
                break
        if not placed:
            groups[cves] = [adv]

    out = []
    for cves, advs in groups.items():
        corro = []
        ids = {a.advisory_id for a in advs}
        for a in advs:
            for other in ids - {a.advisory_id}:
                if other in (a.title or ""):
                    corro.append("%s→%s(제목)" % (a.advisory_id, other))
        out.append(LinkedAdvisory(tuple(sorted(cves)),
                                  tuple(sorted(advs, key=lambda x: x.advisory_id)),
                                  tuple(sorted(corro))))
    return sorted(out, key=lambda g: g.cves)


# --------------------------------------------------------------------------
# 제품 단위 비교
# --------------------------------------------------------------------------
@dataclass
class ProductComparison:
    key: str                     # 비교 기준 (주문번호 또는 제품명)
    views: Dict[str, FieldView]
    @property
    def conflicting(self) -> bool:
        """서로 다른 출처가 겹치는 범위를 다르게 말한다 — 진짜 충돌."""
        return any(v.conflicting for v in self.views.values())

    @property
    def multivalued(self) -> bool:
        return any(v.multivalued for v in self.views.values())

    @property
    def disjoint(self) -> bool:
        return any(v.disjoint for v in self.views.values())

    @property
    def undecidable(self) -> bool:
        return any(v.undecidable for v in self.views.values())


def compare_products(link: LinkedAdvisory) -> List[ProductComparison]:
    """연결된 권고문들의 같은 제품에 대한 주장을 필드별로 대조한다."""
    buckets: Dict[str, List[Claim]] = {}
    for adv in link.advisories:
        role, basis = publisher_role(adv)
        for p in adv.products:
            key = p.model_numbers[0] if p.model_numbers else p.product_name
            if p.version_raw is None:
                continue
            buckets.setdefault(key, []).append(
                Claim("version_range", p.version_raw, adv.advisory_id, role, basis,
                      adv.sha256, adv.current_release_date))

    out = []
    for key, claims in sorted(buckets.items()):
        view = resolve_field("version_range", claims)
        if view is not None:
            out.append(ProductComparison(key, {"version_range": view}))
    return out


def compare_cvss(link: LinkedAdvisory) -> Optional[FieldView]:
    claims = []
    for adv in link.advisories:
        role, basis = publisher_role(adv)
        for v in adv.vulnerabilities:
            score, vector = v.cvss()
            if vector:
                claims.append(Claim("cvss", vector, adv.advisory_id, role, basis,
                                    adv.sha256, adv.current_release_date))
                break
    return resolve_field("cvss", claims)


def provenance_table(link: LinkedAdvisory) -> List[dict]:
    """시점·개정 차이는 충돌이 아니라 출처 정보다."""
    rows = []
    for adv in link.advisories:
        role, basis = publisher_role(adv)
        rows.append({
            "advisory_id": adv.advisory_id,
            "publisher": adv.publisher_name,
            "role": role,
            "role_basis": basis,
            "declared_category": adv.publisher_category,
            "released_at": adv.current_release_date,
            "sha256": adv.sha256,
            "products": len(adv.products),
        })
    return sorted(rows, key=lambda r: r["advisory_id"])
