# -*- coding: utf-8 -*-
"""적용성 판정 엔진 — 부록 D 의사코드의 구현.

**결정적 규칙 모듈이다. LLM 이 관여하지 않는다** (표 32 금지 항목:
버전 비교, affected/not_affected 확정).

상태 매핑은 표 19 를 따른다:

  제품    버전         구성      VEX              출력
  일치    영향 범위    충족      known_affected   affected_confirmed
  일치    미상         미상      없음             insufficient_information
  후보    미상         미상      없음             candidate
  후보    영향 범위    미상      없음             affected_likely
  일치    범위 밖      무관      없음             not_affected_confirmed
  일치    수정 버전    패치 증거 -                fixed
  상충    상충         상충      상충             conflicting_evidence
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Dict, List, Optional, Tuple

from .csaf import Advisory, ProductEntry
from .identity import IdentityResult, resolve_product
from .logic import Tri
from .model import DEFAULT_FRESHNESS_DAYS, Asset, Component, parse_ts
from .capability import grants_from_cvss, requires_from_cvss
from .versions import in_range, parse_range

# 1.1.0: vers:all/* 를 와일드카드로 인식 (ADR-023). 판정이 바뀌므로 버전을 올린다.
RULE_VERSION = "applicability/1.1.0"

# 부록 B 한국어 문구 — UI 문자열의 정본
PHRASES = {
    "affected_confirmed": "적용 확인",
    "affected_likely": "적용 가능성 높음",
    "candidate": "후보",
    "insufficient_information": "정보 부족",
    "not_affected_confirmed": "비영향 확인",
    "fixed": "수정 확인",
    "conflicting_evidence": "근거 충돌",
    "stale": "정보 오래됨",
    "no_known_match": "현재 일치 항목 없음",
}

# 확정 상태는 신선한 증거를 요구한다
CONFIRMED_STATES = ("affected_confirmed", "not_affected_confirmed")

#: 관측이 아니라 **주장**인 수집 방법 (ADR-038).
#:
#: 엔지니어링 프로젝트 파일은 '이 프로젝트가 대상으로 설정한 버전' 을 담는다.
#: 장비에서 읽은 값이 아니다 — 장비를 바꿨거나 현장에서 펌웨어를 올렸으면
#: 프로젝트는 그대로여도 실제는 다르다. 이 값으로 '안전' 쪽 결론에 도달하면
#: 아무도 관측하지 않은 버전으로 안전을 선언하는 것이다.
#:
#: 식별(주문번호)은 여기 해당하지 않는다 — 그건 문서화된 현장 기록이고,
#: 오래되면 신선도 정책이 따로 잡는다.
CLAIMED_METHODS = ("project_file",)


def is_claimed(component) -> bool:
    """이 부품의 버전이 관측값이 아니라 설정값인가."""
    return bool(component is not None and component.method in CLAIMED_METHODS)


@dataclass
class Decision:
    status: str
    phrase_ko: str
    identity_level: Optional[str]
    identity_confidence: float
    decisive_conditions: List[str]
    fields: Dict[str, List[str]]
    evidence: Dict[str, object]
    next_best_question: Optional[str]
    as_of: str
    rule_version: str
    parser_version: str
    input_hash: str
    asset_id: str
    cves: Tuple[str, ...] = ()
    max_cvss: Optional[float] = None
    cvss_vector: Optional[str] = None
    grants: Tuple[str, ...] = ()      # 이 취약점이 공격자에게 주는 능력
    requires: Tuple[str, ...] = ()    # 쓰려면 이미 있어야 하는 능력

    def to_card(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "status": self.status,
            "phrase_ko": self.phrase_ko,
            "identity_level": self.identity_level,
            "identity_confidence": self.identity_confidence,
            "decisive_conditions": self.decisive_conditions,
            "fields": self.fields,
            "evidence": self.evidence,
            "next_best_question": self.next_best_question,
            "cves": list(self.cves),
            "max_cvss": self.max_cvss,
            "cvss_vector": self.cvss_vector,
            "grants": list(self.grants),
            "requires": list(self.requires),
            "as_of": self.as_of,
            "rule_version": self.rule_version,
            "parser_version": self.parser_version,
            "input_hash": self.input_hash,
        }

    def canonical_json(self) -> str:
        """결정적 직렬화. wall-clock 은 어디에도 등장하지 않는다."""
        return json.dumps(self.to_card(), ensure_ascii=False, sort_keys=True, indent=2)


# --------------------------------------------------------------------------
# 부품 선택
# --------------------------------------------------------------------------
def select_component(asset: Asset, product: ProductEntry) -> Optional[Component]:
    """권고문의 product 가 가리키는 자산 부품을 고른다.

    슬라이스 1 규칙: 부품 type 토큰과 제품명 토큰의 중첩이 가장 큰 것.
    부품이 하나뿐이면 그것을 쓴다.

    **부품이 여럿인데 어느 것도 제품명과 겹치지 않으면 None 을 돌려준다.**
    임의로 첫 부품을 골라 비교하면 엉뚱한 부품의 버전으로 '비영향 확인' 이
    나올 수 있다 — HMI 의 OS 버전으로 런타임 권고를 판정하는 식의 false safe.
    None 은 상위에서 UNKNOWN 으로 이어져 정보 부족 판정이 된다.
    """
    if not asset.components:
        return None
    if len(asset.components) == 1:
        return asset.components[0]

    import re
    tok = lambda s: set(re.findall(r"[a-z0-9]+", (s or "").lower()))
    pname = tok(product.product_name) | tok(product.full_name)
    best, best_score = None, 0
    for c in asset.components:
        score = len(tok(c.type) & pname)
        if score > best_score:
            best, best_score = c, score
    return best  # 중첩이 전혀 없으면 None


def _compute_input_hash(asset: Asset, advisory: Advisory, as_of: str,
                        freshness_days: int) -> str:
    """판정을 재현하는 데 필요한 입력만 해싱한다 (NFR-EXP-001).

    신선도 정책도 입력이다 — 같은 자산·같은 권고라도 정책이 다르면 stale 과
    affected_confirmed 로 갈리므로 해시가 달라야 한다.
    """
    payload = {
        "as_of": as_of,
        "freshness_days": freshness_days,
        "rule_version": RULE_VERSION,
        "parser_version": advisory.parser_version,
        "advisory_sha256": advisory.sha256,
        "asset_id": asset.asset_id,
        "identity": {
            "vendor_raw": asset.identity.vendor_raw,
            "family_raw": asset.identity.family_raw,
            "model_raw": asset.identity.model_raw,
            "order_number": asset.identity.order_number,
        },
        "components": [
            {
                "type": c.type,
                "version_raw": c.version_raw,
                "version_state": c.version_state,
                "observed_at": c.observed_at,
            }
            for c in asset.components
        ],
        "remediation_evidence": [
            {"advisory_id": r.get("advisory_id"), "observed_at": r.get("observed_at")}
            for r in asset.remediation_evidence
        ],
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _vex_status(advisory: Advisory, product_ids) -> Dict[str, bool]:
    """권고문이 이 product 들에 대해 선언한 VEX 상태를 모은다."""
    seen = {"known_affected": False, "known_not_affected": False,
            "fixed": False, "under_investigation": False}
    for v in advisory.vulnerabilities:
        for pid in product_ids:
            for key in v.status_of(pid):
                if key in seen:
                    seen[key] = True
    return seen


def _cvss_for(advisory: Advisory, product_ids) -> Tuple[Optional[float], Optional[str]]:
    """일치한 product 에 걸린 CVE 중 최대 CVSS 와 그 벡터."""
    ids = set(product_ids)
    best, vector = None, None
    for v in advisory.vulnerabilities:
        if not any(pid in ids for pid in v.product_status.get("known_affected", ())):
            continue
        score, vec = v.cvss()
        if score is not None and (best is None or score > best):
            best, vector = score, vec
    return best, vector


def _affected_cves(advisory: Advisory, product_ids) -> Tuple[str, ...]:
    """일치한 product 들이 known_affected 로 걸린 CVE 목록.

    우선순위 엔진(슬라이스 2)이 KEV·EPSS 와 조인하는 키다. 하나의 권고가 431개
    CVE 를 담는 경우(Siemens SSA-019113)가 실제로 있으므로 단수가 아니라 목록이다.
    """
    ids = set(product_ids)
    out = []
    for v in advisory.vulnerabilities:
        if not v.cve:
            continue
        if any(pid in ids for pid in v.product_status.get("known_affected", ())):
            out.append(v.cve)
    return tuple(sorted(set(out)))


# --------------------------------------------------------------------------
# 부록 D: decide_applicability
# --------------------------------------------------------------------------
def decide_applicability(
    asset: Asset,
    advisory: Advisory,
    as_of: str,
    freshness_days: int = DEFAULT_FRESHNESS_DAYS,
) -> Decision:
    as_of_date = parse_ts(as_of)
    if as_of_date is None:
        raise ValueError("as_of 를 날짜로 읽을 수 없습니다: %r" % as_of)

    projected = asset.as_of(as_of_date)
    input_hash = _compute_input_hash(projected, advisory, as_of, freshness_days)

    matched: List[str] = []
    mismatched: List[str] = []
    missing: List[str] = []
    conditions: List[str] = []
    question: Optional[str] = None
    raw_expression: Optional[str] = None

    def build(status: str, level=None, conf=0.0, cves=(), cvss=(None, None)) -> Decision:
        score, vector = cvss
        return Decision(
            status=status,
            phrase_ko=PHRASES[status],
            identity_level=level,
            identity_confidence=conf,
            decisive_conditions=conditions,
            fields={"matched": matched, "mismatched": mismatched, "missing": missing},
            evidence={
                "advisory_id": advisory.advisory_id,
                "advisory_title": advisory.title,
                "publisher": advisory.publisher_name,
                "publisher_category": advisory.publisher_category,
                "advisory_sha256": advisory.sha256,
                "source_path": advisory.source_path,
                "current_release_date": advisory.current_release_date,
                "raw_expression": raw_expression,
            },
            next_best_question=question,
            as_of=as_of,
            rule_version=RULE_VERSION,
            parser_version=advisory.parser_version,
            input_hash=input_hash,
            asset_id=asset.asset_id,
            cves=tuple(cves),
            max_cvss=score,
            cvss_vector=vector,
            grants=tuple(sorted(grants_from_cvss(vector))),
            requires=tuple(sorted(requires_from_cvss(vector))),
        )

    # --- 1. 자산에 식별 재료가 있는가 ---
    ident: IdentityResult = resolve_product(projected, advisory)
    if not ident.resolvable:
        missing.append("identity.vendor_raw / model_raw")
        conditions.append("자산에 제조사·모델 정보가 전혀 없어 제품을 특정할 수 없습니다.")
        question = "이 장치의 제조사와 모델(주문번호)을 확인해 주세요. 판정에 필요한 최소 정보입니다."
        return build("insufficient_information")

    # --- 2. 식별 충돌 ---
    if ident.conflicting:
        names = sorted({m.product.product_name for m in ident.matches})
        conditions.append("동일 확신 수준에서 서로 다른 제품이 일치합니다: %s" % ", ".join(names))
        return build("conflicting_evidence", ident.best_level, ident.confidence)

    # --- 3. 권고문에 일치하는 제품이 없음 ---
    if not ident.matches:
        mismatched.append("vendor/product_name")
        conditions.append(
            "이 권고문의 대상 제품 목록에서 일치 항목을 찾지 못했습니다 "
            "(권고 대상: %s)." % (advisory.products[0].vendor if advisory.products else "미상")
        )
        # 부록 B: "안전 표현 금지" — 이 경로의 어떤 문구에도 안전 어휘를 쓰지 않는다
        conditions.append(
            "이는 이 권고문 한 건에 한정된 결과입니다. 다른 권고문의 영향 여부는 "
            "별도로 판정해야 합니다."
        )
        question = "다른 권고문 범위를 넓히거나, 제조사·모델 표기가 정확한지 확인해 주세요."
        return build("no_known_match", None, 0.0)

    level = ident.best_level
    conf = ident.confidence
    matched_pids = [m.product.product_id for m in ident.matches]
    cves = _affected_cves(advisory, matched_pids)
    cvss = _cvss_for(advisory, matched_pids)
    matched.append("vendor=%s" % (ident.matches[0].product.vendor or "?"))
    matched.append("product_name=%s" % ident.matches[0].product.product_name)
    conditions.append("식별 수준 %s — %s" % (level, ident.matches[0].reason))

    # --- 4. 버전 범위를 삼진 논리로 평가 ---
    results: List[Tri] = []
    deciding: Optional[Component] = None
    ranges_seen: List[str] = []
    ambiguous_component = False
    for m in ident.matches:
        comp = select_component(projected, m.product)
        if comp is None and len(projected.components) > 1:
            ambiguous_component = True
        rng = parse_range(m.product.version_raw)
        if m.product.version_raw is not None and m.product.version_raw not in ranges_seen:
            ranges_seen.append(m.product.version_raw)
        version_raw = comp.version_raw if comp else None
        r = in_range(version_raw, rng)
        results.append(r)
        if deciding is None or r is Tri.TRUE:
            deciding = comp

    # 여러 product 가 일치하면(Siemens 의 겹치는 범위) 원문을 전부 보존한다
    raw_expression = " | ".join(ranges_seen) if ranges_seen else None
    version_verdict = Tri.or_(*results) if results else Tri.UNKNOWN

    comp_desc = deciding.type if deciding else "component"
    # 이 버전이 관측값인가 설정값인가. 아래 결론 단계가 이걸 본다 (ADR-038).
    claimed = is_claimed(deciding)
    if claimed:
        conditions.append(
            "이 버전은 엔지니어링 프로젝트 파일에 **설정된** 값입니다. 장비에서 읽은 "
            "값이 아니므로 확정 근거로 쓰지 않습니다."
        )
    if version_verdict is Tri.TRUE:
        matched.append("%s=%s ∈ %s" % (comp_desc, deciding.version_raw, raw_expression))
        conditions.append(
            "버전 %s 가 영향 범위 %s 에 포함됩니다." % (deciding.version_raw, raw_expression)
        )
    elif version_verdict is Tri.FALSE:
        mismatched.append("%s=%s ∉ %s" % (comp_desc, deciding.version_raw, raw_expression))
        conditions.append(
            "버전 %s 가 영향 범위 %s 밖입니다." % (deciding.version_raw, raw_expression)
        )
    else:
        missing.append("%s.version" % comp_desc)
        conditions.append(
            "버전을 확인할 수 없어 영향 범위 %s 와 대조하지 못했습니다. "
            "미상을 '해당 없음'으로 처리하지 않습니다." % raw_expression
        )
        question = (
            "%s 의 정확한 버전을 확인해 주세요. 현재 영향 범위는 %s 이며, "
            "이 값 하나로 적용 확인과 비영향 확인이 갈립니다." % (comp_desc, raw_expression)
        )

    # 부품을 특정하지 못한 경우가 더 정확한 진단이므로 위 문구를 덮어쓴다
    if ambiguous_component:
        missing.append("어느 부품에 대한 권고인지 불명")
        conditions.append(
            "자산에 부품이 여럿인데 권고 대상 제품과 이름이 겹치는 부품이 없어 "
            "비교 대상을 특정하지 못했습니다. 임의로 한 부품을 골라 비교하지 않습니다."
        )
        question = (
            "이 권고문이 가리키는 부품이 %s 중 무엇인지 확인해 주세요."
            % ", ".join(c.type for c in projected.components)
        )

    # --- 5. VEX 상태 ---
    # not_affected 와 fixed 는 '안전' 쪽 결론이므로 표 19 의 '일치' 를 요구한다.
    # 식별이 후보 수준일 때 여기로 빠지면 잘못된 제품의 벤더 선언으로 비영향을
    # 확정하게 된다 — false safe 의 전형적인 경로다.
    vex = _vex_status(advisory, matched_pids)
    if vex["known_not_affected"] and ident.is_matched:
        conditions.append("공급자가 이 제품을 known_not_affected 로 선언했습니다.")
        return build("not_affected_confirmed", level, conf, cves, cvss)
    if vex["under_investigation"]:
        conditions.append("공급자가 아직 조사 중(under_investigation)으로 선언했습니다.")
        return build("insufficient_information", level, conf, cves, cvss)

    # --- 6. 패치 증거 → fixed (표 10: 설치 증거가 있어야 한다) ---
    remediation = projected.remediation_for(advisory.advisory_id)
    if remediation and version_verdict is Tri.FALSE and ident.is_matched and not claimed:
        matched.append("remediation_evidence=%s" % remediation.get("evidence_id"))
        conditions.append(
            "수정 버전 설치 증거(%s)가 확인되었습니다." % remediation.get("evidence_id")
        )
        # 참고: 패치 증거가 오래되어도 fixed 를 유지한다. 표 10 은 fixed 의 후속을
        # '회귀 상태 모니터' 로 규정하므로 재관측은 stale 이 아니라 모니터링 대상이다.
        return build("fixed", level, conf, cves, cvss)

    # --- 7. 표 19 매핑 ---
    if ident.is_matched and claimed:
        # 식별은 확정됐지만 **버전이 관측값이 아니다**. 확정 어휘를 쓰지 않는다.
        if version_verdict is Tri.TRUE:
            status = "affected_likely"
            conditions.append(
                "설정된 버전이 영향 범위 안이지만, 실제 장비의 버전을 확인하기 "
                "전에는 '확인'이 아닌 '가능성 높음'으로 유지합니다."
            )
        elif version_verdict is Tri.FALSE:
            # 범위 밖이어도 **비영향으로 확정하지 않는다.** 프로젝트가 최신이
            # 아닐 수 있고, 그 경우 실제 장비는 영향 범위 안에 있다.
            status = "insufficient_information"
            conditions.append(
                "설정된 버전은 영향 범위 밖이지만, 그것이 실제 장비의 버전이라는 "
                "증거가 없습니다. 미상을 '해당 없음'으로 처리하지 않습니다."
            )
        else:
            # 비교 자체를 못 했다. '범위 밖' 이라고 말하면 거짓이다 — 위쪽 4단계가
            # 이미 "대조하지 못했습니다" 를 달아 뒀으므로 덧붙이지 않는다.
            status = "insufficient_information"
        question = question or (
            "%s 의 **실제** 펌웨어 버전을 장비에서 확인해 주세요. 프로젝트 파일의 "
            "설정값(%s)과 다를 수 있습니다." % (comp_desc, deciding.version_raw
                                        if deciding else "미상")
        )
    elif ident.is_matched:
        if version_verdict is Tri.TRUE:
            status = "affected_confirmed"
        elif version_verdict is Tri.FALSE:
            status = "not_affected_confirmed"
        else:
            status = "insufficient_information"
    else:
        # 후보 수준 식별 — 확정 어휘를 쓰지 않는다
        if version_verdict is Tri.TRUE:
            status = "affected_likely"
            conditions.append(
                "제품 식별이 %s 수준이라 '확인'이 아닌 '가능성 높음'으로 유지합니다." % level
            )
            question = question or (
                "정확한 모델(주문번호)을 확인해 주세요. 확정되면 적용 확인으로 승격됩니다."
            )
        else:
            # 식별이 약하면 범위 밖이라도 비영향으로 확정하지 않는다 (false safe 방지)
            status = "candidate"
            conditions.append(
                "제품 식별이 %s 수준이므로 버전 비교 결과를 확정 근거로 쓰지 않습니다." % level
            )
            question = question or "정확한 모델(주문번호)을 확인해 주세요."

    # --- 8. 신선도: '확정'은 신선한 증거를 요구한다 (표 10 stale) ---
    if status in CONFIRMED_STATES and deciding is not None:
        od = deciding.observed_date
        if od is not None and (as_of_date - od) > timedelta(days=freshness_days):
            conditions.insert(
                0,
                "관측 시점 %s 이 신선도 정책(%d일)을 초과했습니다. 재수집 전에는 확정하지 않습니다."
                % (deciding.observed_at, freshness_days),
            )
            question = "%s 의 버전을 다시 관측해 주세요." % comp_desc
            return build("stale", level, conf, cves, cvss)

    return build(status, level, conf, cves, cvss)
