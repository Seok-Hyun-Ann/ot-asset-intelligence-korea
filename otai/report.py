# -*- coding: utf-8 -*-
"""보고서 자료 모으기 (ADR-049).

**상사와 감사인에게 줄 것이 없었다.** 오프라인 번들과 원시 JSON 뿐이고 엑셀도
인쇄물도 없었다. KISA 51항목 + NIST 229항목 매핑을 애써 넣어 놓고 출력이 터미널
텍스트라면 그 작업의 수혜자가 없다. 예산 없는 팀이 도구 존속을 정당화할 수단이
0개라는 뜻이기도 하다.

**규칙을 다시 쓰지 않는다.** `queue` 와 **같은 파이프라인**으로 판정·노출·도달성·
점검 항목을 만들고 모아 담기만 한다. 보고서가 따로 계산하면 화면과 다른 수를
말하게 된다 — 이 저장소가 반복해 겪은 실수다.

**시계를 읽지 않는다** (불변 규칙 4). 보고서에 '생성 시각' 이 없고 **기준 시점
(`as_of`)** 만 있다. 그래서 같은 입력이면 같은 보고서가 나오고, 감사인이 다시
돌려 해시를 맞춰 볼 수 있다 — 보고서가 재현 가능하다는 것은 제약이 아니라 기능이다.

**주장하지 않는 것을 보고서가 직접 싣는다.** 등급 정확도·경로 탐지 정확도를
주장하지 않고, 자산이 합성이면 그 사실을 표지에 적고, 공개 권고문이 희박한
제조사를 세어 이름을 부른다 (ADR-046).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .applicability import PHRASES, decide_applicability
from .controls import (ABSENT, NOT_ASSESSABLE, PRESENT, SCOPE_KO, STATUS_KO,
                       evidence_for, load_all)
from .exposure import find as find_exposure
from .identity import could_match, index_advisory
from .logic import Tri
from .paths import evaluate_reachability
from .priority import BUCKET_ORDER, BUCKET_PHRASES, evaluate_priority, sort_queue
from .repo import completeness

#: 보고서가 반드시 싣는 문장. 지우지 말 것 — 이게 없으면 등급이 사실로 읽힌다.
DISCLAIMERS = (
    "조치 등급(P0~P4)의 **정확도는 주장하지 않습니다.** 전문가 합의 골드셋이 없어 "
    "검증은 규칙 발화와 불변량까지입니다 (ADR-008).",
    "공격 경로 탐지의 **정확도도 주장하지 않습니다.** '그때 실제로 어떤 경로가 "
    "존재했는가' 를 아는 정답 집합이 없습니다 (ADR-013).",
    "점검 항목은 **근거를 댄 것이고 준수 여부 판정이 아닙니다.** 취약점 분석·평가는 "
    "정보통신기반 보호법에 따라 자격을 갖춘 평가기관이 수행합니다 (ADR-043).",
    "'현재 일치 항목 없음' 은 **안전하다는 뜻이 아닙니다.** 지금 아는 범위에서 "
    "일치가 없다는 것뿐입니다 (불변 규칙 1).",
    "'미상' 은 빈칸이 아니라 **아직 모른다**는 뜻입니다. 모르는 것을 '없음' 으로 "
    "접지 않습니다 (불변 규칙 2).",
)

#: 공개 권고문이 희박한 제조사. 실측값이고, 말하지 않으면 '안전' 으로 읽힌다.
#: 정본은 `cli.THIN_COVERAGE_HINT` 가 아니라 **이 보고서가 직접 센 수**다.
THIN_THRESHOLD = 5


@dataclass
class ActionRow:
    bucket: str
    bucket_phrase: str
    asset_id: str
    label: str
    owner: str
    zone: str
    vendor: str
    model: str
    advisory_id: str
    status: str
    status_ko: str
    fired_rules: str
    kev: str
    floor_if_confirmed: str
    blocked_by: str
    rationale: str


@dataclass
class AssetRow:
    asset_id: str
    label: str
    asset_type: str
    vendor: str
    model: str
    order_number: str
    firmware: str
    firmware_method: str
    factory: str
    zone: str
    owner: str
    department: str
    level: str
    lifecycle: str
    addresses: str
    synthetic: str


@dataclass
class ExposureRow:
    asset_id: str
    label: str
    owner: str
    kind: str
    code: str
    title: str
    why: str
    what_to_do: str
    bucket: str


@dataclass
class ControlRow:
    standard: str
    standard_id: str
    code: str
    name: str
    severity: str
    category: str
    our_scope: str
    present: int
    absent: int
    not_assessable: int
    note: str


@dataclass
class CoverageRow:
    vendor: str
    our_assets: int
    advisories: int
    verdict: str


@dataclass
class Report:
    as_of: str
    policy_version: str
    kev_snapshot: Optional[str]
    topology_source: Optional[str]
    topology_synthetic: Optional[bool]
    advisories: int
    actions: List[ActionRow] = field(default_factory=list)
    assets: List[AssetRow] = field(default_factory=list)
    exposures: List[ExposureRow] = field(default_factory=list)
    controls: List[ControlRow] = field(default_factory=list)
    coverage: List[CoverageRow] = field(default_factory=list)
    buckets: Dict[str, int] = field(default_factory=dict)
    levels: Dict[str, int] = field(default_factory=dict)
    synthetic_assets: int = 0

    @property
    def disclaimers(self) -> Tuple[str, ...]:
        return DISCLAIMERS

    @property
    def thin_vendors(self) -> List[CoverageRow]:
        return [c for c in self.coverage if c.advisories < THIN_THRESHOLD]


# --------------------------------------------------------------------------
def _first_firmware(body: dict) -> Tuple[str, str]:
    for c in body.get("components") or ():
        v = (c.get("version") or {})
        if v.get("raw"):
            return str(v["raw"]), str(c.get("method") or "")
    return "", ""


def _addresses(body: dict) -> str:
    out = []
    for a in ((body.get("network") or {}).get("addresses") or ()):
        bit = a.get("ip") or a.get("hostname") or a.get("mac") or ""
        if bit:
            out.append(str(bit))
    return ", ".join(out[:4]) + (" 외 %d" % (len(out) - 4) if len(out) > 4 else "")


def _asset_row(body: dict, asset) -> AssetRow:
    ident = body.get("identity") or {}
    loc = body.get("location") or {}
    own = body.get("ownership") or {}
    fw, method = _first_firmware(body)
    return AssetRow(
        asset_id=str(body.get("asset_id") or ""),
        label=str(body.get("label") or ""),
        asset_type=str(body.get("asset_type") or ""),
        vendor=str(ident.get("vendor_raw") or ""),
        model=str(ident.get("model_raw") or ident.get("family_raw") or ""),
        order_number=str(ident.get("order_number") or ""),
        firmware=fw or "미상",
        firmware_method=method,
        factory=str(loc.get("factory") or ""),
        zone=str(loc.get("zone") or ""),
        owner=str(own.get("contact") or ""),
        department=str(own.get("department") or ""),
        level=completeness(body),
        lifecycle=str(body.get("lifecycle_status") or "미상"),
        addresses=_addresses(body),
        synthetic="예 (실재하지 않는 장비)" if body.get("synthetic") else "",
    )


def _blocked_by(item) -> str:
    bits = []
    for p in item.pending_escalations:
        bits.append("%s: %s 미확인" % (p.rule_id, ", ".join(p.missing)))
    return " · ".join(bits)


def build(*, bodies: Sequence[dict], assets: Sequence, advisories: Sequence,
          as_of: str, topology=None, kev=None, policy=None,
          lens: str = "default", max_cvss=None) -> Report:
    """보고서 자료를 모은다. **엔진을 부르기만 한다.**

    `bodies` 는 자산 원문 dict, `assets` 는 같은 순서의 `Asset` 객체다. 둘을 함께
    받는 이유: 대장 시트는 원문의 `label`·`ownership` 을 그대로 싣고, 판정은
    모델 객체로 돌려야 한다.
    """
    from .policy import DEFAULT_POLICY
    policy = policy or DEFAULT_POLICY          # `None` 을 넘기면 엔진이 터진다

    rep = Report(
        as_of=as_of,
        policy_version=getattr(policy, "version", None) or "policy/default",
        kev_snapshot=getattr(kev, "catalog_version", None),
        topology_source=str(getattr(topology, "source_path", "") or "") or None,
        topology_synthetic=(None if topology is None
                            else bool((topology.provenance or {}).get("synthetic"))),
        advisories=len(advisories),
    )

    indexes = [index_advisory(a) for a in advisories]
    items = []
    vendor_assets: Dict[str, int] = {}
    #: (자산, 판정, 노출, 도달성) — 점검 항목 집계가 이것을 그대로 쓴다
    per_asset: List[tuple] = []

    for body, asset in zip(bodies, assets):
        rep.assets.append(_asset_row(body, asset))
        if body.get("synthetic"):
            rep.synthetic_assets += 1
        lvl = completeness(body)
        rep.levels[lvl] = rep.levels.get(lvl, 0) + 1
        v = ((body.get("identity") or {}).get("vendor_raw") or "").strip()
        if v:
            vendor_assets[v] = vendor_assets.get(v, 0) + 1

        # 판정 — queue 와 같은 사전 필터를 거친다 (ADR-030)
        asset_items = []
        for adv, ix in zip(advisories, indexes):
            if not could_match(asset, ix):
                continue
            d = decide_applicability(asset, adv, as_of=as_of)
            if d.status == "no_known_match":
                continue
            asset_items.append(evaluate_priority(
                d, asset, kev=kev, lens=lens, topology=topology, policy=policy))
        items.extend(asset_items)

        # 노출 — 권고문이 없어도 나온다 (ADR-035)
        h02 = any("H02" in (i.fired_rules or ()) for i in asset_items)
        found, _questions = find_exposure(asset, topology=topology, as_of=as_of,
                                          h02_fired=h02)
        own = (body.get("ownership") or {}).get("contact") or ""
        for f in found:
            rep.exposures.append(ExposureRow(
                asset_id=f.asset_id, label=str(body.get("label") or ""),
                owner=str(own), kind=f.kind, code=f.code, title=f.title,
                why=f.why, what_to_do=f.what_to_do, bucket=f.bucket))

        # 점검 항목이 쓸 근거를 **여기서 한 번** 모은다. 아래에서 다시 판정하면
        # 두 벌이 되고, 같은 자산에 대해 다른 수를 말하게 된다.
        reach = (evaluate_reachability(topology, asset.asset_id, as_of=as_of)
                 if topology is not None else None)
        per_asset.append((asset, asset_items, found, reach))

    by_id = {r.asset_id: r for r in rep.assets}
    for item in sort_queue(items):
        a = by_id.get(item.asset_id)
        rep.buckets[item.bucket] = rep.buckets.get(item.bucket, 0) + 1
        rep.actions.append(ActionRow(
            bucket=item.bucket, bucket_phrase=BUCKET_PHRASES.get(item.bucket, ""),
            asset_id=item.asset_id,
            label=a.label if a else "", owner=a.owner if a else "",
            zone=a.zone if a else "", vendor=a.vendor if a else "",
            model=a.model if a else "",
            advisory_id=item.advisory_id, status=item.status,
            status_ko=PHRASES.get(item.status, item.status),
            fired_rules=", ".join(item.fired_rules),
            kev=", ".join(item.kev_cves[:3]),
            floor_if_confirmed=item.floor_if_confirmed or "",
            blocked_by=_blocked_by(item),
            rationale=" / ".join(item.rationale[:2]),
        ))

    rep.controls = _controls(per_asset)
    rep.coverage = _coverage(vendor_assets, advisories)
    return rep


def _controls(per_asset) -> List[ControlRow]:
    """점검 항목을 **자산 전체로** 집계한다.

    `otai controls` 는 자산 1건씩이라 800대를 돌리려면 루프를 직접 짜야 했다.
    보고서는 항목마다 '근거 있음 몇 대 / 근거 없음 몇 대' 를 센다.

    근거는 `build` 가 이미 모아 둔 것을 쓴다 — 여기서 다시 판정하면 같은 자산에
    대해 두 벌이 생긴다.
    """
    sets = load_all()
    if not sets:
        return []
    per: Dict[Tuple[str, str], Dict[str, int]] = {}
    meta: Dict[Tuple[str, str], object] = {}

    for asset, findings, exposures, reach in per_asset:
        for cs in sets:
            for c in cs.controls:
                key = (cs.standard_id, c.code)
                meta.setdefault(key, (cs, c))
                e = evidence_for(c, asset, findings=findings, exposures=exposures,
                                 reachability=reach)
                box = per.setdefault(key, {PRESENT: 0, ABSENT: 0, NOT_ASSESSABLE: 0})
                box[e.status] += 1

    rows = []
    for key, box in per.items():
        cs, c = meta[key]
        rows.append(ControlRow(
            standard=cs.standard.get("title", cs.standard_id),
            standard_id=cs.standard_id,
            # KISA 는 `name` 이 없고 우리가 쓴 한 줄 요약(`gist`)만 있다.
            # NIST 는 통제 이름이 있고 `gist` 가 없다. 빈 열로 두지 않는다.
            code=c.code, name=c.name or c.gist or "", severity=c.severity,
            category=c.category, our_scope=SCOPE_KO.get(c.our_scope, c.our_scope),
            present=box[PRESENT], absent=box[ABSENT],
            not_assessable=box[NOT_ASSESSABLE],
            note=(c.note or "")[:300]))
    rows.sort(key=lambda r: (r.standard, r.code))
    return rows


def _coverage(vendor_assets: Dict[str, int], advisories) -> List[CoverageRow]:
    """우리 자산의 제조사가 공개 권고문에 **몇 번 나오는가.**

    이 표가 없으면 '알려진 일치 없음' 이 '안전' 으로 읽힌다 (불변 규칙 1).
    LS산전 설비 120대에 대해 아무 말도 못 하는 것과, 그 설비가 깨끗한 것은 다르다.
    """
    blobs = []
    for a in advisories:
        blobs.append(" ".join(((p.vendor or "") + " " + (p.product_name or ""))
                              for p in a.products).lower())
    rows = []
    for vendor, n in sorted(vendor_assets.items(), key=lambda kv: -kv[1]):
        key = vendor.lower()
        hits = sum(1 for b in blobs if key in b)
        if hits >= THIN_THRESHOLD:
            verdict = "권고문이 있습니다 — CVE 축이 돕니다"
        elif hits:
            verdict = ("권고문이 %d건뿐입니다 — CVE 축은 거의 비고 "
                       "**안전하다는 뜻이 아닙니다**" % hits)
        else:
            verdict = ("공개 권고문이 없습니다 — CVE 축은 비고 **안전하다는 뜻이 "
                       "아닙니다.** 노출·경로·점검 항목으로 봅니다")
        rows.append(CoverageRow(vendor=vendor, our_assets=n, advisories=hits,
                                verdict=verdict))
    return rows
