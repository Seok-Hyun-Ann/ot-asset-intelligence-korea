# -*- coding: utf-8 -*-
"""다음 최적 질문 (SPEC 6.2, FR-NBQ-001).

기획서의 요지: 고정 폼을 채우게 하지 않는다. **아는 것만 받고**, 그 상태에서
답할 수 있는 만큼 답한 뒤, 결론을 가장 크게 바꿀 질문 하나만 되돌려준다.

질문의 가치는 세 가지로 판단한다:
  1. 지금 판정을 막고 있는가          (엔진의 `fields.missing`)
  2. 답하면 후보가 얼마나 줄어드는가   (실제로 넣어보고 센다)
  3. 조치 등급이 바뀔 수 있는가        (적용성이 확정된 뒤에만 의미)

**추측하지 않는다.** 사용자가 '확인 불가'를 고르면 그 필드는 미상으로 남고
판정은 미상인 채로 유지된다 — 빈칸을 기본값으로 채우지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, List, Optional, Sequence

from .applicability import decide_applicability
from .model import Asset, Component, Identity

ASSET_TYPES = ["PLC", "HMI", "SCADA", "Historian", "Engineering WS",
               "네트워크 장비", "로봇·드라이브", "기타"]
SAFETY = [("high", "높음 — 정지하면 인명·환경 위험"),
          ("medium", "중간 — 품질·생산 영향"),
          ("low", "낮음 — 시험·보조 설비"),
          ("", "확인 불가")]
LIFECYCLE = [("supported", "지원 중"), ("EOL", "단종(EOL)"),
             ("EOS", "지원 종료(EOS)"), ("", "확인 불가")]


@dataclass
class Question:
    field: str
    label: str
    help: str
    kind: str                      # text | select | choice
    options: List[dict]
    why: str
    skippable: bool = True


def _has(asset: Asset, field: str) -> bool:
    i = asset.identity
    if field == "asset_type":
        return bool(asset.asset_type)
    if field == "identity.vendor_raw":
        return bool(i.vendor_raw)
    if field == "identity.model_raw":
        return bool(i.model_raw or i.family_raw)
    if field == "identity.order_number":
        return bool(i.order_number)
    if field == "firmware":
        return any(c.version_raw for c in asset.components)
    if field == "operations.safety_criticality":
        return bool((asset.operations or {}).get("safety_criticality"))
    if field == "lifecycle_status":
        return bool(asset.lifecycle_status)
    if field == "network":
        return asset.network.declared
    return False


def _statuses(asset: Asset, advisories, as_of: str) -> List[str]:
    return [decide_applicability(asset, a, as_of=as_of).status for a in advisories]


def _matched(statuses: Sequence[str]) -> int:
    """지금 '이 자산과 관계있다' 고 보는 권고문 수."""
    return sum(1 for s in statuses
               if s not in ("no_known_match", "not_affected_confirmed", "fixed"))


def _probe_identity(asset: Asset, advisories, as_of: str) -> int:
    """제조사·모델을 알면 후보가 몇 개로 줄어드는지 어림한다.

    실제 권고문들의 벤더를 넣어보고 가장 좁혀지는 경우를 센다 — 지어내지 않는다.
    """
    vendors = {p.vendor for a in advisories for p in a.products if p.vendor}
    best = None
    for v in sorted(vendors):
        probe = replace(asset, identity=replace(asset.identity, vendor_raw=v))
        n = _matched(_statuses(probe, advisories, as_of))
        best = n if best is None else min(best, n)
    return best if best is not None else 0


def next_question(asset: Asset, advisories, as_of: str) -> Optional[Question]:
    """지금 물어야 할 질문 하나. 없으면 None."""
    now = _statuses(asset, advisories, as_of)
    matched_now = _matched(now)

    if not _has(asset, "asset_type"):
        return Question(
            "asset_type", "이 장치는 무엇입니까?",
            "정확한 모델을 몰라도 됩니다. 종류만 알면 시작할 수 있습니다.",
            "select", [{"v": t, "t": t} for t in ASSET_TYPES],
            "가장 먼저 필요한 값입니다. 여기서 시작하면 나머지를 순서대로 묻습니다.",
            skippable=False)

    if not _has(asset, "identity.vendor_raw"):
        narrowed = _probe_identity(asset, advisories, as_of)
        return Question(
            "identity.vendor_raw", "제조사가 어디입니까?",
            "명판이나 진단 화면에 적혀 있습니다. 예: Siemens, Mitsubishi Electric",
            "text", [],
            "지금 관련 있을 수 있는 권고문이 %d건입니다. 제조사를 알면 최소 %d건까지 줄어듭니다."
            % (matched_now, narrowed))

    if not _has(asset, "identity.model_raw"):
        return Question(
            "identity.model_raw", "모델명이나 제품군은 무엇입니까?",
            "정확한 모델을 모르면 제품군만 적어도 됩니다. 예: MELSEC iQ-R Series",
            "text", [],
            "제품군까지만 알면 '후보' 로, 정확한 모델을 알면 '적용 확인' 으로 갈 수 있습니다.")

    # 여기서부터는 무엇이 판정을 막고 있는지 엔진에게 직접 묻는다
    blocking = []
    for adv in advisories:
        d = decide_applicability(asset, adv, as_of=as_of)
        if d.status in ("insufficient_information", "affected_likely", "candidate"):
            blocking.append((adv, d))

    needs_version = [ (adv, d) for adv, d in blocking
                      if any("version" in m for m in d.fields["missing"]) ]
    if needs_version and not _has(asset, "firmware"):
        adv, d = needs_version[0]
        rng = d.evidence.get("raw_expression")
        return Question(
            "firmware", "펌웨어 버전이 무엇입니까?",
            "진단 웹, 엔지니어링 도구의 장치 속성, 명판에서 확인할 수 있습니다.",
            "text", [],
            "이 값 하나로 적용 확인과 비영향 확인이 갈립니다.%s"
            % (" 영향 범위는 %s 입니다." % rng if rng else ""))

    if not _has(asset, "identity.order_number"):
        exact_possible = any(p.model_numbers for a in advisories for p in a.products)
        if exact_possible:
            return Question(
                "identity.order_number", "주문번호(품번)를 아십니까?",
                "명판에 있습니다. 예: 6ES7518-4AX00-1AB0",
                "text", [],
                "제조사가 주문번호를 공개한 권고문이 있습니다. 주문번호가 있으면 "
                "제품 식별이 '자동 연결 가능' 수준으로 올라갑니다.")

    # 적용성이 정해진 뒤에는 조치 등급을 좌우하는 것들을 묻는다
    if not _has(asset, "operations.safety_criticality"):
        return Question(
            "operations.safety_criticality", "이 장비가 멈추면 어떻게 됩니까?",
            "공정 안전 영향입니다. 강제규칙 H03·H05 가 이 값을 봅니다.",
            "choice", [{"v": v, "t": t} for v, t in SAFETY],
            "적용성은 정해졌습니다. 이제 조치를 언제 할지가 이 값에 달렸습니다.")

    if not _has(asset, "lifecycle_status"):
        return Question(
            "lifecycle_status", "아직 제조사 지원을 받는 장비입니까?",
            "단종(EOL) 장비는 패치가 없어 다른 방식으로 다뤄야 합니다.",
            "choice", [{"v": v, "t": t} for v, t in LIFECYCLE],
            "단종이고 원격접속 경계에 있으면 강제규칙 H04 가 발화합니다.")

    if not _has(asset, "network"):
        return Question(
            "network", "네트워크는 어떻게 연결돼 있습니까?",
            "아는 것만 고르세요. 모르면 비워두면 됩니다 — 미상으로 남습니다.",
            "network", [], "무인증 원격 쓰기와 원격접속 경계는 강제규칙 H02·H04 의 전제조건입니다.")

    return None


def apply_answer(asset: Asset, field: str, value, as_of: str) -> Asset:
    """답을 자산에 반영한다. 빈 값은 **미상으로 남긴다** — 기본값으로 채우지 않는다."""
    i = asset.identity
    v = (value or "").strip() if isinstance(value, str) else value

    if field == "asset_type":
        return replace(asset, asset_type=v or "")
    if field == "identity.vendor_raw":
        return replace(asset, identity=replace(i, vendor_raw=v or None))
    if field == "identity.model_raw":
        return replace(asset, identity=replace(i, model_raw=v or None,
                                               family_raw=i.family_raw or (v or None)))
    if field == "identity.order_number":
        return replace(asset, identity=replace(i, order_number=v or None))
    if field == "firmware":
        c = Component(type="controller_firmware",
                      version_raw=v or None,
                      version_state="known" if v else "unknown",
                      observed_at=as_of + "T00:00:00Z" if v else None,
                      method="manual", evidence_id="ev-manual-input")
        return replace(asset, components=(c,))
    if field == "operations.safety_criticality":
        ops = dict(asset.operations or {})
        if v:
            ops["safety_criticality"] = v
        else:
            ops.pop("safety_criticality", None)
        return replace(asset, operations=ops)
    if field == "lifecycle_status":
        return replace(asset, lifecycle_status=v or None)
    if field == "network":
        from .model import Network, Protocol
        d = value or {}
        protos = []
        if d.get("modbus_plain"):
            protos.append(Protocol("modbus_tcp", 502, "server", False))
        ra = {"type": d.get("remote_type") or "unknown"} if d.get("remote") else None
        return replace(asset, network=Network(tuple(protos), ra, (), declared=True))
    return asset
