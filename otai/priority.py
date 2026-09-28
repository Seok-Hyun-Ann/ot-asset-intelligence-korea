# -*- coding: utf-8 -*-
"""우선순위·조치 결정 엔진 (표 22~24, 부록 D `decide_action`).

**결정적 규칙 모듈이다. LLM 이 P0~P4 를 단독 결정하지 않는다** (표 32 금지 항목).

핵심 설계 (ADR-007): 강제규칙의 전제조건이 미상이면 **발화시키지도 무시하지도
않는다.** 항목은 `P?` 로 가고 "무엇이 확인되면 어느 등급이 되는지"를 함께 싣는다.
슬라이스 1의 '다음 최적 질문'을 우선순위에 적용한 것이다.

Kleene 논리곱이 이 설계를 공짜로 준다:
  전제조건 하나라도 FALSE → 규칙은 FALSE (미상이 남아 있어도 발화하지 않는다)
  FALSE 가 없고 UNKNOWN 이 있으면 → 규칙은 UNKNOWN (보류)
따라서 비영향 자산은 `applicable=FALSE` 때문에 보류 목록에 아예 오르지 않는다.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .applicability import Decision
from .kev import KevCatalog
from .lifecycle import LifecycleView
from .logic import Tri
from .capability import CONTROL_WRITE
from .model import Asset
from .paths import evaluate_reachability
from .policy import DEFAULT_POLICY, Policy
from .topology import Topology

POLICY_VERSION = "priority/1.0.0"

# 표 24 + ADR-007 의 `P?`. 정렬은 이 순서를 따른다.
BUCKETS = ("P0", "P?", "P1", "P2", "P3", "P4")
BUCKET_ORDER = {b: i for i, b in enumerate(BUCKETS)}

BUCKET_PHRASES = {
    "P0": "지금 격리 또는 비상 검토",
    "P?": "확인 필요 — 막힌 강제규칙",
    "P1": "정기 창 밖 조치",
    "P2": "다음 정비 창",
    "P3": "확인 또는 모니터",
    "P4": "비해당·수용·종결",
}

# 적용성 상태 → 강제규칙이 발화하지 않았을 때의 기본 버킷
BASE_BUCKET = {
    "affected_confirmed": "P2",
    "affected_likely": "P3",
    "candidate": "P3",
    "insufficient_information": "P3",
    "stale": "P3",
    "conflicting_evidence": "P3",
    "not_affected_confirmed": "P4",
    "fixed": "P4",
    "no_known_match": "P4",
}


# --------------------------------------------------------------------------
# 전제조건
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Precondition:
    name: str
    value: Tri
    evidence: str


@dataclass
class Context:
    """규칙이 참조하는 현장 맥락."""
    decision: Decision
    asset: Asset
    kev: Optional[KevCatalog] = None
    max_cvss: Optional[float] = None
    topology: Optional[Topology] = None
    policy: Policy = DEFAULT_POLICY
    # 다중 소스 비교에서 온 충돌 신호 (FR-SRC-005 → H05)
    source_conflict: Optional[bool] = None
    # 표 13 권위로 정리한 수명주기. 없으면 자산 입력값만 본다 (기존 동작).
    lifecycle: Optional["LifecycleView"] = None
    _cache: dict = field(default_factory=dict)

    @property
    def kev_hits(self) -> Tuple[str, ...]:
        if self.kev is None:
            return ()
        return self.kev.intersect(self.decision.cves)

    def reachability(self, require_capability=None):
        """토폴로지 도달성 (ADR-014). 규칙마다 재계산하지 않도록 캐시한다."""
        key = require_capability or "*"
        if key not in self._cache:
            self._cache[key] = evaluate_reachability(
                self.topology, self.asset.asset_id,
                as_of=self.decision.as_of, require_capability=require_capability,
            )
        return self._cache[key]


def _applicable(ctx: Context) -> Precondition:
    st = ctx.decision.status
    if st in ("affected_confirmed", "affected_likely"):
        return Precondition("적용성", Tri.TRUE, "적용 상태 %s" % st)
    if st in ("candidate", "insufficient_information", "stale", "conflicting_evidence"):
        return Precondition("적용성", Tri.UNKNOWN, "적용 상태 %s — 확정되지 않음" % st)
    return Precondition("적용성", Tri.FALSE, "적용 상태 %s" % st)


def _kev_listed(ctx: Context) -> Precondition:
    if ctx.kev is None:
        return Precondition("실제 악용(KEV)", Tri.UNKNOWN, "KEV 스냅샷이 로드되지 않음")
    hits = ctx.kev_hits
    if hits:
        e = ctx.kev.entry(hits[0])
        return Precondition("실제 악용(KEV)", Tri.TRUE,
                            "KEV 등재 %s (%s / %s)" % (hits[0], e.vendor_project, e.product))
    # KEV 는 '알려진 악용' 의 완전한 목록이므로 부재는 사실이지 미상이 아니다
    return Precondition("실제 악용(KEV)", Tri.FALSE,
                        "적용 CVE %d건 중 KEV 등재 없음" % len(ctx.decision.cves))


def _valid_path(ctx: Context) -> Precondition:
    """멀티홉 도달성 (ADR-014) — 관측 엣지만으로 된 경로가 있어야 확정."""
    r = ctx.reachability()
    return Precondition("유효 경로", r.verdict, r.reason)


def _reaches_critical(ctx: Context) -> Precondition:
    """공격이 중요 자산에 제어 쓰기 능력으로 도달하는가 (표 23 H02)."""
    if ctx.topology is None:
        return Precondition("중요 자산 도달", Tri.UNKNOWN, "토폴로지가 로드되지 않음")
    node = ctx.topology.node_for_asset(ctx.asset.asset_id)
    if node is None:
        return Precondition("중요 자산 도달", Tri.UNKNOWN,
                            "이 자산이 토폴로지에 없습니다 — 도달 불가로 단정하지 않습니다")
    if not node.is_critical:
        return Precondition("중요 자산 도달", Tri.FALSE,
                            "이 자산은 안전 중요 자산이 아닙니다")
    r = ctx.reachability(require_capability=CONTROL_WRITE)
    if r.verdict is Tri.TRUE:
        return Precondition("중요 자산 도달", Tri.TRUE,
                            "제어 쓰기 능력으로 도달하는 확인 경로 %d개" % len(r.confirmed_paths))
    return Precondition("중요 자산 도달", r.verdict, r.reason)


def _external_zone(ctx: Context) -> Precondition:
    """외부 상위 Zone(Purdue L4 이상)에서 도달하는가 (표 23 H03)."""
    r = ctx.reachability()
    if r.verdict is not Tri.TRUE:
        return Precondition("외부 상위 Zone 도달", r.verdict, r.reason)
    topo = ctx.topology
    external = [p for p in r.confirmed_paths
                if topo.nodes[p.entry].purdue_level >= 4.0]
    if external:
        return Precondition("외부 상위 Zone 도달", Tri.TRUE,
                            "외부 진입점 %s 에서 확인 경로 존재"
                            % ", ".join(sorted({p.entry for p in external})))
    return Precondition("외부 상위 Zone 도달", Tri.FALSE,
                        "확인 경로의 진입점이 모두 내부입니다")


def _plaintext_control_write(ctx: Context) -> Precondition:
    """무인증 원격 쓰기 — 자산이 선언한 프로토콜로 평가 가능 (표 4)."""
    net = ctx.asset.network
    if not net.declared:
        return Precondition("무인증 원격 쓰기", Tri.UNKNOWN, "네트워크 정보 미수집")
    hits = [p for p in net.protocols if p.is_plaintext_control_server]
    if hits:
        p = hits[0]
        return Precondition("무인증 원격 쓰기", Tri.TRUE,
                            "%s/%s 평문 서버 노출" % (p.protocol, p.port))
    unknown_enc = [p for p in net.protocols if p.encrypted is None and p.role == "server"]
    if unknown_enc:
        return Precondition("무인증 원격 쓰기", Tri.UNKNOWN,
                            "%s 의 암호화 여부 미상" % unknown_enc[0].protocol)
    return Precondition("무인증 원격 쓰기", Tri.FALSE, "평문 제어 서버 노출 없음")


def _safety_impact(ctx: Context) -> Precondition:
    v = (ctx.asset.operations or {}).get("safety_criticality")
    if v in ("high",):
        return Precondition("공정 안전 영향", Tri.TRUE, "safety_criticality=high")
    if v in ("none", "low"):
        return Precondition("공정 안전 영향", Tri.FALSE, "safety_criticality=%s" % v)
    if v in ("medium",):
        return Precondition("공정 안전 영향", Tri.UNKNOWN, "safety_criticality=medium — 판단 보류")
    return Precondition("공정 안전 영향", Tri.UNKNOWN, "safety_criticality 미상")


def _vendor_critical(ctx: Context) -> Precondition:
    if ctx.max_cvss is None:
        return Precondition("벤더 Critical", Tri.UNKNOWN, "CVSS 점수 없음")
    if ctx.max_cvss >= ctx.policy.vendor_critical_cvss:
        return Precondition("벤더 Critical", Tri.TRUE, "최대 CVSS %.1f" % ctx.max_cvss)
    return Precondition("벤더 Critical", Tri.FALSE, "최대 CVSS %.1f" % ctx.max_cvss)


def _remote_access_boundary(ctx: Context) -> Precondition:
    t = ctx.asset.network.has_remote_access
    if t is Tri.TRUE:
        return Precondition("원격접속 경계", Tri.TRUE, "remote_access 선언됨")
    if t is Tri.FALSE:
        return Precondition("원격접속 경계", Tri.FALSE, "원격접속 없음으로 선언")
    return Precondition("원격접속 경계", Tri.UNKNOWN, "네트워크 정보 미수집")


def _eol(ctx: Context) -> Precondition:
    """지원이 끝났는가 (표 13: 제조사 EOL/EOS 가 1차, 현장 기록이 보조).

    정리된 뷰가 있으면 그것을 쓴다 — 제조사가 `no_fix_planned` 를 선언했다면
    사용자가 'supported' 라고 적었어도 제조사가 이긴다. 근거도 함께 남긴다.
    """
    lv = ctx.lifecycle
    if lv is not None:
        if lv.state == "end_of_life":
            who = "제조사 확인" if lv.vendor_confirmed else "현장 기록"
            return Precondition("수명주기 종료", Tri.TRUE,
                                "%s — %s" % (who, (lv.winner.basis if lv.winner else "")[:90]))
        if lv.state == "supported":
            return Precondition("수명주기 종료", Tri.FALSE,
                                (lv.winner.basis if lv.winner else "지원 중"))
        return Precondition("수명주기 종료", Tri.UNKNOWN,
                            "수명주기 근거 없음 — 제조사 EOL/EOS 도 현장 기록도 없습니다")

    v = (ctx.asset.lifecycle_status or "").lower()
    if v in ("eol", "eos"):
        return Precondition("수명주기 종료", Tri.TRUE, "lifecycle_status=%s" % v)
    if v == "supported":
        return Precondition("수명주기 종료", Tri.FALSE, "lifecycle_status=supported")
    return Precondition("수명주기 종료", Tri.UNKNOWN, "lifecycle_status 미상")


def _version_unknown(ctx: Context) -> Precondition:
    if ctx.decision.status == "insufficient_information":
        return Precondition("버전 미상", Tri.TRUE, "적용성 판정이 정보 부족")
    return Precondition("버전 미상", Tri.FALSE, "버전 정보 있음")


def _source_conflict(ctx: Context) -> Precondition:
    """판정 자체의 충돌 또는 **다중 소스 비교**에서 온 충돌 (FR-SRC-005).

    H05 는 슬라이스 2~4 동안 실제 트리거가 없던 유일한 강제규칙이다.
    소스 비교가 붙으면서 비로소 발화 경로가 생긴다.
    """
    if ctx.decision.status == "conflicting_evidence":
        return Precondition("소스 충돌", Tri.TRUE, "근거 충돌 판정")
    if ctx.source_conflict is True:
        return Precondition("소스 충돌", Tri.TRUE, "다중 소스 비교에서 값 불일치")
    if ctx.source_conflict is False:
        return Precondition("소스 충돌", Tri.FALSE, "다중 소스가 같은 값을 확인")
    return Precondition("소스 충돌", Tri.FALSE, "충돌 없음")


# --------------------------------------------------------------------------
# 강제 상황 규칙 (표 23) — 선언적 테이블
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class HardRule:
    rule_id: str
    condition: str
    floor: str
    preconditions: Tuple[Callable[[Context], Precondition], ...]
    escalate_to: Optional[str] = None
    escalate_when: Optional[str] = None   # 이 전제조건이 TRUE 면 escalate_to 로


HARD_RULES: Tuple[HardRule, ...] = (
    HardRule(
        "H01", "KEV + 적용 확정/가능 + 유효 경로", "P1",
        (_kev_listed, _applicable, _valid_path),
        escalate_to="P0", escalate_when="공정 안전 영향",
    ),
    HardRule(
        "H02", "무인증 원격 쓰기가 중요 자산에 도달", "P0",
        (_plaintext_control_write, _reaches_critical, _applicable),
    ),
    HardRule(
        "H03", "벤더 Critical + 공정 안전 영향 + 외부 상위 Zone 도달", "P1",
        (_vendor_critical, _safety_impact, _external_zone, _applicable),
    ),
    HardRule(
        "H04", "EOL + 원격접속 경계 자산 + 버전 미상", "P1",
        (_eol, _remote_access_boundary, _version_unknown),
    ),
    HardRule(
        "H05", "소스 충돌 + 높은 잠재 안전 영향", "P1",
        (_source_conflict, _safety_impact),
    ),
)


@dataclass(frozen=True)
class RuleOutcome:
    rule_id: str
    condition: str
    fired: Tri
    floor: str
    preconditions: Tuple[Precondition, ...]

    @property
    def blocking(self) -> Tuple[Precondition, ...]:
        return tuple(p for p in self.preconditions if p.value is Tri.UNKNOWN)


def evaluate_hard_rules(ctx: Context) -> Tuple[RuleOutcome, ...]:
    out = []
    for rule in HARD_RULES:
        pres = tuple(fn(ctx) for fn in rule.preconditions)
        fired = Tri.and_(*(p.value for p in pres))
        floor = ctx.policy.hard_rule_floors.get(rule.rule_id, rule.floor)
        if fired is Tri.TRUE and rule.escalate_when:
            extra = {p.name: p.value for p in pres}
            hit = extra.get(rule.escalate_when)
            if hit is None:
                # escalate_when 이 이 규칙의 전제조건이 아니면 별도 평가
                for fn in (_safety_impact,):
                    p = fn(ctx)
                    if p.name == rule.escalate_when:
                        hit = p.value
                        pres = pres + (p,)
            if hit is Tri.TRUE and rule.escalate_to:
                floor = rule.escalate_to
        out.append(RuleOutcome(rule.rule_id, rule.condition, fired, floor, pres))
    return tuple(out)


# --------------------------------------------------------------------------
# 사용자 렌즈 (11.3) — 버킷은 못 바꾸고 같은 버킷 안의 정렬만 바꾼다
# --------------------------------------------------------------------------
LENS_DIMENSIONS = ("안전", "악용", "도달성", "기술", "수명", "정비")

LENS_PRESETS: Dict[str, Dict[str, float]] = {
    # 가중치 작성자: 프로젝트 소유자 (ADR-010). 표 41 의 승인자 자리를 비워두지 않는다.
    "default": {d: 1.0 for d in LENS_DIMENSIONS},
    "ops": {"안전": 2.0, "악용": 1.0, "도달성": 1.0, "기술": 0.5, "수명": 1.0, "정비": 2.0},
    "security": {"안전": 1.0, "악용": 2.5, "도달성": 2.0, "기술": 1.5, "수명": 1.0, "정비": 0.3},
}


def _signals(ctx: Context, outcomes: Sequence[RuleOutcome]) -> Dict[str, float]:
    ops = ctx.asset.operations or {}
    sev = {"high": 1.0, "medium": 0.6, "low": 0.2, "none": 0.0}
    reach = Tri.or_(*[p.value for o in outcomes for p in o.preconditions
                      if p.name in ("유효 경로", "무인증 원격 쓰기", "원격접속 경계")]) \
        if outcomes else Tri.UNKNOWN
    return {
        "안전": sev.get(ops.get("safety_criticality"), 0.5),
        "악용": 1.0 if ctx.kev_hits else 0.0,
        "도달성": {Tri.TRUE: 1.0, Tri.UNKNOWN: 0.5, Tri.FALSE: 0.0}[reach],
        "기술": (ctx.max_cvss or 0.0) / 10.0,
        "수명": 1.0 if (ctx.asset.lifecycle_status or "").lower() in ("eol", "eos") else 0.0,
        "정비": 0.5 if ops.get("next_maintenance_window") else 1.0,
    }


# --------------------------------------------------------------------------
# 행동 큐 항목
# --------------------------------------------------------------------------
@dataclass
class PendingEscalation:
    rule_id: str
    condition: str
    floor_if_confirmed: str
    missing: List[str]
    question: str


@dataclass
class QueueItem:
    asset_id: str
    advisory_id: str
    status: str
    bucket: str
    bucket_phrase: str
    floor_if_confirmed: Optional[str]
    fired_rules: List[str]
    pending_escalations: List[PendingEscalation]
    rationale: List[str]
    cves: List[str]
    kev_cves: List[str]
    lens_score: float
    policy_version: str
    kev_snapshot: Optional[str]
    as_of: str
    priority_input_hash: str
    topology_source: Optional[str] = None
    exception_applied: bool = False
    exception_expires: Optional[str] = None
    # 렌즈 차원별 신호값. UI 가 가중치를 실시간으로 바꿔 점수를 다시 계산할 수 있게
    # 노출한다 — 버킷은 여기 영향을 받지 않는다는 불변량을 눈으로 보여주기 위해서다.
    signals: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "advisory_id": self.advisory_id,
            "status": self.status,
            "bucket": self.bucket,
            "bucket_phrase": self.bucket_phrase,
            "floor_if_confirmed": self.floor_if_confirmed,
            "fired_rules": self.fired_rules,
            "pending_escalations": [
                {
                    "rule_id": p.rule_id,
                    "condition": p.condition,
                    "floor_if_confirmed": p.floor_if_confirmed,
                    "missing": p.missing,
                    "question": p.question,
                }
                for p in self.pending_escalations
            ],
            "rationale": self.rationale,
            "cves": self.cves,
            "kev_cves": self.kev_cves,
            "lens_score": round(self.lens_score, 4),
            "policy_version": self.policy_version,
            "kev_snapshot": self.kev_snapshot,
            "topology_source": self.topology_source,
            "exception_applied": self.exception_applied,
            "exception_expires": self.exception_expires,
            "signals": {k: round(v, 4) for k, v in sorted(self.signals.items())},
            "as_of": self.as_of,
            "priority_input_hash": self.priority_input_hash,
        }


def _priority_hash(decision: Decision, ctx: Context, lens_name: str,
                   exception: Optional[dict] = None) -> str:
    payload = {
        "applicability_input_hash": decision.input_hash,
        "policy_version": ctx.policy.version,
        "kev_catalog_version": ctx.kev.catalog_version if ctx.kev else None,
        "kev_sha256": ctx.kev.sha256 if ctx.kev else None,
        "topology": ctx.topology.source_path if ctx.topology else None,
        "lens": lens_name,
        "max_cvss": ctx.max_cvss,
        "exception": None if exception is None else {
            "approver": exception.get("approver"),
            "granted_as_of": exception.get("granted_as_of"),
            "expires_as_of": exception.get("expires_as_of"),
            "bucket_accepted": exception.get("bucket_accepted"),
        },
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def evaluate_priority(
    decision: Decision,
    asset: Asset,
    kev: Optional[KevCatalog] = None,
    max_cvss: Optional[float] = None,
    lens: str = "default",
    topology: Optional[Topology] = None,
    exception: Optional[dict] = None,
    policy: Policy = DEFAULT_POLICY,
    lifecycle: Optional["LifecycleView"] = None,
    source_conflict: Optional[bool] = None,
) -> QueueItem:
    if max_cvss is None:
        max_cvss = decision.max_cvss
    ctx = Context(decision=decision, asset=asset, kev=kev, max_cvss=max_cvss,
                  topology=topology, policy=policy, source_conflict=source_conflict,
                  lifecycle=lifecycle)
    outcomes = evaluate_hard_rules(ctx)

    fired = [o for o in outcomes if o.fired is Tri.TRUE]
    blocked = [o for o in outcomes if o.fired is Tri.UNKNOWN]

    base = ctx.policy.base_bucket.get(decision.status, "P3")
    rationale: List[str] = []

    # 1) 발화한 강제규칙이 있으면 가장 급한 floor 를 따른다 — 렌즈로 못 내린다
    if fired:
        bucket = min((o.floor for o in fired), key=lambda b: BUCKET_ORDER[b])
        for o in fired:
            rationale.append("강제규칙 %s 발화 (%s) → 최소 %s" % (o.rule_id, o.condition, o.floor))
        floor_if_confirmed = None
    else:
        bucket = base
        floor_if_confirmed = None

    # 2) 보류된 규칙 — 확정되면 지금보다 급해지는 것만 P? 로 올린다
    pending: List[PendingEscalation] = []
    for o in blocked:
        if BUCKET_ORDER[o.floor] >= BUCKET_ORDER[bucket]:
            continue  # 확정돼도 지금보다 급해지지 않으면 보류할 이유가 없다

        # 적용성이 확정되기 전에는 우선순위를 보류하지 않는다.
        #
        # 적용성이 미상인데 "확인하면 P0 일 수도" 를 붙이면 큐의 대부분이 P? 가 되어
        # 행동 큐가 무의미해진다 — 결정 C 가 피하려던 바로 그 실패 모드다.
        # 적용성이 미상일 때 올바른 다음 행동은 **적용성 확인**이고, 그것은 이미
        # 판정 카드의 '다음 최적 질문' 이 말하고 있다. 도달성을 묻는 것은 그다음이다.
        app = next((p for p in o.preconditions if p.name == "적용성"), None)
        if app is not None and app.value is not Tri.TRUE:
            continue

        missing = [p.name for p in o.blocking]
        pending.append(
            PendingEscalation(
                rule_id=o.rule_id,
                condition=o.condition,
                floor_if_confirmed=o.floor,
                missing=missing,
                question="%s 을(를) 확인하면 %s 이(가) 발화해 최소 %s 이 됩니다."
                         % (", ".join(missing), o.rule_id, o.floor),
            )
        )

    if pending and not fired:
        floor_if_confirmed = min((p.floor_if_confirmed for p in pending),
                                 key=lambda b: BUCKET_ORDER[b])
        bucket = "P?"
        rationale.append(
            "강제규칙 %s 이(가) 전제조건 미상으로 보류되었습니다. 확정 시 최소 %s."
            % (", ".join(p.rule_id for p in pending), floor_if_confirmed)
        )
    elif not fired:
        rationale.append("발화한 강제규칙 없음 — 적용 상태 %s 의 기본 등급 %s"
                         % (decision.status, base))

    # 3) 승인된 위험 수용 (FR-ACT-001)
    #
    # **강제규칙이 발화했으면 예외로 내릴 수 없다.** 렌즈에 적용한 것과 같은 보호다
    # (표 23: "사용자 가중치로 하향 불가"). 예외는 규칙이 발화하지 않은 항목의
    # 잔여 위험을 사람이 책임지고 수용하는 장치이지, 안전 하한을 뚫는 수단이 아니다.
    accepted_exception = None
    if exception is not None and not fired:
        accepted_exception = exception
        bucket = exception.get("bucket_accepted", "P4")
        pending = []
        floor_if_confirmed = None
        rationale.append(
            "승인된 위험 수용 — 승인자 %s, 만료 %s, 사유: %s"
            % (exception.get("approver", "?"), exception.get("expires_as_of", "?"),
               exception.get("reason", "-"))
        )
    elif exception is not None and fired:
        rationale.append(
            "예외가 있으나 강제규칙 %s 이(가) 발화해 적용되지 않습니다 (안전 하한)."
            % ", ".join(o.rule_id for o in fired)
        )

    presets = ctx.policy.lens_presets or LENS_PRESETS
    weights = presets.get(lens, presets.get("default", LENS_PRESETS["default"]))
    sig = _signals(ctx, outcomes)
    score = sum(weights.get(d, 1.0) * sig.get(d, 0.0) for d in LENS_DIMENSIONS)

    return QueueItem(
        asset_id=decision.asset_id,
        advisory_id=str(decision.evidence["advisory_id"]),
        status=decision.status,
        bucket=bucket,
        bucket_phrase=BUCKET_PHRASES[bucket],
        floor_if_confirmed=floor_if_confirmed,
        fired_rules=[o.rule_id for o in fired],
        pending_escalations=pending,
        rationale=rationale,
        cves=list(decision.cves),
        kev_cves=list(ctx.kev_hits),
        lens_score=score,
        signals=dict(sig),
        policy_version=ctx.policy.version,
        kev_snapshot=kev.catalog_version if kev else None,
        topology_source=topology.source_path if topology else None,
        as_of=decision.as_of,
        exception_applied=bool(accepted_exception),
        exception_expires=(accepted_exception or {}).get("expires_as_of"),
        priority_input_hash=_priority_hash(decision, ctx, lens, exception),
    )


def sort_queue(items: Sequence[QueueItem]) -> List[QueueItem]:
    """P0 → P? (floor 순) → P1 → P2 → P3 → P4.

    같은 버킷 안에서만 렌즈 점수가 순서를 바꾼다. 동점은 asset_id 로 결정적 정렬.
    """
    def key(it: QueueItem):
        return (
            BUCKET_ORDER[it.bucket],
            BUCKET_ORDER.get(it.floor_if_confirmed or "P4", 99),
            -it.lens_score,
            it.asset_id,
            it.advisory_id,
        )
    return sorted(items, key=key)
