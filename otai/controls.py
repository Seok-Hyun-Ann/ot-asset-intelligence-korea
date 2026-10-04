# -*- coding: utf-8 -*-
"""점검 항목에 **근거를 댄다** — 준수 여부를 판정하지 않는다 (ADR-043 · ADR-044).

표준 둘을 싣는다:

| 표준 | 항목 | 우리가 근거를 대는 것 |
|---|:--:|:--:|
| KISA 「기술적 취약점 분석·평가 방법 상세가이드」 2026 · `06. 제어시스템` | 51 | 9 |
| NIST SP 800-82r3 `부록 F — OT Overlay` (SP 800-53 Rev.5 재단) | 229 | 11 |

**둘은 다른 어휘로 같은 것을 묻는다.** C-18(알려진 취약점 대응)과 SI-2(Flaw
Remediation)는 둘 다 우리 적용성 판정이 근거다. 그래서 근거를 항목 코드가 아니라
**`evidence_kind` 종류별로** 모은다 (`_gather`) — 항목마다 로직을 따로 쓰면 둘이
어긋나고, 한쪽을 고칠 때 다른 쪽이 조용히 멈춘다.

**'판정 어휘' 를 쓰지 않는다.** 취약점 분석·평가는 정보통신기반 보호법에 따라
자격을 갖춘 평가기관이 수행한다. 「양호」·「취약」은 그쪽의 어휘이고, 우리가 쓰면
할 수 없는 법적 주장을 하는 것이다. 우리 어휘는 **근거 있음 / 근거 없음 /
도구가 답할 수 없음** 셋이다.

**셋인 이유**는 이 제품의 다른 모든 곳과 같다 — 답하지 못한 것을 '문제 없음' 으로
접지 않는다. `not_assessable` 은 통과도 미달도 아니다.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .logic import Tri
from .safeio import bounded_json_load

#: 근거 상태 셋. **'양호'·'취약'·판정 어휘를 쓰지 않는다** (ADR-043).
PRESENT = "evidence_present"        # 근거를 냈다
ABSENT = "evidence_absent"          # 낼 수 있는 항목인데 아직 근거가 없다
NOT_ASSESSABLE = "not_assessable"   # 도구가 답할 수 없는 항목이다

STATUS_KO = {
    PRESENT: "근거 있음",
    ABSENT: "근거 없음",
    NOT_ASSESSABLE: "도구가 답할 수 없음",
}

SCOPE_KO = {
    "direct": "직접 근거",
    "partial": "일부만",
    "none": "도구 범위 밖",
}


@dataclass(frozen=True)
class Control:
    code: str
    #: KISA 는 상/중/하. NIST 오버레이는 기준선으로 말하므로 빈 문자열이다.
    severity: str
    category: str          # KISA 분류 또는 NIST 통제군(한국어)
    our_scope: str          # direct | partial | none
    gist: Optional[str]     # 우리가 쓴 한 줄 요약 (KISA)
    evidence_kind: Tuple[str, ...]
    note: Optional[str]
    name: Optional[str] = None    # 통제 이름 (NIST)
    quote: Optional[str] = None   # 오버레이 원문 짧은 인용 (NIST — 인용 가능한 출처)
    standard_id: str = ""

    @property
    def assessable(self) -> bool:
        return self.our_scope in ("direct", "partial")


@dataclass(frozen=True)
class ControlSet:
    standard: dict
    disclaimer: str
    controls: Tuple[Control, ...]

    @property
    def standard_id(self) -> str:
        return self.standard.get("id", "")

    def get(self, code: str) -> Optional[Control]:
        for c in self.controls:
            if c.code == code:
                return c
        return None

    @property
    def assessable(self) -> Tuple[Control, ...]:
        return tuple(c for c in self.controls if c.assessable)


@dataclass(frozen=True)
class Evidence:
    """한 자산에 대한 한 항목의 근거."""
    control: Control
    status: str
    basis: Tuple[str, ...]      # 사람이 읽는 근거 문장
    pointers: Tuple[str, ...]   # 어느 화면·판정을 보면 되는지

    @property
    def status_ko(self) -> str:
        return STATUS_KO[self.status]


def load_controls(path) -> ControlSet:
    """매핑 표를 읽는다. 외부 파일이므로 `safeio` 를 거친다 (ADR-041)."""
    doc = bounded_json_load(path)
    std = doc.get("standard") or {}
    return ControlSet(
        standard=std,
        disclaimer=doc.get("disclaimer", ""),
        controls=tuple(
            Control(
                code=c["code"], severity=c.get("severity", ""),
                category=c.get("category") or c.get("family_ko", ""),
                our_scope=c.get("our_scope", "none"),
                gist=c.get("gist"),
                evidence_kind=tuple(c.get("evidence_kind") or ()),
                note=c.get("note"),
                name=c.get("name"),
                quote=c.get("overlay_quote"),
                standard_id=std.get("id", ""),
            )
            for c in doc.get("controls") or ()
        ),
    )


def find_sets(root="data/controls") -> List[Path]:
    """실린 표준 **전부**. 하나만 고르지 않는다 — 둘 다 답해야 한다 (ADR-044)."""
    d = Path(root)
    return sorted(d.glob("*.json")) if d.exists() else []


def load_all(root="data/controls") -> List[ControlSet]:
    return [load_controls(p) for p in find_sets(root)]


def find_set(root="data/controls") -> Optional[Path]:
    """예전 이름. 첫 표준 하나만 돌려준다 — 새 코드는 `find_sets` 를 쓸 것."""
    s = find_sets(root)
    return s[0] if s else None


# --------------------------------------------------------------------------
# 근거 모으기
# --------------------------------------------------------------------------
#: 적용성 상태 중 '이 장비가 해당한다' 쪽. `no_known_match` 는 포함하지 않는다 —
#: 대상이 아니라는 것은 근거가 아니다 (불변 규칙 1).
_APPLIES = ("affected_confirmed", "affected_likely", "candidate",
            "insufficient_information", "conflicting_evidence", "stale")

#: `_gather` 가 **실제로 만들어 내는** 근거 종류. 표준 파일이 이 목록에 없는
#: 이름을 가리키면 그 항목은 조용히 '근거 없음' 이 된다 — `exposure.
#: CONTROL_PROTOCOLS` 와 같은 함정이다 (ADR-040). `tests/test_controls.py` 가
#: 실린 표준 전부를 훑어 이 집합에 드는지 검사한다.
EVIDENCE_KINDS = (
    "applicability_decision",   # 적용성 9상태 판정과 근거
    "remediation_evidence",     # 수정 버전 설치 증거로 fixed 확정
    "exposure_finding",         # 표 4 의 노출·구성 위험 전부
    "plaintext_control",        # 그중 암호 없는 제어 통신
    "exposure_crossref",        # 다른 항목에서 함께 본다는 안내
    "lifecycle",                # 수명주기 상태
    "hard_rule_H02",            # 무인증 원격 쓰기 → P0
    "hard_rule_H04",            # 지원 종료 + 경계 + 버전 미상 → P1
    "asset_inventory",          # 식별 정보 · 부품 버전
    "identity_completeness",    # L0~L5
    "network_addresses",        # IP · MAC
    "topology",                 # 관측된 통신 상대
    "reachability",             # 도달성 판정
    "attack_paths",             # 경로와 구간별 근거
    "blocking_candidates",      # 끊을 후보와 그 대가
    "capture_endpoints",        # 캡처에서 본 끝점
)

#: 도달성을 **무엇에 대한 근거로 말하는지**가 표준마다 다르다. KISA C-21 은
#: '망 분리', NIST SC-7 은 '경계 보호' 를 묻는다. 셋 다 같은 사실에서 나온다.
_SEPARATION = {
    "C-21": ("분리되어 있지 않다는 근거입니다", "분리됐다는 뜻이 아닙니다", "분리 여부를"),
}
_SEPARATION_DEFAULT = ("경계가 서 있지 않다는 근거입니다", "경계가 섰다는 뜻이 아닙니다",
                       "경계 통제 여부를")

#: 근거를 댄 **다음에** 반드시 붙는 한계. 근거가 없으면 붙이지 않는다 — 아무
#: 근거도 없는 자리에서 한계만 말하면 무엇을 본 것인지 알 수 없다.
_RIDERS = {
    # KISA
    "C-19": ("'최신 버전인가' 는 판단하지 않습니다 — 최신이 무엇인지 아는 출처가 "
             "없고, 추정하면 없는 사실을 만듭니다.",),
    "C-43": ("담당자와 설치 SW 목록은 아직 담지 못합니다.",),
    # NIST SP 800-82r3 OT Overlay
    "CM-8": ("설치 소프트웨어 목록은 아직 담지 못합니다 — SBOM 입력이 필요합니다.",),
    "CM-7": ("'운영에 필요한 통신인가' 는 판단하지 않습니다 — 공정 요구를 알아야 "
             "하고, 모르는 것을 불필요로 단정하면 가동을 멈추는 조치를 권하게 됩니다.",),
    "SA-22": ("무조건 패치를 권하지 않습니다 — 오버레이가 말하는 대체 수단과 보상 "
              "통제를 함께 냅니다.",),
    "SI-2": ("패치를 적용하지는 않습니다 — 조치 실행은 사람이 승인하고 수행합니다.",),
    "SI-4": ("지속 탐지는 하지 않습니다. 사용자가 준 캡처의 시간 창만 읽고 망에 "
             "아무것도 보내지 않습니다 — 그래서 운영 성능에 영향이 없습니다.",),
    "RA-5": ("**능동 스캔은 하지 않습니다** — 현장 안전 때문에 금지입니다. 이 통제의 "
             "스캐닝 요구는 다른 수단으로 채워야 합니다.",),
    "RA-3": ("등급의 정확도는 주장하지 않습니다 — 위험평가의 입력이지 위험평가 "
             "자체가 아닙니다.",),
    "IA-3": ("MAC 은 랜카드 제조사까지만 말합니다 — 장비 인증의 대체물이 아닙니다.",),
}


def _require(items, name, label, attrs) -> tuple:
    """넘어온 것이 정말 그것인지 확인한다 — 아니면 **크게 실패한다**.

    `getattr(x, "kind", "")` 로 조용히 넘기면 **잘못된 입력이 근거가 된다.**
    실측: `exposure.find()` 는 `(발견, 질문)` **튜플**을 돌려주는데 풀지 않고
    그대로 넘기면 노출 1건이 '2건' 이 되고, 문자열 3개를 넘기면 '3건' 이 된다.
    예외도 나지 않는다. 세는 대상을 틀리면 없는 사실을 만드는 것이다 (ADR-035).

    삼진 논리는 **현장에 대한 사실**이 미상일 때 쓰는 것이고, 타입이 틀린 것은
    호출자의 버그다. 둘을 섞지 않는다.
    """
    seq = tuple(items)
    for i, it in enumerate(seq):
        if not any(hasattr(it, a) for a in attrs):
            raise TypeError(
                "%s[%d] 이 %s이 아니다 — %s 를 받았는데 %s 중 하나는 있어야 한다. "
                "`exposure.find()` 는 (발견, 질문) 튜플을 돌려준다 — 풀어서 넘길 것."
                % (name, i, label, type(it).__name__, " · ".join(attrs)))
    return seq


def _gather(asset, findings, exposures, reachability, capture_endpoints,
            words) -> Dict[str, List[Tuple[Optional[str], Optional[str]]]]:
    """근거를 **종류별로** 모은다.

    두 표준이 같은 근거를 다른 코드로 부르므로, 항목마다 다시 세면 어긋난다.
    값은 `(근거 문장, 화면 안내)` 이고 문장이 `None` 이면 안내만 준다 — 안내는
    근거가 아니므로 그것만으로 '근거 있음' 이 되지 않는다.
    """
    g: Dict[str, List[Tuple[Optional[str], Optional[str]]]] = {}

    def add(kind, line, ptr=None):
        g.setdefault(kind, []).append((line, ptr))

    # 적용성 ------------------------------------------------------------
    hit = [f for f in findings if getattr(f, "status", None) in _APPLIES]
    if hit:
        add("applicability_decision",
            "이 장비에 해당하는 권고문 %d건의 판정과 근거가 있습니다." % len(hit),
            "자산 상세 → 이 자산에 대한 판정")
    done = [f for f in findings if getattr(f, "status", None) == "fixed"]
    if done:
        add("remediation_evidence",
            "수정 버전 설치 증거로 확정된 판정이 %d건 있습니다." % len(done),
            "자산 상세 → 이 자산에 대한 판정")

    # 노출 (표 4) --------------------------------------------------------
    if exposures:
        add("exposure_finding",
            "패치로 없앨 수 없는 통신 방식 위험 %d건과 보상 통제 제안이 있습니다."
            % len(exposures), "할 일 → 장비가 놓인 방식")
        add("exposure_crossref",
            "제어 명령 통로가 열려 있는지는 통신 방식 위험에서 함께 봅니다.")
    plain = [e for e in exposures if getattr(e, "kind", "") == "exposure"]
    if plain:
        add("plaintext_control",
            "암호 없이 제어 명령이 오가는 통신 %d건을 찾았습니다." % len(plain),
            "할 일 → 장비가 놓인 방식")
    elif getattr(getattr(asset, "network", None), "protocols", ()):
        add("plaintext_control",
            "통신 목록은 있으나 평문 제어 통신으로 잡힌 것이 없습니다. "
            "암호화 여부가 미상인 통신은 질문으로 올라갑니다.",
            "자산 상세 → 다음에 확인할 것")

    # 수명주기 · 강제규칙 -------------------------------------------------
    lc = getattr(asset, "lifecycle_status", None)
    if lc:
        add("lifecycle", "수명주기 상태가 '%s' 로 기록돼 있습니다." % lc,
            "자산 상세 → 지금까지 아는 것")
    fired = set()
    for f in findings:
        fired.update(getattr(f, "fired_rules", ()) or ())
    if "H02" in fired:
        add("hard_rule_H02",
            "무인증 원격 쓰기가 중요 자산에 도달해 H02 가 발화했습니다 — 로직 "
            "변경이 허가 없이 가능한 상태입니다.", "할 일 → P0")
    if "H04" in fired:
        add("hard_rule_H04",
            "지원 종료 + 원격접속 경계 + 버전 미상으로 H04 가 발화했습니다.",
            "할 일")

    # 인벤토리 ----------------------------------------------------------
    ident = getattr(asset, "identity", None)
    have = [n for n, v in (("제조사", getattr(ident, "vendor_raw", None)),
                           ("모델명", getattr(ident, "model_raw", None)),
                           ("주문번호", getattr(ident, "order_number", None))) if v]
    if have:
        add("asset_inventory", "식별 정보: %s." % ", ".join(have))
        add("identity_completeness", None, "자산 목록 → 식별 완성도 L0~L5")
    fw = [c for c in getattr(asset, "components", ()) if c.version_raw]
    if fw:
        add("asset_inventory",
            "펌웨어/소프트웨어 버전 %d건이 출처·시점과 함께 있습니다." % len(fw))
    net = getattr(asset, "network", None)
    addr = list(getattr(net, "ips", ()) or ()) + list(getattr(net, "macs", ()) or ())
    if addr:
        add("network_addresses", "주소 정보(IP·MAC) %d건이 있습니다." % len(addr))
    peers = getattr(net, "observed_peers", ()) or ()
    if peers:
        add("topology", "관측된 통신 상대 %d개가 있습니다." % len(peers),
            "마인드맵 · 공격 경로")

    # 도달성 — **반증 쪽으로만 답한다** (ADR-014) --------------------------
    affirm, deny, obj = words
    if reachability is not None:
        v = getattr(reachability, "verdict", None)
        add("attack_paths", None, "공격 경로")
        if v is Tri.TRUE:
            add("reachability",
                "바깥에서 이 장비까지 **모든 구간이 확인된 경로**가 있습니다 — %s."
                % affirm, "공격 경로")
            add("blocking_candidates",
                "경로를 끊는 차단 후보와, 그때 영향받는 정상 통신을 함께 셉니다.",
                "공격 경로 → 차단 후보")
        elif v is Tri.UNKNOWN:
            add("reachability",
                "경로 일부가 추론이라 %s 확정하지 못했습니다." % obj)
        else:
            add("reachability",
                "관측된 범위에서는 닿는 길을 찾지 못했습니다. **%s** — 토폴로지가 "
                "미완일 수 있습니다." % deny)

    if capture_endpoints:
        add("capture_endpoints",
            "캡처에서 실제로 통신한 끝점 %d개를 찾았습니다. 인가 목록과 대조할 수 "
            "있습니다." % len(capture_endpoints), "자산 가져오기 → 캡처 파일")
    return g


def evidence_for(control: Control, asset, findings=(), exposures=(),
                 reachability=None, capture_endpoints=()) -> Evidence:
    """이 자산에 대해 이 항목의 근거가 있는가.

    `findings` 는 적용성 판정 목록, `exposures` 는 표 4 의 노출 발견,
    `reachability` 는 도달성 판정, `capture_endpoints` 는 캡처에서 본 끝점이다.
    없으면 없는 대로 — **없는 것을 '문제 없음' 으로 접지 않는다.**

    넘어온 것이 그 모양인지 먼저 확인한다. 범위 밖 항목이어도 확인한다 — 호출자의
    실수를 항목에 따라 봐주면 어느 항목에서 터질지가 표에 달린다.
    """
    findings = _require(findings, "findings", "적용성 판정", ("status",))
    exposures = _require(exposures, "exposures", "노출 발견", ("kind", "code"))
    if reachability is not None and not hasattr(reachability, "verdict"):
        raise TypeError("reachability 에 verdict 가 없다 — %s 를 받았다."
                        % type(reachability).__name__)

    if not control.assessable:
        return Evidence(control, NOT_ASSESSABLE,
                        ("정책·절차·물리·교육 항목이라 도구가 답할 수 없습니다.",), ())

    pool = _gather(asset, findings, exposures, reachability, capture_endpoints,
                   _SEPARATION.get(control.code, _SEPARATION_DEFAULT))
    basis: List[str] = []
    ptr: List[str] = []
    for kind in control.evidence_kind:
        for line, where in pool.get(kind, ()):
            if line and line not in basis:
                basis.append(line)
            if where and where not in ptr:
                ptr.append(where)

    if basis:
        for rider in _RIDERS.get(control.code, ()):
            if rider not in basis:
                basis.append(rider)
        return Evidence(control, PRESENT, tuple(basis), tuple(ptr))
    return Evidence(control, ABSENT,
                    ("이 항목에 댈 근거를 아직 만들지 못했습니다. **미달이라는 뜻이 "
                     "아닙니다** — 필요한 입력이 없을 수 있습니다.",), ())


def unproducible_kinds(cs: ControlSet) -> Tuple[str, ...]:
    """이 표준이 가리키는데 `_gather` 가 만들지 않는 근거 종류 (ADR-044).

    비어 있지 않으면 그 항목들은 입력이 다 있어도 '근거 없음' 이 된다.
    """
    want = {k for c in cs.controls for k in c.evidence_kind}
    return tuple(sorted(want - set(EVIDENCE_KINDS)))


def summarize(evidences: Sequence[Evidence]) -> Dict[str, int]:
    out = {PRESENT: 0, ABSENT: 0, NOT_ASSESSABLE: 0}
    for e in evidences:
        out[e.status] = out.get(e.status, 0) + 1
    return out
