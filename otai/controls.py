# -*- coding: utf-8 -*-
"""점검 항목에 **근거를 댄다** — 준수 여부를 판정하지 않는다 (ADR-043).

KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」의
`06. 제어시스템` 장은 점검항목 51개(C-01~C-51)를 둔다. 우리는 그중 **9개**에
기계가 만든 근거를 댈 수 있고, 나머지 42개는 정책·절차·물리·교육이라 도구가
답할 수 없다.

**'준수' 라고 말하지 않는다.** 취약점 분석·평가는 정보통신기반 보호법에 따라
자격을 갖춘 평가기관이 수행한다. 「양호」·「취약」은 그쪽의 판정 어휘이고, 우리가
쓰면 할 수 없는 법적 주장을 하는 것이다. 우리 어휘는 **근거 있음 / 근거 없음 /
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

#: 근거 상태 셋. **'양호'·'취약'·'준수' 를 쓰지 않는다** (ADR-043).
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
    severity: str          # 상 | 중 | 하 — 표준이 정한 값
    category: str
    our_scope: str         # direct | partial | none
    gist: Optional[str]
    evidence_kind: Tuple[str, ...]
    note: Optional[str]

    @property
    def assessable(self) -> bool:
        return self.our_scope in ("direct", "partial")


@dataclass(frozen=True)
class ControlSet:
    standard: dict
    disclaimer: str
    controls: Tuple[Control, ...]

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
    return ControlSet(
        standard=doc.get("standard") or {},
        disclaimer=doc.get("disclaimer", ""),
        controls=tuple(
            Control(
                code=c["code"], severity=c.get("severity", ""),
                category=c.get("category", ""), our_scope=c.get("our_scope", "none"),
                gist=c.get("gist"),
                evidence_kind=tuple(c.get("evidence_kind") or ()),
                note=c.get("note"),
            )
            for c in doc.get("controls") or ()
        ),
    )


def find_set(root="data/controls") -> Optional[Path]:
    d = Path(root)
    if not d.exists():
        return None
    files = sorted(d.glob("*.json"))
    return files[0] if files else None


# --------------------------------------------------------------------------
# 근거 모으기
# --------------------------------------------------------------------------
#: 적용성 상태 중 '이 장비가 해당한다' 쪽. `no_known_match` 는 포함하지 않는다 —
#: 대상이 아니라는 것은 근거가 아니다 (불변 규칙 1).
_APPLIES = ("affected_confirmed", "affected_likely", "candidate",
            "insufficient_information", "conflicting_evidence", "stale")


def evidence_for(control: Control, asset, findings=(), exposures=(),
                 reachability=None, capture_endpoints=()) -> Evidence:
    """이 자산에 대해 이 항목의 근거가 있는가.

    `findings` 는 적용성 판정 목록, `exposures` 는 표 4 의 노출 발견,
    `reachability` 는 도달성 판정, `capture_endpoints` 는 캡처에서 본 끝점이다.
    없으면 없는 대로 — **없는 것을 '문제 없음' 으로 접지 않는다.**
    """
    if not control.assessable:
        return Evidence(control, NOT_ASSESSABLE,
                        ("정책·절차·물리·교육 항목이라 도구가 답할 수 없습니다.",), ())

    basis: List[str] = []
    ptr: List[str] = []
    code = control.code

    if code == "C-18":
        hit = [f for f in findings if getattr(f, "status", None) in _APPLIES]
        if hit:
            basis.append("이 장비에 해당하는 권고문 %d건의 판정과 근거가 있습니다." % len(hit))
            ptr.append("자산 상세 → 이 자산에 대한 판정")
        if exposures:
            basis.append("패치로 없앨 수 없는 통신 방식 위험 %d건과 "
                         "보상 통제 제안이 있습니다." % len(exposures))
            ptr.append("할 일 → 장비가 놓인 방식")

    elif code == "C-19":
        lc = getattr(asset, "lifecycle_status", None)
        if lc:
            basis.append("수명주기 상태가 '%s' 로 기록돼 있습니다." % lc)
            ptr.append("자산 상세 → 지금까지 아는 것")
        if any("H04" in (getattr(f, "fired_rules", ()) or ()) for f in findings):
            basis.append("지원 종료 + 원격접속 경계 + 버전 미상으로 H04 가 발화했습니다.")
        if basis:
            basis.append("'최신 버전인가' 는 판단하지 않습니다 — 최신이 무엇인지 아는 "
                         "출처가 없고, 추정하면 없는 사실을 만듭니다.")

    elif code == "C-43":
        ident = getattr(asset, "identity", None)
        have = [n for n, v in (("제조사", getattr(ident, "vendor_raw", None)),
                               ("모델명", getattr(ident, "model_raw", None)),
                               ("주문번호", getattr(ident, "order_number", None))) if v]
        fw = [c for c in getattr(asset, "components", ()) if c.version_raw]
        net = getattr(asset, "network", None)
        addr = list(getattr(net, "ips", ()) or ()) + list(getattr(net, "macs", ()) or ())
        if have:
            basis.append("식별 정보: %s." % ", ".join(have))
        if fw:
            basis.append("펌웨어/소프트웨어 버전 %d건이 출처·시점과 함께 있습니다." % len(fw))
        if addr:
            basis.append("주소 정보(IP·MAC) %d건이 있습니다." % len(addr))
        if basis:
            basis.append("담당자와 설치 SW 목록은 아직 담지 못합니다.")
            ptr.append("자산 목록 → 식별 완성도 L0~L5")

    elif code in ("C-08", "C-12"):
        plain = [e for e in exposures if getattr(e, "kind", "") == "exposure"]
        if plain:
            basis.append("암호 없이 제어 명령이 오가는 통신 %d건을 찾았습니다." % len(plain))
            ptr.append("할 일 → 장비가 놓인 방식")
        elif getattr(getattr(asset, "network", None), "protocols", ()):
            basis.append("통신 목록은 있으나 평문 제어 통신으로 잡힌 것이 없습니다. "
                         "암호화 여부가 미상인 통신은 질문으로 올라갑니다.")
            ptr.append("자산 상세 → 다음에 확인할 것")

    elif code == "C-21":
        if reachability is not None:
            v = getattr(reachability, "verdict", None)
            if v is Tri.TRUE:
                basis.append("바깥에서 이 장비까지 **모든 구간이 확인된 경로**가 있습니다 "
                             "— 분리되어 있지 않다는 근거입니다.")
                ptr.append("공격 경로")
            elif v is Tri.UNKNOWN:
                basis.append("경로 일부가 추론이라 분리 여부를 확정하지 못했습니다.")
            else:
                basis.append("관측된 범위에서는 닿는 길을 찾지 못했습니다. "
                             "**분리됐다는 뜻이 아닙니다** — 토폴로지가 미완일 수 있습니다.")

    elif code == "C-24":
        if capture_endpoints:
            basis.append("캡처에서 실제로 통신한 끝점 %d개를 찾았습니다. "
                         "인가 목록과 대조할 수 있습니다." % len(capture_endpoints))
            ptr.append("자산 가져오기 → 캡처 파일")

    elif code == "C-26":
        peers = getattr(getattr(asset, "network", None), "observed_peers", ()) or ()
        if peers:
            basis.append("관측된 통신 상대 %d개가 있습니다." % len(peers))
            ptr.append("마인드맵 · 공격 경로")

    elif code == "C-50":
        if any("H02" in (getattr(f, "fired_rules", ()) or ()) for f in findings):
            basis.append("무인증 원격 쓰기가 중요 자산에 도달해 H02 가 발화했습니다 "
                         "— 로직 변경이 허가 없이 가능한 상태입니다.")
            ptr.append("할 일 → P0")
        if any(getattr(e, "code", "") for e in exposures):
            basis.append("제어 명령 통로가 열려 있는지는 통신 방식 위험에서 함께 봅니다.")

    status = PRESENT if basis else ABSENT
    if status == ABSENT:
        basis = ["이 항목에 댈 근거를 아직 만들지 못했습니다. "
                 "**미달이라는 뜻이 아닙니다** — 필요한 입력이 없을 수 있습니다."]
    return Evidence(control, status, tuple(basis), tuple(ptr))


def summarize(evidences: Sequence[Evidence]) -> Dict[str, int]:
    out = {PRESENT: 0, ABSENT: 0, NOT_ASSESSABLE: 0}
    for e in evidences:
        out[e.status] = out.get(e.status, 0) + 1
    return out
