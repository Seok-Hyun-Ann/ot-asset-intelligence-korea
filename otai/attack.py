# -*- coding: utf-8 -*-
"""MITRE ATT&CK for ICS 연동 (표 13, SPEC 10.1).

**엣지 타입 → 기법 매핑만 한다. CVE → 기법 매핑은 하지 않는다** (ADR-015).

SPEC 10.1: "CVE 에서 기법으로의 연결은 **출처가 있는 매핑과 내부 추론을 구분**".
CVE→기법에는 권위 있는 공개 출처가 사실상 없다. 내부 추론으로 만들면 그것이 바로
SPEC 이 경계하는 출처 없는 매핑이고, LLM 으로 만들면 표 32 위반이다.

엣지 타입→기법은 경로 **구조**에서 직접 도출되므로 근거를 댈 수 있다. 그래도
내부 매핑임을 숨기지 않고 각 항목에 `provenance="internal:edge_type"` 을 붙인다.

버전 고정 (표 14): `ics-attack-<version>.json` 을 그대로 저장하고 버전을 기록한다.
"""
from __future__ import annotations

import json
import re
from .safeio import bounded_json_load
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

# 엣지 타입 → ATT&CK ICS 기법.
# **내부 매핑이다.** 경로 구조에서 도출되며 CVE 와는 무관하다.
# 항목을 늘릴 때는 "이 엣지가 존재한다는 사실만으로 그 기법이 성립하는가" 를 물을 것.
EDGE_TYPE_TECHNIQUES: Dict[str, Tuple[str, ...]] = {
    # 엔지니어링 워크스테이션이 PLC 를 관리 = 프로그램 다운로드 경로
    "administers": ("T0843",),          # Program Download
    # 평문 제어 프로토콜 도달 = 비인가 명령 메시지
    # v19 에서 ICS 기법 체계가 재편되었다: T0855(Unauthorized Command Message)는
    # revoked 되고 T1692(Unauthorized Message)/T1692.001(Command Message)로 대체됐다.
    # 이것이 표 14 가 "버전 고정 · 폐기 항목 유지"를 요구하는 이유다 —
    # ID 를 고정 문자열로 박아두면 조용히 아무것도 매핑되지 않는다.
    "can_reach_control": ("T1692.001",),
    # 논리적 제어 관계 = 파라미터 변조 지점
    "controls": ("T0836",),             # Modify Parameter
}

CONTROL_PROTOCOLS = ("modbus_tcp", "modbus")

# v18 이하는 T0xxx, v19 부터 T1xxx(+ .00n 하위기법)
_TECHNIQUE_ID = re.compile(r"^T\d{3,4}(\.\d{3})?$")


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    description: str
    provenance: str = "internal:edge_type"


@dataclass(frozen=True)
class AttackCatalog:
    version: str
    techniques: Dict[str, Technique]
    source_path: str

    def get(self, tid: str) -> Optional[Technique]:
        return self.techniques.get(tid)

    def for_edge(self, edge) -> Tuple[Technique, ...]:
        """이 엣지의 구조가 함의하는 기법. 없으면 빈 튜플."""
        keys = [edge.edge_type]
        if edge.edge_type == "can_reach" and \
                (edge.protocol or "").lower() in CONTROL_PROTOCOLS:
            keys.append("can_reach_control")

        out = []
        for k in keys:
            for tid in EDGE_TYPE_TECHNIQUES.get(k, ()):
                t = self.get(tid)
                if t is not None and t not in out:
                    out.append(t)
        return tuple(out)


def load_attack(path) -> AttackCatalog:
    """ATT&CK ICS STIX 번들에서 attack-pattern 만 색인한다."""
    path = Path(path)
    doc = bounded_json_load(path)                       # 외부 번들 — safeio 경유

    version = ""
    techniques: Dict[str, Technique] = {}
    for obj in doc.get("objects", ()):
        t = obj.get("type")
        if t == "x-mitre-collection":
            version = obj.get("x_mitre_version", "") or version
        if t != "attack-pattern":
            continue
        # 번들에 따라 source_name 이 "mitre-attack" 또는 레거시 "mitre-ics-attack" 이다.
        # 둘 다 받되 ICS 기법 ID 형태(T0xxx)만 채택한다.
        tid = None
        for ref in obj.get("external_references", ()):
            if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack"):
                candidate = ref.get("external_id") or ""
                if _TECHNIQUE_ID.match(candidate):
                    tid = candidate
                    break
        if not tid:
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue  # 폐기 항목은 색인하지 않는다 (표 14)
        techniques[tid] = Technique(
            technique_id=tid,
            name=obj.get("name", ""),
            description=(obj.get("description", "") or "").split("\n")[0][:300],
        )

    if not version:
        version = Path(path).stem.replace("ics-attack-", "")

    return AttackCatalog(version=version, techniques=techniques, source_path=path.name)


def verify_mapping(catalog: AttackCatalog) -> Tuple[str, ...]:
    """매핑 테이블의 기법 ID 가 이 번들에서 실제로 해석되는지 확인한다.

    ATT&CK 는 릴리스마다 기법을 revoke·재편한다. 확인하지 않으면 매핑이 조용히
    비어버린다 — 실제로 v19 에서 T0855 가 revoked 되며 그 일이 일어났다.
    """
    missing = []
    for _, tids in sorted(EDGE_TYPE_TECHNIQUES.items()):
        for tid in tids:
            if catalog.get(tid) is None:
                missing.append(tid)
    return tuple(missing)


def find_bundle(root="data/attack") -> Optional[Path]:
    base = Path(root)
    if not base.exists():
        return None
    cands = sorted(base.glob("ics-attack-*.json"))
    return cands[-1] if cands else None
