# -*- coding: utf-8 -*-
"""공격자 능력 격자 (슬라이스 3 경로 탐색의 상태).

  network < credentials < code_exec < control_write

경로는 최단 거리가 아니라 **능력의 상태 전이**로 평가한다 (SPEC 10.1):
엣지를 지나려면 요구 능력을 이미 갖고 있어야 하고, 취약점이나 노출이
새 능력을 부여한다.

취약점이 능력을 부여하는지는 **CVSS 벡터에서 도출**한다 — 이것이 슬라이스 1의
판정이 경로 탐색에 영향을 주는 유일한 통로다. 추측하지 않는다: 벡터가 없으면
아무 능력도 부여하지 않는다.
"""
from __future__ import annotations

import re
from typing import FrozenSet, Optional, Tuple

NETWORK = "network"
CREDENTIALS = "credentials"
CODE_EXEC = "code_exec"
CONTROL_WRITE = "control_write"

# 낮은 것부터. 상위 능력이 하위를 함의하지는 않는다 — 별개의 능력으로 둔다.
LATTICE: Tuple[str, ...] = (NETWORK, CREDENTIALS, CODE_EXEC, CONTROL_WRITE)
RANK = {c: i for i, c in enumerate(LATTICE)}

PHRASES = {
    NETWORK: "네트워크 도달",
    CREDENTIALS: "자격증명 보유",
    CODE_EXEC: "코드 실행",
    CONTROL_WRITE: "제어 쓰기",
}

_AV = re.compile(r"AV:([NALP])")
_PR = re.compile(r"PR:([NLH])")
_UI = re.compile(r"UI:([NR])")
_I = re.compile(r"/I:([NLH])")


def grants_from_cvss(vector: Optional[str]) -> FrozenSet[str]:
    """CVSS 벡터에서 '이 취약점을 쓰면 무엇을 얻는가' 를 도출한다.

    보수적으로 읽는다 — 벡터가 없거나 파싱 불가면 **아무것도 부여하지 않는다**.
    없는 능력을 지어내면 경로가 거짓으로 이어져 R06(경로의 거짓 확신)이 된다.

      AV:N + PR:N  → 원격·무인증  → code_exec
      AV:N + PR:L/H → 원격·인증 필요 → code_exec (단 credentials 를 요구)
      I:H          → 무결성 완전 훼손 → control_write
    """
    if not vector:
        return frozenset()
    av = _AV.search(vector)
    pr = _PR.search(vector)
    if not av or not pr:
        return frozenset()

    granted = set()
    if av.group(1) == "N":
        granted.add(CODE_EXEC)
    integ = _I.search(vector)
    if integ and integ.group(1) == "H":
        granted.add(CONTROL_WRITE)
    return frozenset(granted)


def requires_from_cvss(vector: Optional[str]) -> FrozenSet[str]:
    """이 취약점을 쓰려면 무엇이 이미 있어야 하는가."""
    if not vector:
        return frozenset()
    av = _AV.search(vector)
    pr = _PR.search(vector)
    if not av or not pr:
        return frozenset()

    need = {NETWORK} if av.group(1) == "N" else set()
    if pr.group(1) in ("L", "H"):
        need.add(CREDENTIALS)
    return frozenset(need)


def describe(caps: FrozenSet[str]) -> str:
    if not caps:
        return "없음"
    return ", ".join(PHRASES[c] for c in sorted(caps, key=lambda c: RANK.get(c, 99)))
