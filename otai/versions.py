# -*- coding: utf-8 -*-
"""버전 문법 판별 · 비교 · 범위 평가 (R03).

실데이터가 요구하는 문법 2종:
  freeform  "<=48"                         CISA / 다수 조정기관
  vers:     "vers:intdot/>=3.1.6|<3.1.7"   Siemens ProductCERT

설계 원칙 (SPEC 8.2):
  - raw_expression 은 언제나 보존한다. 정규화 값은 별도.
  - SemVer 를 가정하지 않는다. scheme 별 비교기로 처리한다.
  - 버전 미상을 0 으로 치환하지 않는다.
  - 비교 불가는 UNKNOWN 이다. 절대 FALSE 가 아니다 (false safe 방지).

vers: 문법 단순화 — `|` 로 이어진 제약을 AND 로 해석한다. Siemens 실사용
(`>=3.1.6`, `>=3.1.6|<3.1.7`)은 전부 단일 구간이라 이 해석이 정확하다.
교대 구간을 쓰는 공급자가 등장하면 그때 VERS 정식 의미론으로 확장한다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Tuple

from .logic import Tri

# 지원 scheme: 정수-점 (펌웨어 리비전, Siemens intdot, 단일 정수 "48")
INTDOT = "intdot"
UNKNOWN_SCHEME = "unknown_scheme"

_OPS = ("<=", ">=", "!=", "==", "<", ">", "=")
_CONSTRAINT_RE = re.compile(r"^\s*(<=|>=|!=|==|<|>|=)?\s*[vV]?([0-9][0-9.]*)\s*$")
_VERSION_RE = re.compile(r"^\s*[vV]?([0-9]+(?:\.[0-9]+)*)\s*$")


@dataclass(frozen=True)
class Constraint:
    op: str
    version: Tuple[int, ...]
    raw: str


@dataclass(frozen=True)
class VersionRange:
    raw: str
    grammar: str  # "vers" | "freeform" | "unparseable"
    scheme: str
    constraints: Tuple[Constraint, ...] = field(default=())
    wildcard: bool = False   # vers:all/* — 모든 버전이 영향 범위

    @property
    def parseable(self) -> bool:
        if self.wildcard:
            return True
        return self.grammar != "unparseable" and bool(self.constraints)


def parse_version(raw: Optional[str]) -> Optional[Tuple[int, ...]]:
    """정수-점 버전을 튜플로. 파싱 불가는 None (0 으로 치환하지 않는다)."""
    if raw is None:
        return None
    m = _VERSION_RE.match(str(raw))
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def _pad(a: Tuple[int, ...], b: Tuple[int, ...]):
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def _parse_constraint(text: str) -> Optional[Constraint]:
    m = _CONSTRAINT_RE.match(text)
    if not m:
        return None
    op = m.group(1) or "="
    if op == "==":
        op = "="
    v = parse_version(m.group(2))
    if v is None:
        return None
    return Constraint(op=op, version=v, raw=text.strip())


def parse_range(raw: Optional[str]) -> VersionRange:
    """문법을 판별해 파싱한다. 실패해도 raw 는 항상 보존된다."""
    text = "" if raw is None else str(raw)
    stripped = text.strip()

    if stripped.startswith("vers:"):
        body = stripped[len("vers:"):]
        scheme, sep, rest = body.partition("/")

        # vers:all/* = "모든 버전 영향". Siemens 실데이터에서 157개 product 중
        # 23개(15%)가 이 표기를 쓴다. 파싱 실패로 두면 UNKNOWN 이 되어 적용 대상을
        # 놓친다 — false safe 는 아니지만 표 39 의 후보 Recall 을 깎는다.
        if rest.strip() == "*":
            return VersionRange(raw=text, grammar="vers", scheme=scheme or "all",
                                wildcard=True)

        cons = []
        if sep and rest.strip():
            for part in rest.split("|"):
                c = _parse_constraint(part)
                if c is None:
                    cons = []
                    break
                cons.append(c)
        if not cons:
            return VersionRange(raw=text, grammar="vers", scheme=scheme or UNKNOWN_SCHEME)
        return VersionRange(
            raw=text,
            grammar="vers",
            scheme=scheme or INTDOT,
            constraints=tuple(cons),
        )

    c = _parse_constraint(stripped)
    if c is not None:
        return VersionRange(raw=text, grammar="freeform", scheme=INTDOT, constraints=(c,))

    # 연산자를 포함하지만 버전을 못 읽은 경우도 freeform 시도로 본다
    grammar = "freeform" if any(op in stripped for op in _OPS) else "unparseable"
    return VersionRange(raw=text, grammar=grammar, scheme=UNKNOWN_SCHEME)


def _eval(version: Tuple[int, ...], c: Constraint) -> Tri:
    a, b = _pad(version, c.version)
    if c.op == "<=":
        ok = a <= b
    elif c.op == ">=":
        ok = a >= b
    elif c.op == "<":
        ok = a < b
    elif c.op == ">":
        ok = a > b
    elif c.op == "=":
        ok = a == b
    elif c.op == "!=":
        ok = a != b
    else:  # pragma: no cover - _CONSTRAINT_RE 가 막는다
        return Tri.UNKNOWN
    return Tri.TRUE if ok else Tri.FALSE


def in_range(version_raw: Optional[str], rng: VersionRange) -> Tri:
    """버전이 범위 안인가. 판단 불가는 UNKNOWN.

    UNKNOWN 을 반환하는 경우:
      - 버전이 없거나 이 scheme 으로 읽을 수 없음
      - 범위 표현을 파싱할 수 없음
    둘 중 어느 쪽도 FALSE(=비해당)로 답하지 않는다. 그것이 false safe 다.
    """
    if not rng.parseable:
        return Tri.UNKNOWN
    v = parse_version(version_raw)
    if v is None:
        return Tri.UNKNOWN
    if rng.wildcard:
        # 모든 버전이 영향이지만, **버전을 아는 경우에만** 확정한다.
        # 버전 미상이면 위에서 이미 UNKNOWN 으로 빠졌다.
        return Tri.TRUE
    if rng.scheme not in (INTDOT, "generic", "semver"):
        return Tri.UNKNOWN
    return Tri.and_(*(_eval(v, c) for c in rng.constraints))
