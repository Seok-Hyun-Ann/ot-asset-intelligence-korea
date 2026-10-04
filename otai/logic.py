# -*- coding: utf-8 -*-
"""Kleene 삼진 논리.

불변 규칙 2 (docs/DECISIONS.md): unknown 을 false 로 붕괴시키지 않는다.
이 모듈이 그 규칙의 유일한 구현 지점이다. 다른 곳에서 bool 로 캐스팅하지 말 것.
"""
from __future__ import annotations

import enum


class Tri(enum.Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"

    @property
    def ko(self) -> str:
        """사람에게 보일 표기. 화면·CLI 는 한국어가 기본이다 (NFR-LOC-001).

        `.value` 를 그대로 찍으면 한국어 화면에 `true`/`unknown` 이 뜬다. 그리고
        `unknown` 은 **언제나 '미상'** 이다 — 빈칸이나 `—` 로 두면 '없음' 으로
        읽힌다 (ADR-031).
        """
        return _KO[self]

    def __bool__(self):  # noqa: D105
        raise TypeError(
            "Tri 를 bool 로 캐스팅할 수 없습니다. UNKNOWN 이 조용히 False 가 되는 것을 "
            "막기 위한 의도적 제한입니다. `is Tri.TRUE` 로 명시 비교하세요."
        )

    @staticmethod
    def and_(*vals: "Tri") -> "Tri":
        """FALSE 가 흡수원. 하나라도 FALSE 면 나머지가 UNKNOWN 이어도 FALSE."""
        if any(v is Tri.FALSE for v in vals):
            return Tri.FALSE
        if any(v is Tri.UNKNOWN for v in vals):
            return Tri.UNKNOWN
        return Tri.TRUE

    @staticmethod
    def or_(*vals: "Tri") -> "Tri":
        """TRUE 가 흡수원."""
        if any(v is Tri.TRUE for v in vals):
            return Tri.TRUE
        if any(v is Tri.UNKNOWN for v in vals):
            return Tri.UNKNOWN
        return Tri.FALSE

    @staticmethod
    def not_(v: "Tri") -> "Tri":
        if v is Tri.TRUE:
            return Tri.FALSE
        if v is Tri.FALSE:
            return Tri.TRUE
        return Tri.UNKNOWN


#: 클래스 **밖에** 둔다 — 본문 안의 평범한 dict 는 enum 멤버로 잡힌다.
_KO = {Tri.TRUE: "예", Tri.FALSE: "아니오", Tri.UNKNOWN: "미상"}
