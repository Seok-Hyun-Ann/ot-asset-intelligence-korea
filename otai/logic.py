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
