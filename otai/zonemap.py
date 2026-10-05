# -*- coding: utf-8 -*-
"""구역 선언 — 캡처가 모르는 것을 사람이 적는다 (ADR-047).

`capture.py` 는 `purdue_level=None` · `zone=None` 을 만든다. 패킷에 그 정보가
없으므로 옳다 (ADR-039). 그런데 **채울 방법이 없었다**: 레벨이 미상이면 도달성이
확정되지 않고(ADR-045), H01~H03 이 막혀 **첫 화면이 전부 `P?` 로 찬다.** 엔진은
정확히 옳게 동작하는데 현업자는 "이 도구는 아무것도 못 말하네" 로 읽는다.

그래서 구역을 **파일로 선언한다.** 현업자가 실제로 아는 모양 그대로다:

    10.10.10.0/24  → 제어망,  Purdue 2
    192.168.88.0/24 → 사무망, Purdue 4, 외부 진입점

**선언은 관측이 아니다.** 이 모듈이 채운 값은 `declared_by` 와 선언 파일의 해시를
증거에 남긴다 — 캡처에서 본 것과 사람이 적은 것을 섞으면, 나중에 "이 레벨을 누가
정했나" 에 답할 수 없다 (불변 규칙 5: 계보 100%).

**규칙에 걸리지 않은 노드는 비워 둔다.** 기본값을 주지 않는다 — `purdue_level=0`
으로 채우면 모르는 장비가 전부 물리 제어 계층이 되고 `critical_nodes()` 가 그것을
안전 핵심 표적으로 센다 (ADR-039 가 막은 것).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .safeio import UnsafeInput, bounded_json_load

#: 선언으로 채울 수 있는 것. 이 밖의 필드는 건드리지 않는다.
DECLARABLE = ("zone", "purdue_level", "is_entry_point", "is_critical", "node_type")

MAX_RULES = 500


@dataclass(frozen=True)
class ZoneRule:
    """한 줄의 선언. `cidr` 또는 `node_id` 중 하나로 고른다."""
    zone: Optional[str] = None
    purdue_level: Optional[float] = None
    is_entry_point: bool = False
    is_critical: bool = False
    node_type: Optional[str] = None
    cidr: Optional[str] = None
    node_id: Optional[str] = None
    note: Optional[str] = None

    @property
    def network(self):
        if not self.cidr:
            return None
        try:
            return ipaddress.ip_network(self.cidr, strict=False)
        except ValueError as exc:
            raise UnsafeInput("구역 규칙의 CIDR 을 읽을 수 없습니다: %s (%s)"
                              % (self.cidr, exc), "zonemap")

    def matches(self, node_id: str) -> bool:
        if self.node_id:
            return self.node_id == node_id
        net = self.network
        if net is None:
            return False
        try:
            return ipaddress.ip_address(node_id) in net
        except ValueError:
            return False          # IP 모양이 아닌 노드 id (이름 노드) 는 CIDR 로 안 걸린다


@dataclass(frozen=True)
class ZoneMap:
    rules: Tuple[ZoneRule, ...]
    sha256: str
    source: str

    def rule_for(self, node_id: str) -> Optional[ZoneRule]:
        """**먼저 쓴 규칙이 이긴다.** 좁은 것을 위에 두면 그대로 동작한다.

        우선순위를 접두 길이로 자동 정렬하지 않는 이유: 사람이 적은 순서가
        사람의 의도다. 자동으로 바꾸면 `0.0.0.0/0` 을 맨 위에 둔 사람의 "전부
        외부로 보되 아래에서 예외" 라는 의도가 조용히 뒤집힌다.
        """
        for r in self.rules:
            if r.matches(node_id):
                return r
        return None


def load_zonemap(path) -> ZoneMap:
    """구역 선언 파일을 읽는다. 외부 파일이므로 `safeio` 를 거친다 (ADR-041)."""
    p = Path(path)
    doc = bounded_json_load(p)
    raw = doc.get("zones") if isinstance(doc, dict) else doc
    if not isinstance(raw, list):
        raise UnsafeInput("구역 선언은 목록이어야 합니다 ('zones' 키 또는 최상위 배열)",
                          p.name)
    if len(raw) > MAX_RULES:
        raise UnsafeInput("구역 규칙 %d개 > 상한 %d" % (len(raw), MAX_RULES), p.name)

    rules = []
    for i, r in enumerate(raw):
        if not isinstance(r, dict):
            raise UnsafeInput("%d번째 구역 규칙이 객체가 아닙니다" % (i + 1), p.name)
        if not r.get("cidr") and not r.get("node_id"):
            raise UnsafeInput("%d번째 구역 규칙에 cidr 도 node_id 도 없습니다"
                              % (i + 1), p.name)
        lvl = r.get("purdue_level")
        rule = ZoneRule(
            zone=r.get("zone"),
            purdue_level=None if lvl is None else float(lvl),
            is_entry_point=bool(r.get("is_entry_point")),
            is_critical=bool(r.get("is_critical")),
            node_type=r.get("node_type"),
            cidr=r.get("cidr"), node_id=r.get("node_id"),
            note=r.get("note"),
        )
        rule.network          # CIDR 을 지금 검증한다 — 적용 중에 터지지 않게
        rules.append(rule)

    return ZoneMap(rules=tuple(rules),
                   sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
                   source=p.name)


@dataclass
class ApplyResult:
    declared: int = 0                                  # 값이 채워진 노드 수
    untouched: List[str] = field(default_factory=list)  # 규칙에 안 걸린 노드
    entry_points: List[str] = field(default_factory=list)


def apply_zonemap(doc: dict, zmap: ZoneMap) -> ApplyResult:
    """토폴로지 문서에 선언을 적용한다. **문서를 제자리에서 고친다.**

    이미 값이 있는 필드는 덮어쓰지 않는다 (불변 규칙 3: Assertion 은 추가만).
    """
    res = ApplyResult()
    for node in doc.get("nodes") or ():
        nid = node.get("node_id") or ""
        rule = zmap.rule_for(nid)
        if rule is None:
            res.untouched.append(nid)
            continue

        touched = []
        for fieldname in DECLARABLE:
            value = getattr(rule, fieldname)
            if value in (None, False, ""):
                continue
            if node.get(fieldname) not in (None, False, ""):
                continue          # 이미 아는 값을 덮지 않는다
            node[fieldname] = value
            touched.append(fieldname)
        if not touched:
            res.untouched.append(nid)
            continue

        res.declared += 1
        if rule.is_entry_point:
            res.entry_points.append(nid)
        # **선언은 관측이 아니다.** 누가 적었는지를 증거에 남긴다 (불변 규칙 5).
        ev = node.setdefault("evidence", {})
        ev["declared_by"] = "zonemap"
        ev["declared_fields"] = touched
        ev["zonemap_sha256"] = zmap.sha256
        if rule.note:
            ev["declared_note"] = rule.note

    prov = doc.setdefault("provenance", {})
    prov["zonemap"] = {
        "source": zmap.source, "sha256": zmap.sha256,
        "rules": len(zmap.rules), "declared_nodes": res.declared,
        "note": "Purdue 레벨·구역·진입점은 **사람이 선언한 값**이고 캡처에서 "
                "관측한 것이 아닙니다. 통신(엣지)만 관측입니다.",
    }
    return res


def template(doc: dict) -> dict:
    """토폴로지에 보이는 주소로 **빈 선언 서식**을 만든다.

    현업자가 처음부터 쓰지 않게 /24 단위로 묶어 주되, **값은 비워 둔다** —
    레벨을 추측해서 채워 주면 그 추측이 사실로 굳는다.
    """
    nets: Dict[str, int] = {}
    others: List[str] = []
    for node in doc.get("nodes") or ():
        nid = node.get("node_id") or ""
        try:
            ip = ipaddress.ip_address(nid)
        except ValueError:
            others.append(nid)
            continue
        net = str(ipaddress.ip_network("%s/24" % ip, strict=False)) if ip.version == 4 \
            else str(ipaddress.ip_network("%s/64" % ip, strict=False))
        nets[net] = nets.get(net, 0) + 1

    zones = [{"cidr": net, "zone": "", "purdue_level": None,
              "is_entry_point": False,
              "note": "장비 %d대가 이 대역에 있습니다 — 구역 이름과 Purdue 레벨을 "
                      "적어 주세요" % n}
             for net, n in sorted(nets.items(), key=lambda kv: -kv[1])]
    for nid in sorted(others):
        zones.append({"node_id": nid, "zone": "", "purdue_level": None,
                      "is_entry_point": False,
                      "note": "IP 모양이 아닌 노드입니다"})
    return {
        "_설명": [
            "구역 선언 서식입니다. zone 과 purdue_level 을 채워 `--zones` 로 주세요.",
            "먼저 쓴 규칙이 이깁니다 — 좁은 대역을 위에 두세요.",
            "Purdue: 0 물리공정 · 1 기본제어 · 2 감시제어 · 3 운영 · 4 기업망 · 5 외부",
            "밖에서 들어오는 자리에 is_entry_point: true 를 주세요. 하나도 없으면",
            "도달성이 미상으로 남습니다 — '닿지 않는다' 가 아닙니다 (ADR-045).",
            "비워 둔 항목은 **채우지 않은 것으로 남습니다.** 추측해서 넣지 않습니다.",
        ],
        "zones": zones,
    }
