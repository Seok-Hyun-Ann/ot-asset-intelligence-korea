# -*- coding: utf-8 -*-
"""자산 모델과 as_of 시간 축.

SPEC 7.2: published_at / modified_at / ingested_at / observed_at / valid_until 을
섞지 않는다. 이 모듈이 다루는 것은 observed_at 하나뿐이다.

as_of 규칙 (설계 원칙 P7): 특정 과거 시점으로 조회하면 그 시점에 **알고 있던 것만**
쓴다. 그 이후의 관측은 존재하지 않는 것으로 취급한다 — 이것이 판정 재현의 근거다.
"""
from __future__ import annotations

import json
from .safeio import bounded_json_load
from dataclasses import dataclass, replace
from datetime import date, datetime
from pathlib import Path
from typing import List, Optional, Tuple

# 신선도 정책: 이보다 오래된 관측으로는 '확정' 상태를 만들지 않는다 (표 10 stale)
DEFAULT_FRESHNESS_DAYS = 365


def parse_ts(value: Optional[str]) -> Optional[date]:
    """ISO 문자열을 date 로. 시각·타임존은 날짜 단위 비교로 축약한다."""
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        pass
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        return None


@dataclass(frozen=True)
class Component:
    type: str
    version_raw: Optional[str]      # None = 미상 (0 으로 치환하지 않는다)
    version_state: str              # "known" | "unknown"
    observed_at: Optional[str]
    method: Optional[str]
    evidence_id: Optional[str]

    @property
    def observed_date(self) -> Optional[date]:
        return parse_ts(self.observed_at)


@dataclass(frozen=True)
class Protocol:
    """자산이 노출하는 서비스. 표 4 의 Exposure Pattern 근거가 된다."""
    protocol: str
    port: Optional[int]
    role: Optional[str]          # server | client
    encrypted: Optional[bool]    # None = 미상 (false 로 가정하지 않는다)

    @property
    def is_plaintext_control_server(self) -> bool:
        """평문 제어 프로토콜 서버 — 무인증 원격 쓰기의 전제.

        전통적 Modbus TCP(502)는 애플리케이션 계층에 인증·기밀성이 없다.
        Modbus Security 는 802 를 쓴다 (SPEC 2.2).
        """
        return (
            self.protocol.lower().replace("-", "_") in ("modbus_tcp", "modbus")
            and self.role == "server"
            and self.encrypted is False
        )


@dataclass(frozen=True)
class NetworkAddress:
    """자산이 쓰는 주소 하나. **값이 아니라 관측이다** (ADR-042).

    CISA 자산 인벤토리 지침의 고우선 속성 중 Hostname·IP·MAC 과 중간 우선순위의
    VLAN 이 여기 담긴다. 하나로 접지 않는 이유는 이중화 CPU·다중 NIC 가 현장에서
    예외가 아니기 때문이다 — 접으면 나머지가 조용히 사라진다.

    `method` 가 출처다: `capture`(PCAP 관측) · `import`(사람이 CSV 로) ·
    `manual` · `project_file`. 부품 버전과 같은 규율이다 (ADR-038).
    """
    ip: Optional[str] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vlan: Optional[int] = None
    method: Optional[str] = None
    observed_at: Optional[str] = None
    evidence_id: Optional[str] = None

    @property
    def observed_date(self):
        return parse_ts(self.observed_at)

    @property
    def is_empty(self) -> bool:
        return not any((self.ip, self.mac, self.hostname, self.vlan))


@dataclass(frozen=True)
class Network:
    protocols: Tuple[Protocol, ...] = ()
    remote_access: Optional[dict] = None
    observed_peers: Tuple[str, ...] = ()
    declared: bool = False       # 네트워크 정보를 아예 수집하지 않았으면 False
    addresses: Tuple[NetworkAddress, ...] = ()

    def _distinct(self, attr) -> Tuple:
        """순서를 지키며 중복만 없앤다. 정렬하면 '처음 본 것' 이 사라진다."""
        out = []
        for a in self.addresses:
            v = getattr(a, attr)
            if v is not None and v not in out:
                out.append(v)
        return tuple(out)

    @property
    def ips(self) -> Tuple[str, ...]:
        return self._distinct("ip")

    @property
    def macs(self) -> Tuple[str, ...]:
        return self._distinct("mac")

    @property
    def hostnames(self) -> Tuple[str, ...]:
        return self._distinct("hostname")

    @property
    def vlans(self) -> Tuple[int, ...]:
        return self._distinct("vlan")

    @property
    def has_remote_access(self):
        """Tri 로 답한다 — 미수집과 '없음' 을 구분한다."""
        from .logic import Tri
        if not self.declared:
            return Tri.UNKNOWN
        if self.remote_access is None:
            return Tri.FALSE
        return Tri.TRUE


@dataclass(frozen=True)
class Identity:
    vendor_raw: Optional[str]
    family_raw: Optional[str]
    model_raw: Optional[str]
    order_number: Optional[str]

    @property
    def has_any(self) -> bool:
        return any((self.vendor_raw, self.family_raw, self.model_raw, self.order_number))


@dataclass(frozen=True)
class Asset:
    asset_id: str
    asset_type: str
    identity: Identity
    components: Tuple[Component, ...]
    location: dict
    operations: dict
    remediation_evidence: Tuple[dict, ...] = ()
    network: Network = Network()
    lifecycle_status: Optional[str] = None   # supported | EOL | EOS | unknown

    # ---- as_of 투영 -------------------------------------------------------
    def as_of(self, as_of_date: date) -> "Asset":
        """as_of 시점에 알고 있던 자산으로 투영한다.

        이후에 관측된 값은 미상으로 되돌린다. 관측을 삭제하지 않고 **미상으로
        낮추는** 이유는, 그 부품이 존재한다는 사실 자체는 as_of 이전 정보일 수
        있기 때문이다.
        """
        projected = []
        for c in self.components:
            od = c.observed_date
            if od is not None and od > as_of_date:
                projected.append(replace(c, version_raw=None, version_state="unknown",
                                         observed_at=None, evidence_id=None))
            else:
                projected.append(c)
        rem = tuple(
            r for r in self.remediation_evidence
            if (parse_ts(r.get("observed_at")) or date.min) <= as_of_date
        )
        # 주소도 관측이다. 투영하지 않으면 2월 판정이 9월에 처음 본 MAC 을
        # 말하게 된다 — 재현성(불변 규칙 4)의 구멍이다 (ADR-042).
        # 날짜가 없는 주소는 **남긴다** — 모르는 것을 '이후에 생겼다' 로 읽지 않는다.
        addrs = tuple(
            a for a in self.network.addresses
            if a.observed_date is None or a.observed_date <= as_of_date
        )
        net = replace(self.network, addresses=addrs)
        return replace(self, components=tuple(projected), remediation_evidence=rem,
                       network=net)

    def remediation_for(self, advisory_id: str) -> Optional[dict]:
        for r in self.remediation_evidence:
            if str(r.get("advisory_id", "")).upper() == advisory_id.upper():
                return r
        return None


def load_asset(path) -> Asset:
    # 자산 파일은 사용자가 손으로 고쳐 되돌려주는 입력이다 (ADR-038/039).
    return asset_from_dict(bounded_json_load(path))


def asset_from_dict(data: dict) -> Asset:
    """부록 C 형식 본문 → Asset. 저장소는 이미 dict 를 들고 있으므로 파일을 거치지 않는다."""
    ident = data.get("identity") or {}

    comps: List[Component] = []
    for c in data.get("components") or ():
        v = c.get("version") or {}
        raw = v.get("raw")
        state = v.get("state") or ("known" if raw else "unknown")
        comps.append(
            Component(
                type=c.get("type", ""),
                version_raw=raw,
                version_state=state,
                observed_at=c.get("observed_at"),
                method=c.get("method"),
                evidence_id=c.get("evidence_id"),
            )
        )

    net = data.get("network")
    network = Network(
        protocols=tuple(
            Protocol(
                protocol=pr.get("protocol", ""),
                port=pr.get("port"),
                role=pr.get("role"),
                encrypted=pr.get("encrypted"),
            )
            for pr in (net or {}).get("services", []) or (net or {}).get("protocols", [])
        ),
        remote_access=(net or {}).get("remote_access"),
        observed_peers=tuple((net or {}).get("observed_peers") or ()),
        # `declared` 는 '네트워크를 조사했는가' 다 — `has_remote_access` 를 거쳐
        # H04 에 들어간다. 주소만 있는 블록이 이걸 켜면 "원격접속 없음" 이 되어
        # 조사하지 않은 것이 '없음' 으로 붕괴한다 (불변 규칙 2).
        declared=net is not None and (
            "remote_access" in net or "services" in net or "protocols" in net
            or "observed_peers" in net or net.get("declared") is True),
        addresses=tuple(
            NetworkAddress(
                ip=a.get("ip"), mac=a.get("mac"), hostname=a.get("hostname"),
                vlan=a.get("vlan"), method=a.get("method"),
                observed_at=a.get("observed_at"), evidence_id=a.get("evidence_id"),
            )
            for a in ((net or {}).get("addresses") or ())
        ),
    )

    return Asset(
        asset_id=data["asset_id"],
        asset_type=data.get("asset_type", ""),
        identity=Identity(
            vendor_raw=ident.get("vendor_raw"),
            family_raw=ident.get("family_raw"),
            model_raw=ident.get("model_raw"),
            order_number=ident.get("order_number"),
        ),
        components=tuple(comps),
        location=data.get("location") or {},
        operations=data.get("operations") or {},
        remediation_evidence=tuple(data.get("remediation_evidence") or ()),
        network=network,
        lifecycle_status=data.get("lifecycle_status"),
    )
