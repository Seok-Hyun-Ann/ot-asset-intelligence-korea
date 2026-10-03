# -*- coding: utf-8 -*-
"""캡처 파일에서 토폴로지와 장비 단서를 거둔다 (ADR-039).

**사용자가 파일을 줄 때만 읽는다.** 장비에 붙지 않고 네트워크에 아무것도 보내지
않는다 — 불변 규칙 6 의 수집 우선순위에서 `수동 PCAP` 은 4순위이고, 능동 스캔은
기본 금지다. `projectfile.py` 와 같은 모양이다.

**무엇을 주는가**

  * `observed` 엣지 — "누가 누구와 실제로 통신했나" 는 관측 그 자체다. 지금까지
    토폴로지가 전부 합성이었고 엣지 상태가 하나도 `observed` 가 아니었다.
  * 제조사 단서 — MAC 앞 3바이트(OUI). **랜카드 제조사**이므로 표 18 의
    `Inferred` 수준이고, 이것만으로 자산을 만들지 않는다.
  * 장비 종류 **힌트** — 502 를 듣고 있으면 PLC 같다는 것. 관측이 아니라 추측이라
    `node_type` 이 아니라 `evidence["type_hint"]` 에 근거와 함께 넣는다.

**무엇을 주지 못하는가** (이게 더 중요하다)

  * **Purdue 레벨과 구역.** 그건 엔지니어링 지식이지 패킷에 없다. 노드는
    `purdue_level=None` · `zone=None` 으로 나오고 사람이 채워야 한다.
  * **정확한 모델과 펌웨어.** 프로토콜 식별 대화(CIP List Identity, S7 SZL)를
    해석해야 나오는데 이번 판에는 없다. 그것 없이 '확인' 을 말하면 안 된다.
  * **안 보인 경로.** 캡처는 **시간 창**이다. 10분 동안 안 보였다고 경로가 없는
    것이 아니다. 그래서 이 모듈은 **`observed` 엣지만 만든다** — `inferred` 나
    `unknown` 을 지어내지 않는다. 캡처에 없는 쌍을 어떻게 볼지는 경로 엔진이
    정할 일이다 (ADR-014).

**못 읽은 것은 숫자로 말한다.** 링크 종류가 다르거나, 헤더가 짧거나, 조각난
패킷은 전부 이름 붙은 계수기로 세어 화면에 올린다. 조용히 건너뛰면 "우리 망은
조용하구나" 로 읽힌다.
"""
from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .safeio import UnsafeInput, bounded_capture
from .topology import OBSERVED

#: 링크 종류. 1 이 아니면 프레임 구조가 달라서 이더넷으로 읽으면 안 된다.
LINKTYPE_ETHERNET = 1
LINKTYPE_NAMES = {0: "BSD loopback", 113: "Linux cooked(SLL)", 276: "Linux cooked v2",
                  105: "802.11 무선", 127: "802.11 radiotap", 101: "raw IP"}

#: 포트 → 프로토콜. **짧게 유지한다** — 모르는 포트는 `None` 으로 두고 포트만 남긴다.
#: 이름은 `exposure.CONTROL_PROTOCOLS` 와 **같은 것**을 쓴다 (ADR-040). 여기서
#: `opcua` 라 부르고 저기서 `opc_ua` 라 부르면 캡처에서 본 통신이 노출 위험에서
#: 조용히 빠진다 — 실제로 그랬다. `tests/test_protocols.py` 가 이걸 강제한다.
PORT_PROTOCOL = {
    502: "modbus_tcp", 102: "s7comm", 20000: "dnp3", 2404: "iec104",
    44818: "ethernet_ip", 2222: "ethernet_ip_io", 47808: "bacnet",
    4840: "opc_ua", 34962: "profinet", 34963: "profinet", 34964: "profinet",
    161: "snmp", 123: "ntp", 53: "dns", 67: "dhcp", 68: "dhcp",
    80: "http", 443: "https", 22: "ssh", 23: "telnet", 21: "ftp",
    445: "smb", 3389: "rdp", 5900: "vnc",
}

#: 이 포트를 **듣고 있으면** 제어 장비일 가능성이 있다. 추측이므로 힌트로만 쓴다.
CONTROL_PORTS = (502, 102, 20000, 2404, 44818, 2222, 34962, 34963, 34964, 4840)

#: OT 제조사 OUI. IEEE MA-L 등록값 중 현장에서 흔한 것만 손으로 추린 표다.
#: **전체 IEEE 목록이 아니다** — 없으면 `미상` 이고, 추측하지 않는다.
#: 이건 랜카드 제조사이므로 표 18 에서 `Inferred` 를 넘지 못한다.
OUI_VENDORS = {
    "00:1B:1B": "Siemens", "00:0E:8C": "Siemens", "00:1F:F8": "Siemens",
    "20:87:56": "Siemens", "8C:F3:19": "Siemens", "00:1C:06": "Siemens",
    "00:80:F4": "Mitsubishi Electric", "00:26:92": "Mitsubishi Electric",
    "00:00:BC": "Rockwell Automation", "00:1D:9C": "Rockwell Automation",
    "5C:88:16": "Rockwell Automation",
    "00:80:9F": "Schneider Electric", "00:00:54": "Schneider Electric",
    "00:0B:AB": "Schneider Electric",
    "00:24:59": "ABB", "AC:D3:64": "ABB",
    "00:00:0A": "Omron", "00:20:4A": "Omron",
    "00:E0:7C": "LS ELECTRIC",
    "00:A0:45": "Phoenix Contact", "A8:74:1D": "Phoenix Contact",
    "00:30:DE": "WAGO",
    "00:01:05": "Beckhoff",
    "00:90:E8": "Moxa", "00:0C:82": "Moxa",
    "00:0C:CD": "Hirschmann", "EC:E5:55": "Hirschmann",
    "00:0F:FE": "Yokogawa",
}

MAX_NODES = 20_000
MAX_EDGES = 200_000


@dataclass
class Endpoint:
    """캡처에 나온 IP 하나."""

    ip: str
    macs: Set[str] = field(default_factory=set)
    listens: Set[int] = field(default_factory=set)     # SYN 을 받은 포트
    initiates: Set[int] = field(default_factory=set)   # SYN 을 보낸 포트
    vlans: Set[int] = field(default_factory=set)
    packets: int = 0

    @property
    def mac_ambiguous(self) -> bool:
        """MAC 이 여럿이면 중간에 라우터가 있다는 뜻이다 — 제조사를 귀속할 수 없다."""
        return len(self.macs) > 1

    @property
    def vendor(self) -> Optional[str]:
        if self.mac_ambiguous or not self.macs:
            return None
        return OUI_VENDORS.get(next(iter(self.macs))[:8].upper())

    @property
    def type_hint(self) -> Optional[Tuple[str, str]]:
        """(추측한 종류, 근거). **관측이 아니다.**

        '듣고 있으면 PLC' 만 보면 틀린다 — 작업용 PC 도 도구용으로 제어 포트를
        열어 두는 일이 흔하다. OT 에서 더 강한 신호는 **팬아웃**이다: 여러 제어
        포트로 거는 쪽이 작업용 PC 이고, 받기만 하는 쪽이 제어 장비다.
        """
        srv = sorted(p for p in self.listens if p in CONTROL_PORTS)
        cli = sorted(p for p in self.initiates if p in CONTROL_PORTS)
        if cli and len(cli) >= len(srv):
            return ("workstation",
                    "제어용 포트 %s 로 접속을 걸었습니다"
                    % ", ".join(str(x) for x in cli[:3]))
        if srv:
            return ("plc", "제어용 포트 %d 로 접속을 받았습니다" % srv[0])
        return None


@dataclass
class Flow:
    """한 방향의 통신 하나. 엣지가 된다."""

    src: str
    dst: str
    proto: str                 # tcp | udp
    dport: int
    sports: Set[int] = field(default_factory=set)
    packets: int = 0
    return_packets: int = 0    # 접어 넣은 응답 패킷 수
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    vlans: Set[int] = field(default_factory=set)
    saw_syn: bool = False      # 누가 먼저 걸었는지 아는가

    @property
    def protocol(self) -> Optional[str]:
        return PORT_PROTOCOL.get(self.dport)

    @property
    def sport_protocol(self) -> Optional[str]:
        """출발지 포트가 알려진 서비스면 그것도 말한다. 방향을 단정하지는 않는다.

        SNMP 응답만 캡처에 잡히면 목적지는 임의 포트라 프로토콜이 미상으로
        보인다 — 출발지가 161 이라는 사실은 알려줘야 읽는 사람이 안다.
        """
        known = {PORT_PROTOCOL[s] for s in self.sports if s in PORT_PROTOCOL}
        return sorted(known)[0] if len(known) == 1 else None


@dataclass
class CaptureScan:
    source_path: str
    sha256: str
    mtime: Optional[str] = None
    packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    endpoints: Dict[str, Endpoint] = field(default_factory=dict)
    flows: Dict[Tuple[str, str, str, int], Flow] = field(default_factory=dict)
    #: 못 읽은 이유별 개수. **조용히 건너뛰지 않는다** — 화면에 숫자로 올린다.
    counters: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def bump(self, key: str) -> None:
        self.counters[key] = self.counters.get(key, 0) + 1

    @property
    def unparsed(self) -> int:
        return sum(self.counters.values())


def _mac(raw: bytes) -> str:
    return ":".join("%02X" % b for b in raw)


def _ip(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _iso(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    import datetime as _dt
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse(pkt, scan: CaptureScan) -> None:
    """패킷 하나를 계층별로 읽는다. **못 읽는 곳에서 멈추고 센다.**

    자르기 전에 길이를 본다. 남이 만든 바이트이고, 여기가 결함이 사는 자리다.
    """
    if pkt.link_type != LINKTYPE_ETHERNET:
        scan.bump("링크 종류가 이더넷이 아님")
        return
    b = pkt.data
    if len(b) < 14:
        scan.bump("이더넷 헤더가 짧음")
        return
    dst_mac, src_mac = _mac(b[0:6]), _mac(b[6:12])
    etype = struct.unpack(">H", b[12:14])[0]
    off, vlan = 14, None
    if etype == 0x8100:                     # 802.1Q
        if len(b) < 18:
            scan.bump("VLAN 헤더가 짧음")
            return
        vlan = struct.unpack(">H", b[14:16])[0] & 0x0FFF
        etype = struct.unpack(">H", b[16:18])[0]
        off = 18
    if etype == 0x88CC:
        scan.bump("LLDP (이번 판에서는 읽지 않음)")
        return
    if etype != 0x0800:                     # IPv4 만
        scan.bump("IPv4 가 아님")
        return

    ip = b[off:]
    if len(ip) < 20:
        scan.bump("IP 헤더가 짧음")
        return
    if (ip[0] >> 4) != 4:
        scan.bump("IP 버전이 4가 아님")
        return
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(ip):
        scan.bump("IP 헤더 길이가 잘못됨")
        return
    # 조각난 패킷의 뒷조각에는 전송 계층 헤더가 없다. 읽으면 엉뚱한 포트가 나온다.
    frag_off = struct.unpack(">H", ip[6:8])[0] & 0x1FFF
    if frag_off != 0:
        scan.bump("IP 조각 (뒷조각)")
        return
    proto_num = ip[9]
    src_ip, dst_ip = _ip(ip[12:16]), _ip(ip[16:20])
    payload = ip[ihl:]

    if proto_num == 6:                      # TCP
        if len(payload) < 20:
            scan.bump("TCP 헤더가 짧음")
            return
        sport, dport = struct.unpack(">HH", payload[0:4])
        flags = payload[13]
        syn, ack = bool(flags & 0x02), bool(flags & 0x10)
        proto = "tcp"
    elif proto_num == 17:                   # UDP
        if len(payload) < 8:
            scan.bump("UDP 헤더가 짧음")
            return
        sport, dport = struct.unpack(">HH", payload[0:4])
        syn = ack = False
        proto = "udp"
    else:
        scan.bump("TCP·UDP 가 아님")
        return

    for who, mac in ((src_ip, src_mac), (dst_ip, dst_mac)):
        ep = scan.endpoints.setdefault(who, Endpoint(ip=who))
        ep.macs.add(mac)
        if vlan is not None:
            ep.vlans.add(vlan)
    scan.endpoints[src_ip].packets += 1

    # **누가 먼저 걸었나**는 SYN 으로만 안다. '포트 번호가 작으면 서버' 같은
    # 관습은 OT 에서 자주 틀린다. SYN 이 캡처 창에 없으면 방향은 미상이다.
    if syn and not ack:
        scan.endpoints[src_ip].initiates.add(dport)
        scan.endpoints[dst_ip].listens.add(dport)

    if len(scan.endpoints) > MAX_NODES:
        raise UnsafeInput("장비 수가 상한 %d 을 넘습니다" % MAX_NODES)

    key = (src_ip, dst_ip, proto, dport)
    f = scan.flows.get(key)
    if f is None:
        if len(scan.flows) >= MAX_EDGES:
            scan.bump("통신 쌍이 상한을 넘어 버림")
            return
        f = Flow(src=src_ip, dst=dst_ip, proto=proto, dport=dport,
                 first_seen=pkt.ts, last_seen=pkt.ts)
        scan.flows[key] = f
    f.sports.add(sport)
    f.packets += 1
    f.bytes += len(b)
    f.first_seen = min(f.first_seen, pkt.ts)
    f.last_seen = max(f.last_seen, pkt.ts)
    if vlan is not None:
        f.vlans.add(vlan)
    if syn and not ack:
        f.saw_syn = True


def _fold_return_flows(scan: CaptureScan) -> None:
    """왕복을 대화 하나로. **정할 수 없으면 접지 않는다.**"""
    folded: Set[Tuple[str, str, str, int]] = set()
    for key, f in list(scan.flows.items()):
        if key in folded:
            continue
        for gkey, g in scan.flows.items():
            if gkey in folded or gkey == key:
                continue
            if not (g.src == f.dst and g.dst == f.src and g.proto == f.proto):
                continue
            if not (g.dport in f.sports and f.dport in g.sports):
                continue      # 같은 대화라는 증거가 없다
            # 어느 쪽이 서비스 방향인가
            if f.saw_syn and not g.saw_syn:
                fwd, rev, rkey = f, g, gkey
            elif g.saw_syn and not f.saw_syn:
                fwd, rev, rkey = g, f, key
            elif (f.dport in PORT_PROTOCOL) != (g.dport in PORT_PROTOCOL):
                if f.dport in PORT_PROTOCOL:
                    fwd, rev, rkey = f, g, gkey
                else:
                    fwd, rev, rkey = g, f, key
            else:
                continue      # 모른다 — 둘 다 남긴다
            fwd.return_packets += rev.packets
            fwd.bytes += rev.bytes
            fwd.first_seen = min(fwd.first_seen, rev.first_seen)
            fwd.last_seen = max(fwd.last_seen, rev.last_seen)
            fwd.vlans |= rev.vlans
            folded.add(rkey)
            break
    for k in folded:
        scan.flows.pop(k, None)


def scan_capture(path, *, mtime: Optional[str] = None,
                 max_packets: Optional[int] = None) -> CaptureScan:
    """캡처 파일 하나를 읽는다. 아무것도 쓰지 않는다."""
    path = Path(path)
    scan = CaptureScan(source_path=str(path), sha256=_sha256(path), mtime=mtime)
    kw = {} if max_packets is None else {"max_packets": max_packets}
    links: Set[int] = set()
    try:
        for pkt in bounded_capture(path, **kw):
            scan.packets += 1
            links.add(pkt.link_type)
            scan.first_seen = (pkt.ts if scan.first_seen is None
                               else min(scan.first_seen, pkt.ts))
            scan.last_seen = (pkt.ts if scan.last_seen is None
                              else max(scan.last_seen, pkt.ts))
            _parse(pkt, scan)
    except UnsafeInput as exc:
        scan.warnings.append("안전하지 않아 중단했습니다: %s" % exc.reason)
        return scan

    _fold_return_flows(scan)
    other = links - {LINKTYPE_ETHERNET}
    if other:
        scan.warnings.append(
            "이더넷이 아닌 캡처입니다 (%s). 이 형식은 아직 읽지 못합니다 — "
            "이더넷으로 다시 캡처해 주세요."
            % ", ".join(LINKTYPE_NAMES.get(l, "링크종류 %d" % l) for l in sorted(other)))
    if scan.packets and not scan.flows:
        scan.warnings.append(
            "패킷은 %d개 읽었지만 IPv4 통신을 하나도 찾지 못했습니다." % scan.packets)
    # 관측 시각은 **캡처 안의 첫 패킷 시각**이다. 파일 stat 은 복사하면 바뀐다.
    if scan.mtime is None:
        scan.mtime = _iso(scan.first_seen)
    return scan


# ------------------------------------------------------------------ 자산으로

#: 점 세 개로 끊긴 네 수 — 노드 id 가 IP 인지 보는 최소 체.
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _node_ips(node) -> List[str]:
    """이 노드가 **선언한** IP. 캡처가 만든 토폴로지는 node_id 가 곧 IP 이고,
    손으로 만든 토폴로지는 이름(`plc-fw48`)이라 `evidence.ip(s)` 로 적는다.

    둘 다 사용자가 적은 선언이다 — 추측으로 잇지 않는다는 규칙은 그대로다.
    """
    out = []
    if _IPV4.match(node.node_id or ""):
        out.append(node.node_id)
    ev = getattr(node, "evidence", None) or {}
    one = ev.get("ip")
    if isinstance(one, str) and one not in out:
        out.append(one)
    for ip in (ev.get("ips") or ()):
        if isinstance(ip, str) and ip not in out:
            out.append(ip)
    return out


def address_proposals(scan: CaptureScan, topology=None) -> Tuple[List[dict], List[str]]:
    """캡처에서 본 주소를 **이미 선언된 자산에만** 제안한다 (ADR-042).

    돌려주는 것: (제안 목록, 어느 자산인지 모르는 IP 목록)

    **추측으로 잇지 않는다.** 캡처가 아는 것은 IP 이고 자산을 아는 것은
    주문번호다. 둘을 잇는 근거는 **토폴로지 노드의 `asset_id` 선언** 하나뿐이다.
    제조사가 같다는 것은 근거가 아니다 — 같은 제조사 장비가 수십 대다.

    MAC 이 여럿인 끝점은 라우터 너머라 그 MAC 이 이 장비의 것이 아니다. IP 만
    제안하고 MAC 은 뺀다 (ADR-039 와 같은 규율).
    """
    if topology is None:
        return [], sorted(scan.endpoints)

    by_ip = {}
    for node in topology.nodes.values():
        if not node.asset_id:
            continue
        for ip in _node_ips(node):
            by_ip[ip] = node.asset_id

    out, unlinked = [], []
    for ip in sorted(scan.endpoints):
        ep = scan.endpoints[ip]
        aid = by_ip.get(ip)
        if aid is None:
            unlinked.append(ip)
            continue
        addr = {"ip": ip, "method": "capture",
                "observed_at": scan.mtime,
                "evidence_id": "pcap-%s" % scan.sha256[:12]}
        if ep.macs and not ep.mac_ambiguous:
            addr["mac"] = sorted(ep.macs)[0]
        if len(ep.vlans) == 1:
            addr["vlan"] = next(iter(ep.vlans))
        out.append({
            "asset_id": aid, "address": addr,
            "basis": "토폴로지가 이 주소를 %s 로 선언했습니다" % aid,
            "mac_ambiguous": ep.mac_ambiguous,
            "vendor_hint": ep.vendor,
        })
    return out, unlinked


def merge_address(body: dict, address: dict) -> bool:
    """자산 본문에 주소를 **더한다**. 덮어쓰지 않는다 (불변 규칙 3).

    같은 (ip, mac) 이 이미 있으면 아무것도 하지 않고 False 를 돌려준다 —
    같은 캡처를 두 번 넣어도 목록이 불어나지 않는다.
    """
    net = body.setdefault("network", {})
    addrs = net.setdefault("addresses", [])
    key = (address.get("ip"), address.get("mac"))
    for a in addrs:
        if (a.get("ip"), a.get("mac")) == key:
            return False
    addrs.append(address)
    return True


# ------------------------------------------------------------------ 토폴로지로

def to_topology(scan: CaptureScan) -> dict:
    """`load_topology` 가 읽는 JSON 모양으로 바꾼다.

    **레벨과 구역은 비운다.** 패킷에 없는 정보이고, 0 으로 채우면 모든 장비가
    물리 제어 계층이 된다. `unknown_level_nodes()` 가 이걸 찾아 사용자에게 묻는다.

    **`observed` 엣지만 만든다.** 캡처는 시간 창이라 안 보인 것이 없는 것이
    아니다. 없는 쌍을 어떻게 볼지는 경로 엔진이 정한다 (ADR-014).
    """
    nodes = []
    for ip in sorted(scan.endpoints):
        ep = scan.endpoints[ip]
        ev: Dict[str, object] = {"source": "pcap", "packets": ep.packets}
        if ep.macs:
            ev["macs"] = sorted(ep.macs)
        if ep.mac_ambiguous:
            ev["mac_ambiguous"] = True
            ev["mac_note"] = "MAC 이 여럿입니다 — 중간에 라우터가 있어 제조사를 " \
                             "이 장비의 것으로 볼 수 없습니다"
        if ep.vlans:
            ev["vlans"] = sorted(ep.vlans)
        hint = ep.type_hint
        if hint:
            ev["type_hint"], ev["type_hint_reason"] = hint
        node = {
            "node_id": ip,
            "node_type": "",              # 힌트는 evidence 에만 — 추측을 사실로 올리지 않는다
            "purdue_level": None,         # 패킷에 없다
            "zone": None,                 # 패킷에 없다
            "label": ip,
            "evidence": ev,
        }
        if ep.vendor:
            node["vendor_hint"] = ep.vendor
            ev["vendor_source"] = "MAC OUI — 랜카드 제조사이므로 모델은 알 수 없습니다"
        nodes.append(node)

    edges = []
    for f in sorted(scan.flows.values(), key=lambda x: (x.src, x.dst, x.dport)):
        edges.append({
            "src": f.src, "dst": f.dst, "edge_type": "can_reach",
            "status": OBSERVED,
            "protocol": f.protocol, "port": f.dport,
            "evidence": {
                "source": "pcap", "pcap_sha256": scan.sha256,
                "packets": f.packets, "bytes": f.bytes,
                "return_packets": f.return_packets or None,
                "sport_protocol": f.sport_protocol,
                "first_seen": _iso(f.first_seen), "last_seen": _iso(f.last_seen),
                "direction_known": f.saw_syn,
                "vlans": sorted(f.vlans) or None,
                "transport": f.proto,
            },
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "provenance": {
            "source": "pcap",
            "sha256": scan.sha256,
            "synthetic": False,          # 이 프로젝트의 첫 비합성 토폴로지다
            "window": [_iso(scan.first_seen), _iso(scan.last_seen)],
            "packets": scan.packets,
            "unparsed": scan.counters,
            "note": "관측된 통신만 담았습니다. 캡처는 시간 창이므로 "
                    "여기 없는 경로가 없다는 뜻이 아닙니다. "
                    "Purdue 레벨과 구역은 패킷에 없어 비어 있습니다 — "
                    "사용자가 채워야 합니다.",
        },
    }
