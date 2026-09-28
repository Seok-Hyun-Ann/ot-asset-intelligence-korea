# -*- coding: utf-8 -*-
"""표 4 의 나머지 위험 객체 — Exposure Pattern 과 Configuration Finding.

기획서 표 4 는 위험을 넷으로 **분리하라**고 했다:

    프로토콜 설계 노출   평문·인증 부재·쓰기 도달   Exposure Pattern
    제품 구현 취약점     파서·메모리·인증·DoS       CVE
    구성 취약성          기본 계정·과도한 ACL       Configuration Finding
    수명주기 위험        지원 종료·패치 부재         Lifecycle Finding

지금까지 CVE 와 수명주기만 있었다. 그래서 **CVE 가 하나도 없는 장비는 완벽해
보였다.** 평문 Modbus 를 서버로 열어둔 PLC 도 큐에 뜨지 않았다.

`CVE` 와 다른 점이 핵심이다: **CVE 는 고칠 수 있고, 설계 노출은 대개 못 고친다.**
전통적 Modbus TCP 에는 애플리케이션 계층 인증이 없다 (SPEC 2.2). 펌웨어를 올려도
그대로다. 그래서 답이 '패치' 가 아니라 **보상 통제**다 (SPEC 2.3).

**등급은 계산이 아니라 표다.** 이 발견들에는 CVSS 도 KEV 도 버전 범위도 없어서
점수를 매길 근거가 없다. 아래 고정 표로 정하고, 그 사실을 화면에도 적는다
(ADR-008 의 '정확도 주장 안 함' 과 같은 태도). **관점(렌즈)은 이 행을 건드리지
않는다** — 가중치를 줄 대상이 없다.

**모르면 모른다고 한다.** `encrypted` 가 `None` 이면 '평문일 수도 있다' 는 행을
만들지 않는다. 그건 불변 규칙 2 가 막는 붕괴를 반대 방향으로 하는 것이다.
대신 **질문**을 돌려준다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from .logic import Tri
from .model import Asset
from .paths import CONTROL_WRITE, evaluate_reachability
from .topology import Topology

KINDS = ("exposure", "configuration")

# 제어 명령을 실어 나르는 프로토콜. 여기 있으면 '쓰기' 가 가능한 통로로 본다.
#
# **여기 없으면 조용히 빠진다.** 화면에 아무것도 안 뜨므로 '괜찮구나' 로 읽힌다 —
# 목록에서 빠지는 것이 이 모듈의 false safe 다 (ADR-040). `capture.py` 가 알아보는
# 제어 프로토콜은 반드시 여기에도 있어야 하고, 전용 테스트가 그걸 강제한다.
#
# 여기 담는 기준: **공정 제어 명령이나 로직을 실어 나르는가.** SNMP·NTP 처럼
# 관리·부가 프로토콜은 넣지 않는다 — 넣으면 없는 노출을 만든다.
CONTROL_PROTOCOLS = (
    # 산업 이더넷 (현장에서 가장 흔한 것들)
    "modbus_tcp", "modbus", "modbus_rtu",
    "s7comm", "s7comm_plus",
    "dnp3", "iec104", "iec61850_mms", "iec61850_goose",
    "ethernet_ip", "ethernet_ip_io", "cip",
    "profinet", "profinet_io", "profibus",
    "bacnet", "bacnet_ip",
    "opc_ua", "opc_da",
    "ethercat", "powerlink", "sercos",
    "hart_ip",
    # 제조사 전용
    "fins",            # Omron
    "slmp", "melsec",  # Mitsubishi
    "cclink",          # Mitsubishi CC-Link
    "fl_net",          # JEMA FL-net
    "cspv4",           # Keyence
)

#: 사람이 손으로 적는 표기 → 위 목록의 이름. CSV·프로젝트 파일·PCAP 이 모두
#: 다르게 쓴다. 표기가 다르다고 노출을 놓치면 안 된다.
PROTOCOL_ALIASES = {
    "opcua": "opc_ua", "opc": "opc_da", "opc_ua_tcp": "opc_ua",
    "enip": "ethernet_ip", "ethernetip": "ethernet_ip",
    "ethernet_ip_implicit": "ethernet_ip_io", "enip_io": "ethernet_ip_io",
    "modbustcp": "modbus_tcp", "mbtcp": "modbus_tcp", "modbus_tcp_ip": "modbus_tcp",
    "s7": "s7comm", "iso_tsap": "s7comm", "cotp": "s7comm",
    "s7commplus": "s7comm_plus",
    "iec_104": "iec104", "iec60870_5_104": "iec104", "iec_60870_5_104": "iec104",
    "mms": "iec61850_mms", "goose": "iec61850_goose",
    "dnp_3": "dnp3", "dnp3_0": "dnp3",
    "bacnetip": "bacnet_ip", "bacnet_ipv4": "bacnet_ip",
    "cc_link": "cclink", "cclink_ie": "cclink", "cc_link_ie": "cclink",
    "flnet": "fl_net",
    "hartip": "hart_ip", "omron_fins": "fins",
    "profinet_rt": "profinet", "profinet_irt": "profinet", "pnio": "profinet_io",
}


#: 화면에 쓸 이름. **엔진 이름은 위 목록 그대로 두고 표시만 바꾼다** (ADR-035).
#: `s7comm` 은 이 분야 사람이 아니면 아무 뜻이 없는데, 노출 발견의 제목은
#: '할 일' 화면 — 보안을 모르는 사람이 가장 먼저 보는 곳 — 에 그대로 나간다.
#: `frontend/src/terms.ts` 의 `PROTOCOL` 과 열쇠가 같아야 하고 테스트가 그걸 본다.
PROTOCOL_LABELS = {
    "modbus_tcp": "Modbus TCP", "modbus": "Modbus", "modbus_rtu": "Modbus RTU",
    "s7comm": "Siemens S7", "s7comm_plus": "Siemens S7 (신형)",
    "dnp3": "DNP3", "iec104": "IEC 104",
    "iec61850_mms": "IEC 61850 MMS", "iec61850_goose": "IEC 61850 GOOSE",
    "ethernet_ip": "EtherNet/IP", "ethernet_ip_io": "EtherNet/IP 실시간 I/O",
    "cip": "CIP", "profinet": "PROFINET", "profinet_io": "PROFINET IO",
    "profibus": "PROFIBUS", "bacnet": "BACnet", "bacnet_ip": "BACnet/IP",
    "opc_ua": "OPC UA", "opc_da": "OPC DA (구형)",
    "ethercat": "EtherCAT", "powerlink": "POWERLINK", "sercos": "SERCOS",
    "hart_ip": "HART-IP", "fins": "FINS",
    "slmp": "SLMP", "melsec": "MELSEC", "cclink": "CC-Link",
    "fl_net": "FL-net", "cspv4": "KV CSPv4",
}


def protocol_label(name) -> str:
    """화면에 쓸 이름. **모르는 것은 원문 그대로** 둔다 — 지어내지 않는다."""
    if not name:
        return "미상"
    return PROTOCOL_LABELS.get(normalize_protocol(name), str(name))


def normalize_protocol(name) -> str:
    """사람이 적은 표기를 한 가지 이름으로. **버리지 않고 맞춰만 본다.**

    `OPC UA` · `OPC-UA` · `opc/ua` 가 모두 `opc_ua` 가 된다. 원문
    (`Protocol.protocol`)은 그대로 두고 비교할 때만 쓴다 — 원문 보존은
    불변 규칙 5 다.
    """
    s = (name or "").strip().lower()
    for ch in (" ", "-", "/", ".", "+"):
        s = s.replace(ch, "_")
    while "__" in s:
        s = s.replace("__", "_")
    s = s.strip("_")
    return PROTOCOL_ALIASES.get(s, s)


def is_control_protocol(name) -> bool:
    """이 프로토콜이 제어 명령을 실어 나르는가."""
    return normalize_protocol(name) in CONTROL_PROTOCOLS


@dataclass(frozen=True)
class Check:
    """전제조건 하나. 삼진 논리다 — 모르면 UNKNOWN 이다."""
    name: str
    value: Tri
    evidence: str


@dataclass(frozen=True)
class Finding:
    """자산 하나에 대한 노출·구성 발견.

    CVE 발견과 달리 **권고문이 필요 없다** — 장비가 어떻게 놓여 있는지만 본다.
    """
    kind: str
    code: str
    asset_id: str
    title: str            # 무슨 일인가
    why: str              # 그래서 뭐가 위험한가
    what_to_do: str       # 지금 뭘 하면 되나
    bucket: str
    floor_if_confirmed: Optional[str]
    checks: Tuple[Check, ...]
    evidence: Tuple[str, ...]
    cwe: Optional[str] = None
    # 같은 사실이 CVE 쪽 강제규칙(H02)의 근거로도 쓰였는가 — 화면이 서로를 가리키게 한다
    also_raises_cve: bool = False

    @property
    def missing(self) -> Tuple[str, ...]:
        return tuple(c.name for c in self.checks if c.value is Tri.UNKNOWN)


@dataclass(frozen=True)
class Question:
    """발견이 아니라 물어볼 것. 모르는 것을 발견으로 만들지 않는다."""
    asset_id: str
    field: str
    ask: str
    why: str


def _safety(asset: Asset) -> Check:
    v = (asset.operations or {}).get("safety_criticality")
    if v == "high":
        return Check("사람이 다칠 수 있는 설비", Tri.TRUE,
                     "이 장비는 안전 중요도가 '높음' 으로 등록돼 있습니다")
    if v in ("none", "low"):
        return Check("사람이 다칠 수 있는 설비", Tri.FALSE,
                     "안전 중요도가 '%s' 로 등록돼 있습니다" % v)
    return Check("사람이 다칠 수 있는 설비", Tri.UNKNOWN,
                 "이 장비가 얼마나 중요한지 아직 등록되지 않았습니다")


def _reachable(asset: Asset, topo: Optional[Topology], as_of: str) -> Check:
    """바깥에서 이 장비까지 길이 열려 있는가."""
    if topo is None:
        return Check("바깥에서 닿을 수 있음", Tri.UNKNOWN, "망 구성도가 없습니다")
    node = topo.node_for_asset(asset.asset_id)
    if node is None:
        return Check("바깥에서 닿을 수 있음", Tri.UNKNOWN,
                     "이 장비가 망 구성도에 없습니다 — 닿지 않는다고 단정하지 않습니다")
    r = evaluate_reachability(topo, asset.asset_id, as_of=as_of,
                              require_capability=CONTROL_WRITE)
    if r.verdict is Tri.TRUE:
        return Check("바깥에서 닿을 수 있음", Tri.TRUE,
                     "모든 구간이 확인된 경로가 있습니다")
    if r.verdict is Tri.FALSE:
        return Check("바깥에서 닿을 수 있음", Tri.FALSE, "닿는 길을 찾지 못했습니다")
    return Check("바깥에서 닿을 수 있음", Tri.UNKNOWN,
                 "일부 구간이 추론이라 확정할 수 없습니다")


# ── 등급 표 (계산이 아니라 표다) ───────────────────────────────────────────
def _bucket_for_exposure(safety: Check, reach: Check) -> Tuple[str, Optional[str]]:
    """(등급, 확인되면 오를 등급).

    닿는지 모르면 `P?` 다 — '안 닿는다' 로 단정하지 않는다. 이게 이 제품이
    다른 곳과 다른 지점이다.
    """
    if reach.value is Tri.TRUE:
        return ("P1" if safety.value is Tri.TRUE else "P2"), None
    if reach.value is Tri.UNKNOWN:
        return "P?", ("P1" if safety.value is Tri.TRUE else "P2")
    return "P3", None      # 닿지 않는다고 확인됨 — 그래도 사라지지 않는다


def find(asset: Asset, topology: Optional[Topology] = None,
         as_of: str = "9999-12-31",
         h02_fired: bool = False) -> Tuple[List[Finding], List[Question]]:
    """자산 하나에서 노출·구성 발견과 물어볼 것을 뽑는다."""
    findings: List[Finding] = []
    questions: List[Question] = []
    net = asset.network

    if not net.declared:
        questions.append(Question(
            asset.asset_id, "network",
            "이 장비가 어떤 통신을 주고받는지 알려주세요.",
            "통신 방식을 모르면 '암호 없이 오가는지' 도, '밖에서 닿는지' 도 "
            "판단할 수 없습니다. 안전하다는 뜻이 아니라 모른다는 뜻입니다."))
        return findings, questions

    safety = _safety(asset)
    reach = _reachable(asset, topology, as_of)

    # ── 1. 평문 제어 통신 (Exposure Pattern) ──────────────────────────────
    plain = [p for p in net.protocols
             if is_control_protocol(p.protocol)
             and p.role == "server" and p.encrypted is False]
    unknown_enc = [p for p in net.protocols
                   if is_control_protocol(p.protocol)
                   and p.role == "server" and p.encrypted is None]

    if plain:
        bucket, floor = _bucket_for_exposure(safety, reach)
        names = ", ".join("%s(%s번 포트)" % (protocol_label(p.protocol), p.port)
                          if p.port else protocol_label(p.protocol) for p in plain)
        findings.append(Finding(
            kind="exposure", code="PLAINTEXT_CONTROL", asset_id=asset.asset_id,
            title="이 장비는 명령을 암호 없이 주고받습니다",
            why=("같은 망에 들어온 사람이면 누구나 오가는 명령을 읽을 수 있고, "
                 "장비에게 직접 명령을 보낼 수도 있습니다. 비밀번호를 묻지 않습니다. "
                 "이건 장비 결함이 아니라 이 통신 방식이 원래 그렇게 만들어진 것이라, "
                 "펌웨어를 올려도 없어지지 않습니다."),
            what_to_do=("장비를 바꾸는 대신 주변을 막습니다. 방화벽에서 이 포트로 "
                        "들어오는 '쓰기' 명령을 허용된 기기에서만 오게 하고, 사무망에서 "
                        "이 장비로 직접 닿지 않도록 망을 나누세요. 둘 다 장비를 멈추지 "
                        "않고 할 수 있습니다."),
            bucket=bucket, floor_if_confirmed=floor,
            checks=(Check("암호 없이 명령을 받음", Tri.TRUE,
                          "%s 를 암호 없이 열어두고 있습니다" % names),
                    safety, reach),
            evidence=tuple("%s %s번 포트 · 암호화 안 함 · 명령을 받는 쪽"
                           % (protocol_label(p.protocol), p.port) for p in plain),
            cwe="CWE-319",   # Cleartext Transmission of Sensitive Information
            also_raises_cve=h02_fired,
        ))

    # ── 2. 암호화 여부 미상 → 발견이 아니라 질문 ─────────────────────────
    for p in unknown_enc:
        questions.append(Question(
            asset.asset_id, "network.encrypted",
            "%s 통신이 암호로 보호되는지 확인해 주세요." % protocol_label(p.protocol),
            "암호가 걸려 있지 않다면 등급이 올라갑니다. 지금은 모르는 상태라 "
            "안전하다고도 위험하다고도 하지 않았습니다."))

    # ── 3. 원격 접속에 본인 확인이 하나뿐 (Configuration Finding) ────────
    ra = net.remote_access or {}
    if ra and ra.get("mfa") is False:
        bucket = "P2" if safety.value is Tri.TRUE else "P3"
        kind_of_access = ra.get("type") or "원격 접속"
        findings.append(Finding(
            kind="configuration", code="REMOTE_ACCESS_NO_MFA",
            asset_id=asset.asset_id,
            title="밖에서 들어오는 문에 잠금장치가 하나뿐입니다",
            why=("%s 로 들어올 때 비밀번호만 맞으면 통과합니다. 비밀번호가 새면 "
                 "그대로 들어옵니다. 협력사나 원격 유지보수 계정이 가장 흔한 "
                 "출발점입니다." % kind_of_access),
            what_to_do=("휴대폰 인증처럼 두 번째 확인 수단을 켜세요. 당장 어렵다면 "
                        "접속할 수 있는 시간과 출발지 주소를 좁히고, 접속 기록을 "
                        "남기도록 설정하세요."),
            bucket=bucket, floor_if_confirmed=None,
            checks=(Check("두 번째 본인 확인 없음", Tri.TRUE,
                          "원격 접속 설정에 다중 인증이 꺼져 있습니다"), safety),
            evidence=("원격 접속 방식 %s · 다중 인증 없음" % kind_of_access,),
            cwe="CWE-308",   # Use of Single-factor Authentication
        ))
    elif net.declared and not ra:
        pass   # 원격 접속이 없다고 확인된 상태 — 발견이 아니다

    return findings, questions
