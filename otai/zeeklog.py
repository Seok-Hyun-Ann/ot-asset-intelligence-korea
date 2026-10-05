# -*- coding: utf-8 -*-
"""Zeek / ICSNPP 로그를 읽는다 (ADR-051).

**왜**: 상용 OT 제품은 "자산 정보가 어디서 오나" 를 *자기 패시브 센서*로 답한다.
Dragos 는 프로토콜 1,000종 이상을 해석한다. 우리는 프로토콜 **이름** 29개를 알고
해석기가 0개이며, 입력은 사용자가 준 pcap 한 개(=10분 창)였다.

**해석기를 쓰지 않고 얻는 길**: CISA 의 [ICSNPP](https://github.com/cisagov/ICSNPP)
가 Zeek 플러그인으로 S7comm·ENIP/CIP·BACnet·OPC UA·Omron FINS·GE-SRTP·HART-IP·
EtherCAT·BSAP·ROC-Plus·C12.22·Genisys·Profinet IO CM 을 해석하고, Modbus·DNP3 는
Zeek 코어를 확장한다. 현장에 Malcolm/Zeek 이 이미 있는 경우가 많고 그쪽은
**며칠~몇 주치** 로그를 들고 있다.

**열 이름을 짐작하지 않았다.** 아래 스키마는 ICSNPP 저장소 문서에서 그대로 옮긴
것이고, 옮기지 못한 로그는 다루지 않는다.

### 얻는 것 — 그리고 얻지 못하는 것

| | 어디서 | 지금 대비 |
|---|---|---|
| 며칠~몇 주 관측 창 | `conn.log` | pcap 10분 → 7일 |
| **제조사·제품명·제품코드·리비전·시리얼** | `cip_identity.log` | MAC OUI 추측 → **관측** |
| 제조사·장치명 | `bacnet_discovery.log` | 동일 |
| 임의 속성값 (`firmware-revision` 포함 가능) | `bacnet_property.log` | **누가 그 속성을 읽었다면** |
| **로직 업로드/다운로드가 실제 일어났다** | `s7comm_upload_download.log` | 포트 열림 추론 → 관측 |
| 제어 쓰기가 실제 일어났다 | `modbus.log` · `s7comm.log` 함수 | 동일 |

**S7comm 에서 펌웨어·주문번호는 나오지 않는다.** ICSNPP 의 `s7comm_read_szl.log` 는
SZL **요청** 메타데이터(`szl_id`·`szl_index`·`return_code`)만 남기고 응답 본문을
로깅하지 않는다. 저장소 문서로 확인했다 — 기대를 먼저 접어 둔다.

**Zeek 로그도 시간 창이다.** `provenance.source = "zeek"` 이므로 ADR-048 의 보호가
그대로 적용되어, 경로를 못 찾아도 도달성은 FALSE 가 아니라 미상으로 남는다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .exposure import is_control_protocol, normalize_protocol, protocol_label
from .safeio import UnsafeInput, bounded_zeek_log
from .topology import OBSERVED

#: 다루는 로그와 **그 로그에서 쓰는 열**. 열 이름은 ICSNPP 문서에서 그대로 옮겼다.
#: 여기 없는 로그는 읽지 않는다 — 열 이름을 짐작하는 순간 없는 사실이 생긴다.
KNOWN_LOGS = {
    "conn": ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
             "service", "ts", "duration", "orig_pkts", "resp_pkts",
             "orig_bytes", "resp_bytes"),
    "modbus": ("ts", "id.orig_h", "id.resp_h", "id.resp_p", "func"),
    "dnp3": ("ts", "id.orig_h", "id.resp_h", "id.resp_p", "fc_request"),
    "s7comm": ("ts", "source_h", "destination_h", "destination_p",
               "rosctr_name", "function_name"),
    "s7comm_upload_download": ("ts", "source_h", "destination_h",
                               "function_code", "function_status", "filename",
                               "block_type", "block_number"),
    "cip_identity": ("ts", "source_h", "destination_h", "vendor_id",
                     "vendor_name", "device_type_name", "product_code",
                     "revision", "serial_number", "product_name"),
    "bacnet_discovery": ("ts", "source_h", "destination_h", "pdu_service",
                         "vendor", "object_name", "instance_number"),
    "bacnet_property": ("ts", "source_h", "destination_h", "pdu_service",
                        "property", "value"),
}

#: 로그 이름 → 프로토콜 어휘. 정본은 `exposure.CONTROL_PROTOCOLS` 다 (ADR-040).
LOG_PROTOCOL = {
    "modbus": "modbus_tcp", "dnp3": "dnp3", "s7comm": "s7comm",
    "s7comm_upload_download": "s7comm", "cip_identity": "ethernet_ip",
    "bacnet_discovery": "bacnet", "bacnet_property": "bacnet",
}

#: **쓰기**로 읽는 Modbus 기능 이름. Zeek 은 이름으로 적는다(`WRITE_SINGLE_COIL`).
#: 숫자 코드로 비교하지 않는 이유: Zeek 판에 따라 열 타입이 다르다.
MODBUS_WRITE = ("WRITE_SINGLE_COIL", "WRITE_SINGLE_REGISTER",
                "WRITE_MULTIPLE_COILS", "WRITE_MULTIPLE_REGISTERS",
                "MASK_WRITE_REGISTER", "READ_WRITE_MULTIPLE_REGISTERS")

#: S7comm 에서 **쓰기·제어 행위**로 읽는 함수 이름.
#:
#: 값은 ICSNPP 의 실제 baseline 로그에서 확인한 것이다 — 처음엔 `"Write Var"`·
#: `"PLC Stop"` 이라고 썼는데 실제 값은 **`"Write Variable"`·`"PLC Control"`** 이다.
#: 업로드·다운로드는 전용 로그에서 따로 다룬다 (방향을 구분해야 하므로).
S7_WRITE = ("Write Variable", "PLC Control")

#: 메모리에 들고 있을 제어 행위 수. 7일치 현장 로그면 Modbus 쓰기가 수백만 건이
#: 될 수 있다 — 전부 담으면 메모리가 터지고, 화면에 쏟으면 읽히지 않는다
#: (ADR-031). 표본을 들고 **나머지는 종류별로 센다.**
MAX_CONTROL_EVENTS = 5000


@dataclass
class Identity:
    """관측에서 나온 장비 식별. **MAC OUI 추측과 다른 급이다.**"""
    ip: str
    source_log: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    product_code: Optional[str] = None
    revision: Optional[str] = None
    serial: Optional[str] = None
    extra: Dict[str, str] = field(default_factory=dict)

    @property
    def level_hint(self) -> str:
        """표 18 식별 수준의 **힌트**. 확정은 `identity.py` 가 한다."""
        if self.vendor and self.product and (self.product_code or self.serial):
            return "Deterministic"
        if self.vendor and self.product:
            return "Composite"
        if self.vendor:
            return "Fuzzy"
        return "Inferred"


@dataclass
class ControlEvent:
    """관측된 제어 행위. 포트가 열렸다는 추론이 아니라 **일어난 일**이다."""
    ts: Optional[str]
    kind: str                 # control_write | logic_change
    src: str
    dst: str
    protocol: str
    detail: str


@dataclass
class Flow:
    src: str
    dst: str
    port: Optional[int]
    protocol: Optional[str]
    transport: str = "tcp"
    packets: int = 0
    bytes_: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    @property
    def key(self) -> str:
        return "%s|%s|%s" % (self.src, self.dst, self.port)


@dataclass
class ZeekScan:
    logs_read: Dict[str, int] = field(default_factory=dict)
    #: 아는 로그가 아니라서 **읽지 않은** 것 (열 이름을 짐작하지 않는다)
    skipped_logs: List[str] = field(default_factory=list)
    #: 아는 로그인데 **읽다가 거부된** 것. `(파일명, 이유)` — 멈추지 않고 보고한다
    failed_logs: List[Tuple[str, str]] = field(default_factory=list)
    endpoints: Dict[str, dict] = field(default_factory=dict)
    flows: Dict[str, Flow] = field(default_factory=dict)
    identities: Dict[str, Identity] = field(default_factory=dict)
    #: 표본. 상한을 넘으면 더 담지 않고 `control_counts` 로만 센다
    control_events: List[ControlEvent] = field(default_factory=list)
    #: 종류별 **전체** 건수. 표본보다 클 수 있다 — 그 사실을 화면이 말한다
    control_counts: Dict[str, int] = field(default_factory=dict)
    window: Tuple[Optional[str], Optional[str]] = (None, None)
    counters: Dict[str, int] = field(default_factory=dict)

    @property
    def rows(self) -> int:
        return sum(self.logs_read.values())

    @property
    def control_total(self) -> int:
        return sum(self.control_counts.values())

    @property
    def control_truncated(self) -> int:
        return max(0, self.control_total - len(self.control_events))


def _log_name(path: Path) -> str:
    """`conn.log` · `conn.log.gz` · `conn.21:00:00-22:00:00.log.gz` → `conn`."""
    name = path.name
    for suffix in (".gz", ".log"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name.split(".")[0]


def _ts(v) -> Optional[str]:
    """Zeek 의 epoch 초(문자열 또는 수)를 ISO 로. **시계를 읽지 않는다.**"""
    if v in (None, ""):
        return None
    try:
        from datetime import datetime, timezone
        return datetime.fromtimestamp(float(v), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _int(v) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _port(v) -> Optional[int]:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _s(row: dict, *names) -> Optional[str]:
    """여러 이름 중 **있는 것**을 쓴다. Zeek 판·설정에 따라 열 이름이 갈린다."""
    for n in names:
        v = row.get(n)
        if v not in (None, ""):
            return str(v)
    return None


def _conn_pair(row: dict) -> Tuple[Optional[str], Optional[str]]:
    """제어 행위의 주체·대상은 **연결 기준**이다 (ADR-051).

    ICSNPP 는 패킷마다 `source_h`·`destination_h` 를 **뒤집어** 적는다 —
    `is_orig=F` 인 응답 행에서는 `source_h` 가 PLC 다. 그걸 그대로 쓰면
    **PLC 가 쓰기를 '보냈다'** 고 기록되고, 요청·응답이 각각 세어져 건수도
    두 배가 된다. 실제 baseline 로그에서 확인했다.
    """
    return (_s(row, "id.orig_h", "id_orig_h"), _s(row, "id.resp_h", "id_resp_h"))


def _is_request(row: dict) -> bool:
    """요청 행만 센다. `is_orig` 가 없는 로그는 전부 요청으로 본다."""
    v = _s(row, "is_orig")
    return v is None or str(v).upper().startswith("T")


def scan_logs(paths) -> ZeekScan:
    """Zeek 로그 묶음을 읽는다. 디렉터리를 주면 아는 로그만 골라 읽는다."""
    files: List[Path] = []
    for p in ([paths] if isinstance(paths, (str, Path)) else list(paths)):
        p = Path(p)
        if p.is_dir():
            files.extend(sorted(q for q in p.rglob("*")
                                if q.is_file() and ".log" in q.name))
        else:
            files.append(p)
    if not files:
        raise UnsafeInput("Zeek 로그를 찾지 못했습니다", str(paths))

    scan = ZeekScan()
    first = last = None
    for f in sorted(files):
        name = _log_name(f)
        if name not in KNOWN_LOGS:
            # **열 이름을 짐작하지 않는다.** 모르는 로그는 세어서 보고한다.
            scan.skipped_logs.append(f.name)
            continue
        try:
            fields, rows = bounded_zeek_log(f)
        except UnsafeInput as exc:
            # **한 파일이 못 읽혀도 멈추지 않는다.** 현장 로그 디렉터리에는
            # 로테이트 중인 파일·잘린 파일·btest 산출물이 섞인다. 한 장 때문에
            # 수백 장을 버리지 않고, 무엇을 왜 못 읽었는지 이름을 대서 말한다.
            scan.failed_logs.append((f.name, str(exc)))
            continue
        scan.logs_read[name] = scan.logs_read.get(name, 0) + len(rows)
        for row in rows:
            ts = _ts(_s(row, "ts"))
            if ts:
                first = ts if first is None or ts < first else first
                last = ts if last is None or ts > last else last
            _ingest(scan, name, row)
    scan.window = (first, last)
    return scan


def _add_event(scan: ZeekScan, ev: ControlEvent) -> None:
    """전체 건수는 **항상** 세고, 표본은 상한까지만 담는다.

    역할 힌트가 쓰는 표시는 끝점에 **그때 바로** 남긴다. 표본만 훑으면 상한을
    넘긴 뒤에 나온 장비가 '아무 단서 없음' 으로 떨어진다 — 잘라낸 것이 판정을
    바꾸면 안 된다 (ADR-031 의 '목록을 쏟지 말되 수는 정확히' 와 같은 선).
    """
    scan.control_counts[ev.kind] = scan.control_counts.get(ev.kind, 0) + 1
    if len(scan.control_events) < MAX_CONTROL_EVENTS:
        scan.control_events.append(ev)
    dst = _touch(scan, ev.dst)
    if dst is not None:
        dst.setdefault("got", set()).add(ev.kind)
    src = _touch(scan, ev.src)
    if src is not None:
        src.setdefault("sent", set()).add(ev.kind)


def _touch(scan: ZeekScan, ip: Optional[str]) -> Optional[dict]:
    if not ip:
        return None
    return scan.endpoints.setdefault(ip, {"ip": ip, "seen_in": [],
                                          "protocols": [], "roles": []})


def _ingest(scan: ZeekScan, log: str, row: dict) -> None:
    if log == "conn":
        src = _s(row, "id.orig_h", "id_orig_h")
        dst = _s(row, "id.resp_h", "id_resp_h")
        if not src or not dst:
            scan.counters["주소 없는 conn 행"] = \
                scan.counters.get("주소 없는 conn 행", 0) + 1
            return
        port = _port(_s(row, "id.resp_p", "id_resp_p"))
        service = _s(row, "service")
        proto = normalize_protocol(service) if service else None
        f = scan.flows.get("%s|%s|%s" % (src, dst, port))
        if f is None:
            f = Flow(src=src, dst=dst, port=port, protocol=proto,
                     transport=_s(row, "proto") or "tcp")
            scan.flows[f.key] = f
        if proto and not f.protocol:
            f.protocol = proto
        f.packets += _int(_s(row, "orig_pkts")) + _int(_s(row, "resp_pkts"))
        f.bytes_ += _int(_s(row, "orig_bytes")) + _int(_s(row, "resp_bytes"))
        ts = _ts(_s(row, "ts"))
        if ts:
            f.first_seen = ts if not f.first_seen or ts < f.first_seen else f.first_seen
            f.last_seen = ts if not f.last_seen or ts > f.last_seen else f.last_seen
        for ip, role in ((src, "client"), (dst, "server")):
            e = _touch(scan, ip)
            if e is None:
                continue
            if "conn" not in e["seen_in"]:
                e["seen_in"].append("conn")
            if proto and proto not in e["protocols"]:
                e["protocols"].append(proto)
            if proto and is_control_protocol(proto) and role not in e["roles"]:
                e["roles"].append(role)
        return

    src = _s(row, "source_h", "id.orig_h", "id_orig_h")
    dst = _s(row, "destination_h", "id.resp_h", "id_resp_h")
    proto = LOG_PROTOCOL.get(log)
    for ip in (src, dst):
        e = _touch(scan, ip)
        if e is None:
            continue
        if log not in e["seen_in"]:
            e["seen_in"].append(log)
        if proto and proto not in e["protocols"]:
            e["protocols"].append(proto)

    if log == "cip_identity":
        # **관측에서 나온 식별.** ENIP List Identity **응답**이다.
        #
        # 식별이 가리키는 것은 **자기 신원을 보낸 쪽**, 즉 `source_h` 다.
        # `destination_h` 를 쓰면 물어본 엔지니어링 워크스테이션에 PLC 의
        # 제조사·모델이 붙는다 — 실측에서 그렇게 만들었다가 잡았다. 공장
        # 인벤토리를 거꾸로 적는 종류의 오류다 (ADR-051).
        ip = src or dst
        if ip:
            scan.identities[ip] = Identity(
                ip=ip, source_log=log,
                vendor=_s(row, "vendor_name"),
                product=_s(row, "product_name"),
                product_code=_s(row, "product_code"),
                revision=_s(row, "revision"),
                serial=_s(row, "serial_number"),
                extra={k: str(row[k]) for k in ("device_type_name", "vendor_id")
                       if row.get(k) not in (None, "")})
    elif log == "bacnet_discovery":
        ip = src or dst
        vendor = _s(row, "vendor")
        name = _s(row, "object_name")
        if ip and (vendor or name):
            prev = scan.identities.get(ip)
            if prev is None or prev.source_log == log:
                scan.identities[ip] = Identity(
                    ip=ip, source_log=log, vendor=vendor, product=name,
                    extra={"instance_number": _s(row, "instance_number") or ""})
    elif log == "bacnet_property":
        # 누가 `firmware-revision` 을 읽었다면 여기 값으로 있다 — **조건부다.**
        prop = (_s(row, "property") or "").lower()
        ip = src or dst
        value = _s(row, "value")
        if ip and value and prop in ("firmware-revision", "application-software-version",
                                     "model-name", "vendor-name"):
            ident = scan.identities.get(ip) or Identity(ip=ip, source_log=log)
            ident.extra[prop] = value
            if prop == "model-name" and not ident.product:
                ident.product = value
            if prop == "vendor-name" and not ident.vendor:
                ident.vendor = value
            if prop == "firmware-revision":
                ident.revision = value
            scan.identities[ip] = ident
    elif log in ("modbus", "s7comm", "s7comm_upload_download", "dnp3"):
        # 제어 행위는 **연결 기준 + 요청 행만** 센다 (위 `_conn_pair` 주석 참조).
        if not _is_request(row):
            return
        a, b = _conn_pair(row)
        a, b = a or src, b or dst
        if not a or not b:
            return
        ts = _ts(_s(row, "ts"))

        if log == "modbus":
            func = (_s(row, "func") or "").upper()
            if func in MODBUS_WRITE:
                _add_event(scan, ControlEvent(
                    ts=ts, kind="control_write", src=a, dst=b,
                    protocol="modbus_tcp",
                    detail="Modbus %s 가 관측됐습니다" % func))
        elif log == "s7comm":
            func = _s(row, "function_name") or ""
            if any(w.lower() in func.lower() for w in S7_WRITE):
                _add_event(scan, ControlEvent(
                    ts=ts, kind="control_write", src=a, dst=b,
                    protocol="s7comm", detail="S7comm %s 가 관측됐습니다" % func))
        elif log == "s7comm_upload_download":
            # **업로드는 로직 변경이 아니다.** 실제 baseline 로그의 값은 전부
            # "Start Upload"·"Upload"·"End Upload" 였는데, 처음엔 이 로그의 모든
            # 행을 "로직 변경이 실제로 일어났습니다" 로 적었다 — 프로그램을 읽어
            # 간 것을 바꿨다고 말하는 것이고, OT 에서는 사고 대응을 잘못 띄운다.
            func = _s(row, "function_name", "function_code") or ""
            low = func.lower()
            named = " ".join(filter(None, [_s(row, "block_type"),
                                           _s(row, "block_number")]))
            block = ("블록 %s" % named) if named else "블록"
            if "download" in low:
                kind, what = "logic_change", (
                    "%s이 PLC 로 내려갔습니다 — **로직 변경이 실제로 "
                    "일어났습니다**" % block)
            elif "upload" in low:
                kind, what = "logic_read", (
                    "%s을 읽어 갔습니다 — 변경은 아니지만 프로그램이 밖으로 "
                    "나간 것입니다" % block)
            else:
                kind, what = "logic_transfer", (
                    "%s 전송이 관측됐습니다 (방향 미상 — function_name=%r)"
                    % (block, func))
            _add_event(scan, ControlEvent(
                ts=ts, kind=kind, src=a, dst=b, protocol="s7comm",
                detail="%s (%s)" % (what, func) if func else what))
        elif log == "dnp3":
            fc = (_s(row, "fc_request") or "").upper()
            if "WRITE" in fc or "OPERATE" in fc or "DIRECT" in fc:
                _add_event(scan, ControlEvent(
                    ts=ts, kind="control_write", src=a, dst=b,
                    protocol="dnp3", detail="DNP3 %s 가 관측됐습니다" % fc))


def to_topology(scan: ZeekScan) -> dict:
    """관측된 흐름만 담는다. `capture.to_topology` 와 **같은 모양**이다.

    `provenance.source = "zeek"` 이므로 ADR-048 의 보호가 그대로 걸린다 — 경로를
    못 찾아도 도달성은 FALSE 가 아니라 미상으로 남는다. **로그도 시간 창이다.**
    """
    nodes, edges = [], []
    for ip, e in sorted(scan.endpoints.items()):
        ident = scan.identities.get(ip)
        hint, reason = _role_hint(e, scan)
        nodes.append({
            "node_id": ip, "label": (ident.product if ident and ident.product
                                     else ip),
            "node_type": "",
            # 패킷에도 로그에도 없다. 0 으로 채우지 않는다 (ADR-039).
            "purdue_level": None, "zone": None,
            "evidence": {
                "source": "zeek", "seen_in": sorted(e["seen_in"]),
                "protocols": sorted(e["protocols"]),
                "type_hint": hint, "type_hint_reason": reason,
                **({"identity_vendor": ident.vendor,
                    "identity_product": ident.product,
                    "identity_revision": ident.revision,
                    "identity_serial": ident.serial,
                    "identity_level_hint": ident.level_hint,
                    "identity_source_log": ident.source_log}
                   if ident else {}),
            },
        })
    for f in sorted(scan.flows.values(), key=lambda x: x.key):
        edges.append({
            "src": f.src, "dst": f.dst, "edge_type": "can_reach",
            "status": OBSERVED, "protocol": f.protocol, "port": f.port,
            "evidence": {"source": "zeek", "packets": f.packets,
                         "bytes": f.bytes_, "transport": f.transport,
                         "first_seen": f.first_seen, "last_seen": f.last_seen,
                         "confidence": 0.9},
        })
    return {
        "nodes": nodes, "edges": edges,
        "provenance": {
            "source": "zeek", "synthetic": False,
            "logs": dict(sorted(scan.logs_read.items())),
            "rows": scan.rows, "window": list(scan.window),
            "skipped_logs": sorted(scan.skipped_logs),
            "failed_logs": [{"file": n, "reason": r}
                            for n, r in sorted(scan.failed_logs)],
            "control_events": scan.control_total,
            "control_counts": dict(sorted(scan.control_counts.items())),
            "control_events_sampled": len(scan.control_events),
            "identities": len(scan.identities),
            "note": "Zeek/ICSNPP 로그에서 **관측된 통신만** 담았습니다. 로그도 "
                    "시간 창이므로 여기 없는 경로가 없다는 뜻이 아닙니다 — "
                    "도달성은 FALSE 가 아니라 미상으로 남습니다 (ADR-048/051). "
                    "Purdue 레벨·구역은 로그에 없어 비어 있습니다.",
        },
    }


def _role_hint(e: dict, scan: ZeekScan) -> Tuple[Optional[str], Optional[str]]:
    """역할 **힌트**. 확정이 아니다 (ADR-039 와 같은 선).

    제어 프로토콜 서버로 **접속을 받았으면** 제어 장비일 수 있고, 로직 변경을
    받았으면 그 근거가 훨씬 세다 — 포트가 열렸다는 추론이 아니라 일어난 일이다.
    """
    LOGIC = {"logic_change", "logic_read", "logic_transfer"}
    got = e.get("got") or set()
    sent = e.get("sent") or set()
    if "logic_change" in got:
        return "plc", "로직 블록을 **받았습니다** (관측 — 프로그램이 내려갔다)"
    if got & LOGIC:
        return "plc", "로직 블록 전송에 관여했습니다 (관측 — 프로그램을 들고 있다)"
    if "control_write" in got:
        return "plc", "제어 쓰기를 **받았습니다** (관측)"
    if sent & (LOGIC | {"control_write"}):
        return "workstation", "제어 쓰기·로직 전송을 **보냈습니다** (관측)"
    if "server" in e["roles"]:
        names = [protocol_label(p) for p in e["protocols"]
                 if is_control_protocol(p)]
        return "plc", "제어용 통신(%s) 으로 접속을 받았습니다" % ", ".join(names[:3])
    if "client" in e["roles"]:
        return "workstation", "제어용 통신으로 접속을 걸었습니다"
    return None, None


def identity_proposals(scan: ZeekScan, topology=None) -> Tuple[List[dict], List[str]]:
    """관측 식별을 **이미 선언된 자산에만** 제안한다 (ADR-042 와 같은 규칙).

    자산을 새로 만들지 않는다. 토폴로지가 그 IP 를 어느 자산으로 선언했을 때만
    붙일 후보로 올린다.
    """
    if topology is None:
        return [], sorted(scan.identities)
    by_ip: Dict[str, str] = {}
    for node in topology.nodes.values():
        if not node.asset_id:
            continue
        ev = node.evidence or {}
        cands = [node.node_id] + list(ev.get("ips") or ()) + \
                ([ev["ip"]] if ev.get("ip") else [])
        for ip in cands:
            if ip:
                by_ip[str(ip)] = node.asset_id
    out, unlinked = [], []
    for ip, ident in sorted(scan.identities.items()):
        aid = by_ip.get(ip)
        if aid is None:
            unlinked.append(ip)
            continue
        out.append({"asset_id": aid, "ip": ip, "vendor": ident.vendor,
                    "product": ident.product, "revision": ident.revision,
                    "serial": ident.serial, "level_hint": ident.level_hint,
                    "source_log": ident.source_log, "method": "zeek_observed"})
    return out, unlinked
