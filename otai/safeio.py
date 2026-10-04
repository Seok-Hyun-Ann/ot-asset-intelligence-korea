# -*- coding: utf-8 -*-
"""신뢰할 수 없는 입력을 다루는 **유일한** 모듈 (표 31, 표 40, R09, NFR-SEC-003).

번들과 CSV 는 외부에서 폐쇄망으로 들어가는 유일한 통로다. 여기가 뚫리면 앞선
세 슬라이스의 방어가 전부 무의미해진다.

다른 모듈에서 `zipfile.extractall` · `json.load` · `csv.reader` 를 직접 부르지 말 것.
전부 이 모듈을 거친다.

방어 대상 (표 40 '파서 적대'):
  경로순회(zip slip) · 절대경로 · 드라이브 문자 · 심볼릭 링크
  압축폭탄(압축비·총량·멤버 수) · 거대 JSON · 과중첩 JSON · CSV 수식 인젝션
  XML 외부 엔티티(XXE) · 내부 엔티티 폭탄(빌리언 러프스) · XML 과중첩
  캡처 길이 필드 위조 · pcapng 블록 길이 0/거대 · 잘린 헤더
"""
from __future__ import annotations

import json
import os
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, List, Optional, Tuple

# 기본 한계. 호출자가 낮출 수는 있어도 무제한으로 만들 수는 없다.
MAX_RATIO = 100                      # 압축비 상한 (압축폭탄)
MAX_TOTAL_BYTES = 256 * 1024 * 1024  # 압축 해제 총량
MAX_MEMBERS = 10_000
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_PACKETS = 5_000_000
MAX_SNAPLEN = 262_144                # 표준 최대 스냅 길이
MAX_XML_BYTES = 64 * 1024 * 1024
MAX_XML_DEPTH = 100                  # AutomationML 실제 깊이는 20 안쪽이다
MAX_XML_ELEMENTS = 2_000_000

# OWASP CSV 수식 인젝션: 이 문자로 시작하면 스프레드시트가 수식으로 해석한다
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class UnsafeInput(Exception):
    """거부 사유를 반드시 들고 다닌다 — 감사 로그가 이 문자열을 기록한다."""

    def __init__(self, reason: str, member: Optional[str] = None):
        self.reason = reason
        self.member = member
        super().__init__("%s%s" % (reason, (" (%s)" % member) if member else ""))


# --------------------------------------------------------------------------
# ZIP
# --------------------------------------------------------------------------
def check_member_name(name: str) -> None:
    """멤버 이름 단위 방어. zipfile 이 플랫폼별로 이름을 정규화하므로
    실제 아카이브로는 만들 수 없는 공격 이름도 여기서 직접 검증한다."""
    if not name:
        raise UnsafeInput("빈 멤버 이름")
    if "\\" in name:
        raise UnsafeInput("역슬래시 경로 — 윈도우 경로 주입 시도", name)
    if name.startswith("/"):
        raise UnsafeInput("절대 경로", name)
    if len(name) > 2 and name[1] == ":":
        raise UnsafeInput("드라이브 문자 포함 경로", name)
    parts = PurePosixPath(name).parts
    if any(p == ".." for p in parts):
        raise UnsafeInput("상위 디렉터리 참조(zip slip)", name)
    if any(p.startswith("/") for p in parts):
        raise UnsafeInput("절대 경로 조각", name)


def inspect_zip(zip_path, *, max_ratio=MAX_RATIO, max_total=MAX_TOTAL_BYTES,
                max_members=MAX_MEMBERS) -> List[zipfile.ZipInfo]:
    """**한 바이트도 풀기 전에** 중앙 디렉터리만 보고 판단한다."""
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()

        if len(infos) > max_members:
            raise UnsafeInput("멤버 수 %d > 상한 %d" % (len(infos), max_members))

        total = 0
        for info in infos:
            check_member_name(info.filename)

            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise UnsafeInput("심볼릭 링크 멤버", info.filename)
            if info.filename.endswith("/"):
                continue  # 디렉터리 엔트리

            total += info.file_size
            if total > max_total:
                raise UnsafeInput("압축 해제 총량 %d > 상한 %d" % (total, max_total),
                                  info.filename)
            if info.file_size > 0 and info.compress_size == 0:
                raise UnsafeInput("압축 크기 0 — 조작된 헤더", info.filename)
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > max_ratio:
                    raise UnsafeInput("압축비 %.0f > 상한 %d (압축폭탄)" % (ratio, max_ratio),
                                      info.filename)
        return infos


def safe_extract(zip_path, dest, **limits) -> List[str]:
    """검사를 통과한 멤버만, 대상 디렉터리 안으로만 푼다."""
    dest = Path(dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    infos = inspect_zip(zip_path, **limits)

    written: List[str] = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in infos:
            if info.filename.endswith("/"):
                continue
            target = (dest / info.filename).resolve()
            # 이름 검사를 통과해도 최종 경로를 한 번 더 확인한다
            if not str(target).startswith(str(dest) + os.sep) and target != dest:
                raise UnsafeInput("대상 디렉터리 밖으로 해석됨", info.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                remaining = info.file_size
                while remaining > 0:
                    chunk = src.read(min(1 << 20, remaining))
                    if not chunk:
                        raise UnsafeInput("선언된 크기보다 짧은 멤버", info.filename)
                    out.write(chunk)
                    remaining -= len(chunk)
            written.append(info.filename)
    return written


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------
def _depth(obj, limit: int, level: int = 0) -> None:
    if level > limit:
        raise UnsafeInput("JSON 중첩 깊이 > 상한 %d" % limit)
    if isinstance(obj, dict):
        for v in obj.values():
            _depth(v, limit, level + 1)
    elif isinstance(obj, list):
        for v in obj:
            _depth(v, limit, level + 1)


def _textual_depth(text: str, limit: int) -> None:
    """파싱 **전에** 괄호 깊이를 센다.

    `json.loads` 는 깊이 제한이 없어 과중첩 입력에서 RecursionError 로 죽는다 —
    파싱한 뒤에 깊이를 재는 것은 이미 늦다. 문자열 안의 괄호는 세지 않는다.
    """
    depth = 0
    in_str = False
    escaped = False
    for ch in text:
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                raise UnsafeInput("JSON 중첩 깊이 > 상한 %d" % limit)
        elif ch in "]}":
            depth -= 1


def bounded_json_loads(raw, *, max_bytes=MAX_JSON_BYTES, max_depth=MAX_JSON_DEPTH,
                       name: Optional[str] = None):
    """바이트/문자열을 한계 안에서 파싱한다.

    CSAF·KEV 는 원문 바이트로 sha256 을 먼저 계산하므로 경로가 아니라 바이트를
    받는다. 검사는 `bounded_json_load` 와 같다 — 크기 → 파싱 전 깊이 → 파싱 → 깊이.
    """
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > max_bytes:
            raise UnsafeInput("JSON 크기 %d > 상한 %d" % (len(raw), max_bytes), name)
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UnsafeInput("UTF-8 디코딩 실패: %s" % exc, name)
    else:
        text = str(raw)
        if len(text.encode("utf-8")) > max_bytes:
            raise UnsafeInput("JSON 크기 > 상한 %d" % max_bytes, name)

    _textual_depth(text, max_depth)          # 파싱 전 방어
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UnsafeInput("JSON 파싱 실패: %s" % exc, name)
    except RecursionError:                    # 최후 방어선
        raise UnsafeInput("JSON 중첩이 파서 한계를 초과했습니다", name)
    _depth(data, max_depth)
    return data


def check_json_bounds(raw, *, max_bytes=MAX_JSON_BYTES, max_depth=MAX_JSON_DEPTH,
                      name="<body>") -> None:
    """**파싱하지 않고** 크기와 깊이만 본다. 통과하면 아무것도 돌려주지 않는다.

    HTTP 본문처럼 **다른 곳이 파싱할 바이트**를 위한 것이다. `bounded_json_loads`
    를 쓰면 같은 본문을 두 번 파싱하게 된다 — FastAPI 가 이미 파싱하기 때문이다.
    여기서는 파싱 전 방어만 하고 파싱은 프레임워크에 맡긴다.
    """
    if len(raw) > max_bytes:
        raise UnsafeInput("JSON 크기 %d > 상한 %d" % (len(raw), max_bytes), name)
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsafeInput("UTF-8 디코딩 실패: %s" % exc, name)
    _textual_depth(text, max_depth)


def bounded_json_load(path, *, max_bytes=MAX_JSON_BYTES, max_depth=MAX_JSON_DEPTH):
    path = Path(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise UnsafeInput("JSON 크기 %d > 상한 %d" % (size, max_bytes), path.name)
    return bounded_json_loads(path.read_bytes(), max_bytes=max_bytes,
                              max_depth=max_depth, name=path.name)


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------
MAX_CSV_BYTES = 32 * 1024 * 1024
MAX_CSV_ROWS = 100_000


def bounded_csv_rows(path, *, max_bytes=MAX_CSV_BYTES, max_rows=MAX_CSV_ROWS):
    """CSV 를 한계 안에서 읽는다. 이 모듈이 `csv.reader` 를 부르는 **유일한** 곳이다.

    이 파일 머리의 규칙("`csv.reader` 를 직접 부르지 말 것")은 여기 읽기가 없으면
    지킬 수 없는 말이었다 — `csvimport` 가 자기 상한을 들고 직접 불렀다.

    디코딩 실패도 `UnsafeInput` 으로 바꾼다. `UnicodeDecodeError` 로 새면 호출자의
    `except UnsafeInput` 을 지나쳐 원시 traceback 이 사용자에게 간다 — 읽을 수 없는
    형식은 그렇다고 **말해야** 한다 (ADR-038).

    돌려주는 것은 `(헤더, [(행 번호, 행 dict)])` 이고 행 번호는 1부터 센 파일
    기준이다 (1행은 헤더이므로 데이터는 2부터).
    """
    import csv
    import io as _io

    path = Path(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise UnsafeInput("CSV 크기 %d > 상한 %d" % (size, max_bytes), path.name)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise UnsafeInput(
            "UTF-8 로 읽을 수 없습니다: %s — 엑셀에서 'CSV UTF-8' 로 다시 저장해 "
            "주세요" % exc, path.name)
    try:
        reader = csv.DictReader(_io.StringIO(text))
        headers = reader.fieldnames or []
        rows = []
        for i, row in enumerate(reader, start=2):      # 1행은 헤더
            if i - 1 > max_rows:
                raise UnsafeInput("행 수 > 상한 %d" % max_rows, path.name)
            rows.append((i, row))
    except csv.Error as exc:
        raise UnsafeInput("CSV 를 해석할 수 없습니다: %s" % exc, path.name)
    return headers, rows


# --------------------------------------------------------------------------
# 캡처 (pcap · pcapng)
# --------------------------------------------------------------------------
import struct

#: 매직 바이트. 확장자를 믿지 않는다 — `.pcap` 인데 아닐 수도, 아닌데 맞을 수도.
PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": ("<", False),   # big-endian 기록 → 우리는 뒤집어 읽는다
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\x3c\x4d": ("<", True),    # 나노초 해상도
    b"\x4d\x3c\xb2\xa1": ("<", True),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


@dataclass(frozen=True)
class Packet:
    """패킷 한 개. `data` 는 링크 계층부터의 **원문 바이트**다."""

    ts: float                 # 초 단위 (epoch)
    data: bytes
    link_type: int


def _endian(magic: bytes) -> Tuple[str, bool]:
    """(struct 접두사, 나노초 여부). 매직이 뒤집혀 있으면 바이트 순서도 뒤집힌다."""
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        return ">", magic == b"\xa1\xb2\x3c\x4d"
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        return "<", magic == b"\x4d\x3c\xb2\xa1"
    raise UnsafeInput("캡처 파일이 아닙니다 (매직 바이트 불일치)")


def capture_kind(raw: bytes) -> str:
    """`pcap` · `pcapng` · 아니면 예외."""
    if len(raw) < 4:
        raise UnsafeInput("파일이 너무 짧습니다")
    if raw[:4] == PCAPNG_MAGIC:
        return "pcapng"
    if raw[:4] in PCAP_MAGICS:
        return "pcap"
    raise UnsafeInput("캡처 파일이 아닙니다 (pcap/pcapng 매직이 아님)")


def _read_pcap(raw: bytes, max_packets: int):
    end, nano = _endian(raw[:4])
    if len(raw) < 24:
        raise UnsafeInput("캡처 헤더가 잘렸습니다")
    snaplen, link = struct.unpack(end + "II", raw[16:24])
    if snaplen > MAX_SNAPLEN:
        raise UnsafeInput("snaplen %d 이 상한 %d 을 넘습니다" % (snaplen, MAX_SNAPLEN))
    off, n = 24, 0
    while off + 16 <= len(raw):
        sec, usec, incl, orig = struct.unpack(end + "IIII", raw[off:off + 16])
        off += 16
        # **길이 필드는 공격자가 쓴 값이다.** 자르기 전에 전부 검사한다.
        if incl > orig:
            raise UnsafeInput("패킷 %d: 저장 길이 %d > 원래 길이 %d" % (n, incl, orig))
        if incl > MAX_SNAPLEN:
            raise UnsafeInput("패킷 %d: 저장 길이 %d 이 상한을 넘습니다" % (n, incl))
        if off + incl > len(raw):
            raise UnsafeInput("패킷 %d: 길이가 파일 끝을 넘습니다" % n)
        n += 1
        if n > max_packets:
            raise UnsafeInput("패킷 수가 상한 %d 을 넘습니다" % max_packets)
        yield Packet(sec + (usec / 1e9 if nano else usec / 1e6),
                     raw[off:off + incl], link)
        off += incl


def _tsresol(opts: bytes, end: str) -> float:
    """IDB 옵션에서 타임스탬프 해상도를 읽는다. 없으면 규격 기본값(마이크로초).

    값이 1바이트다 — 최상위 비트가 0 이면 10의 거듭제곱, 1 이면 2의 거듭제곱.
    """
    off = 0
    while off + 4 <= len(opts):
        code, length = struct.unpack(end + "HH", opts[off:off + 4])
        if code == 0:                          # opt_endofopt
            break
        body = opts[off + 4:off + 4 + length]
        if code == 9 and len(body) >= 1:       # if_tsresol
            v = body[0]
            return float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** (v & 0x7F))
        off += 4 + length + ((-length) % 4)    # 옵션은 4바이트 정렬
    return 1e6


def _read_pcapng(raw: bytes, max_packets: int):
    """블록 구조. **길이 0 블록이 무한 루프를 만든다** — 그래서 12 미만을 거부한다."""
    end, off, n, link, tsdiv = "<", 0, 0, 1, 1e6
    while off + 12 <= len(raw):
        btype = raw[off:off + 4]
        if btype == PCAPNG_MAGIC:              # Section Header Block
            bom = raw[off + 8:off + 12]
            end = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
        blen = struct.unpack(end + "I", raw[off + 4:off + 8])[0]
        if blen < 12:
            raise UnsafeInput("블록 길이 %d — 12 미만은 무한 루프입니다" % blen)
        if off + blen > len(raw):
            raise UnsafeInput("블록 길이가 파일 끝을 넘습니다")
        code = struct.unpack(end + "I", btype)[0]
        if code == 0x00000001:                 # Interface Description Block
            link = struct.unpack(end + "H", raw[off + 8:off + 10])[0]
            # `if_tsresol`(옵션 9) 을 안 읽고 마이크로초로 가정하면 나노초로 기록된
            # 캡처의 시각이 1000배 어긋난다. 화면에 그대로 보이는 값이다.
            tsdiv = _tsresol(raw[off + 16:off + blen - 4], end)
        elif code == 0x00000006:               # Enhanced Packet Block
            # 최소 구성: 헤더 28 + 데이터 0 + 뒤쪽 길이 4 = 32.
            # 이걸 안 보면 blen=12 인 블록이 위 검사를 통과하고 `struct.unpack` 이
            # 0바이트를 받아 `UnsafeInput` 이 아니라 `struct.error` 로 터진다.
            if blen < 32:
                raise UnsafeInput("패킷 블록 길이 %d — 최소 32 입니다" % blen)
            hi, lo, incl, orig = struct.unpack(end + "IIII", raw[off + 12:off + 28])
            if incl > orig:
                raise UnsafeInput("패킷 %d: 저장 길이 %d > 원래 길이 %d" % (n, incl, orig))
            # 블록은 데이터 뒤에 **4바이트 정렬 패딩과 뒤쪽 길이 필드**까지 담아야
            # 한다. `28 + incl` 만 보면 자리가 없는 블록을 받아들이게 된다.
            need = 28 + incl + ((-incl) % 4) + 4
            if incl > MAX_SNAPLEN or need > blen:
                raise UnsafeInput("패킷 %d: 길이가 블록을 넘습니다 (%d > %d)"
                                  % (n, need, blen))
            n += 1
            if n > max_packets:
                raise UnsafeInput("패킷 수가 상한 %d 을 넘습니다" % max_packets)
            ts = ((hi << 32) | lo) / tsdiv
            yield Packet(ts, raw[off + 28:off + 28 + incl], link)
        off += blen


def bounded_capture(source, *, max_bytes=MAX_CAPTURE_BYTES, max_packets=MAX_PACKETS):
    """캡처 파일의 패킷을 한계 안에서 하나씩 내놓는다.

    길이 필드를 **믿지 않는다.** 남이 만든 파일이고, 이 제품이 받는 입력 중
    가장 위험하다. 검사에 걸리면 그 자리에서 `UnsafeInput` 을 던진다 — 조용히
    건너뛰면 어디까지 읽었는지 아무도 모른다.
    """
    if isinstance(source, (bytes, bytearray)):
        raw = bytes(source)
    else:
        path = Path(source)
        size = path.stat().st_size
        if size > max_bytes:
            raise UnsafeInput("캡처 크기 %d > 상한 %d" % (size, max_bytes), path.name)
        raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise UnsafeInput("캡처 크기 %d > 상한 %d" % (len(raw), max_bytes))
    kind = capture_kind(raw)
    gen = _read_pcap(raw, max_packets) if kind == "pcap" else _read_pcapng(raw, max_packets)
    for pkt in gen:
        yield pkt


# --------------------------------------------------------------------------
# XML
# --------------------------------------------------------------------------
#: 프롤로그에서 DTD 를 찾는다. XML 규격상 DOCTYPE 은 루트 원소보다 **앞**에만
#: 올 수 있으므로, 루트 시작 전까지만 보면 놓치지 않는다. 뒤에 나오는 것은
#: 애초에 잘못된 XML 이라 expat 이 거부한다.
_DOCTYPE = b"<!DOCTYPE"


def reject_dtd(raw: bytes, member: Optional[str] = None) -> None:
    """DTD 가 있으면 거부한다.

    **왜 파싱 옵션이 아니라 거부인가**: `ElementTree` 는 외부 엔티티는 막지만
    내부 엔티티는 확장한다 — 실측에서 347바이트가 100만 자가 됐다. 그리고
    `xml.etree` 의 파서에는 그 확장을 끄는 공개 손잡이가 없다(3.11 에서
    `XMLParser.parser` 가 사라졌다). 문 앞에서 막는 것이 확실하다.

    설비 도구의 내보내기 형식(AutomationML·TIA·PLCopen)은 DTD 를 쓰지 않으므로
    이 거부로 잃는 입력이 없다.

    프롤로그만 훑는다 — 본문 텍스트에 `&lt;!DOCTYPE` 같은 문자열이 있다고
    멀쩡한 파일을 거부하면 안 된다. XML 규격상 DOCTYPE 은 루트 원소보다 앞에만
    올 수 있으므로 루트를 만나면 멈춘다.
    """
    i, n = 0, len(raw)
    while i < n:
        j = raw.find(b"<", i)
        if j < 0:
            return                        # 원소가 없다 — expat 이 따로 거부한다
        if raw.startswith(b"<!--", j):            # 주석
            k = raw.find(b"-->", j)
            if k < 0:
                return
            i = k + 3
        elif raw.startswith(b"<?", j):            # XML 선언·처리명령
            k = raw.find(b"?>", j)
            if k < 0:
                return
            i = k + 2
        elif raw[j:j + 9].lower() == b"<!doctype":
            raise UnsafeInput(
                "DTD 선언이 있습니다 — 외부 엔티티·엔티티 폭탄의 통로라 받지 않습니다",
                member)
        elif raw.startswith(b"<!", j):            # 프롤로그에 올 수 있는 것은 DOCTYPE 뿐
            raise UnsafeInput("프롤로그에 알 수 없는 선언이 있습니다", member)
        else:
            return                        # 루트 원소 — 여기부터는 본문이다


def bounded_xml_parse(source, *, max_bytes=MAX_XML_BYTES, max_depth=MAX_XML_DEPTH,
                      max_elements=MAX_XML_ELEMENTS, member: Optional[str] = None):
    """XML 을 한계 안에서 읽는다. `source` 는 경로 또는 bytes.

    깊이와 원소 수를 **파싱하면서** 센다. 다 읽고 재면 이미 늦다 — 메모리는
    그때 이미 먹혔다. `XMLPullParser` 로 조각을 흘려보내며 셈한다.
    """
    import xml.etree.ElementTree as ET       # 지연 임포트: 이 모듈만 XML 을 만진다

    if isinstance(source, (bytes, bytearray)):
        raw, name = bytes(source), member
    else:
        path = Path(source)
        name = member or path.name
        size = path.stat().st_size
        if size > max_bytes:
            raise UnsafeInput("XML 크기 %d > 상한 %d" % (size, max_bytes), name)
        raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise UnsafeInput("XML 크기 %d > 상한 %d" % (len(raw), max_bytes), name)

    reject_dtd(raw, name)

    parser = ET.XMLPullParser(events=("start", "end"))
    depth = elements = 0
    try:
        parser.feed(raw)
        for event, _el in parser.read_events():
            if event == "start":
                depth += 1
                elements += 1
                if depth > max_depth:
                    raise UnsafeInput("XML 중첩 깊이 > 상한 %d" % max_depth, name)
                if elements > max_elements:
                    raise UnsafeInput("XML 원소 수 > 상한 %d" % max_elements, name)
            else:
                depth -= 1
        parser.close()
    except ET.ParseError as exc:
        raise UnsafeInput("XML 파싱 실패: %s" % exc, name)
    except RecursionError:
        raise UnsafeInput("XML 중첩이 파서 한계를 초과했습니다", name)

    # 여기까지 왔으면 한계 안이다. 이제 트리를 만든다.
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise UnsafeInput("XML 파싱 실패: %s" % exc, name)


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------
def sanitize_csv_cell(value) -> str:
    """수식 인젝션 무해화 (OWASP).

    값을 **버리지 않는다** — 작은따옴표를 앞에 붙여 텍스트로 고정한다.
    원문 보존은 이 제품의 불변 규칙이므로 잘라내지 않는다.
    """
    if value is None:
        return ""
    s = str(value)
    if s and s.lstrip()[:1] in _FORMULA_PREFIXES:
        return "'" + s
    return s


def is_formula(value) -> bool:
    s = "" if value is None else str(value)
    return bool(s) and s.lstrip()[:1] in _FORMULA_PREFIXES
