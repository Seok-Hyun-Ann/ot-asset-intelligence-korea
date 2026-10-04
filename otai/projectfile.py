# -*- coding: utf-8 -*-
"""엔지니어링 프로젝트 파일에서 자산 정보를 거둔다 (ADR-038).

**사용자가 파일을 줄 때만 읽는다.** 장비에 붙지 않는다 — 불변 규칙 6 의 수집
우선순위에서 '프로젝트 백업' 은 3순위이고, 능동 스캔은 기본 금지다.

**스키마를 추측하지 않는다.** TIA Portal 의 `.ap18` 이나 GX Works3 의 `.gx3` 내부
구조를 우리가 알 방법이 없다. 대신 방향을 뒤집는다 —

    프로젝트 파일에서 문자열을 거두고,
    **실제 권고문에서 뽑아 이미 들고 있는 식별자 목록**과 맞춘다.

권고문 1,306건에서 주문번호 1,028개(변별력 있는 것)와 제품명 4,581개가 나온다.
이건 우리가 검증할 수 있는 근거이고, 저쪽 도구의 스키마와 무관하다. XML 이든
AutomationML 이든 zip 안의 무엇이든 같은 방식으로 읽힌다.

**버전은 거두되 확정하지 않는다.** 프로젝트가 담은 펌웨어는 '이 프로젝트가 대상으로
설정한 값' 이지 장비에서 읽은 값이 아니다. `method="project_file"` 로 표시되고
`applicability.CLAIMED_METHODS` 가 그것으로 '안전' 에 도달하는 것을 막는다.

**아무것도 자동으로 쓰지 않는다.** CSV Import 와 같은 모양이다 — dry-run 이 기본이고,
사람이 보고 고른 것만 적용된다 (추측 금지).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .safeio import (MAX_MEMBERS, UnsafeInput, bounded_xml_parse, inspect_zip,
                     safe_extract)

#: 이 확장자는 zip 으로 열어본다. 나머지는 XML 한 장으로 본다.
ARCHIVE_SUFFIXES = (".zip", ".zap13", ".zap14", ".zap15", ".zap16", ".zap17",
                    ".zap18", ".zap19", ".gxw", ".gx3")
XML_SUFFIXES = (".xml", ".aml", ".amlx", ".caex")

#: 한 아카이브에서 읽을 XML 멤버 수 상한. 프로젝트는 수천 개의 작은 파일이다.
MAX_XML_MEMBERS = 2000
MAX_MEMBER_BYTES = 16 * 1024 * 1024

#: 속성 이름에 이게 들어 있으면 버전 후보로 본다. **추측이므로 확정하지 않는다** —
#: 화면에 후보로 보여주고 사람이 고른다.
_VERSION_HINT = re.compile(r"(firmware|fwversion|version|revision)", re.I)
#: 문서 자체의 판번호는 장비 펌웨어가 아니다. 실측에서 `SchemaVersion="2.15"` 가
#: 펌웨어로 잡혔다 — 이런 값이 자산에 들어가면 없는 버전을 지어내는 셈이 된다.
_NOT_DEVICE_VERSION = re.compile(
    r"(schema|xmlns|namespace|file|tool|export|document|format|library|"
    r"editor|writer|caex|standard)", re.I)
#: 값이 버전처럼 생겼는가. 날짜·GUID 를 버전으로 오인하지 않기 위한 최소 체.
_VERSION_SHAPE = re.compile(r"^v?\d+(\.\d+){0,3}[A-Za-z]?$", re.I)


def _specific(s: str) -> bool:
    """오탐을 만들 만큼 밋밋한 식별자를 버린다.

    코퍼스에는 `110930` 같은 순수 숫자 주문번호가 있다. 그런 값은 XML 어디에나
    나타나므로 맞춰봐야 의미가 없다 — 글자와 숫자가 **둘 다** 있고 7자 이상인
    것만 쓴다. 실측: 1,181개 중 1,028개가 남는다.
    """
    return len(s) >= 7 and any(c.isdigit() for c in s) and any(c.isalpha() for c in s)


def _norm(s: str) -> str:
    return " ".join(s.split()).upper()


def _norm_order(s: str) -> str:
    """주문번호는 **공백을 다 지우고** 맞춘다.

    Siemens 카탈로그 표기는 `6ES7 518-4AP00-0AB0` 처럼 띄어 쓰고, 우리 코퍼스에는
    `6ES7518-4AX00-1AB0` 처럼 붙여 쓴 것이 들어 있다. 공백을 남기면 실제 내보내기
    파일에서 Siemens 장비를 하나도 못 알아볼 수 있다. 7자 이상이고 글자·숫자가
    섞인 값만 사전에 들어가므로 공백을 지워도 오탐이 늘지 않는다.
    """
    return "".join(s.split()).upper()


@dataclass(frozen=True)
class Vocabulary:
    """권고문에서 뽑은 식별자 목록. 이게 프로젝트 파일을 읽는 사전이다."""

    #: 정규화값 → (원문, 제조사, 제품명)
    order_numbers: Dict[str, Tuple[str, str, str]]
    product_names: Dict[str, Tuple[str, str, str]]
    vendors: Dict[str, str]

    @property
    def size(self) -> Tuple[int, int, int]:
        return len(self.order_numbers), len(self.product_names), len(self.vendors)


def nm_of(product) -> str:
    return (product.product_name or "").strip()


def build_vocabulary(advisories: Sequence) -> Vocabulary:
    """권고문 목록에서 사전을 만든다. 외부 데이터가 필요 없다."""
    orders: Dict[str, Tuple[str, str]] = {}
    names: Dict[str, Tuple[str, str]] = {}
    vendors: Dict[str, str] = {}
    for adv in advisories:
        for pr in adv.products:
            vendor = (pr.vendor or "").strip()
            if vendor and len(vendor) >= 3:
                vendors.setdefault(_norm(vendor), vendor)
            for m in (getattr(pr, "model_numbers", None) or ()):
                m = (m or "").strip()
                if _specific(m):
                    # 모델명을 함께 든다 — 화면의 '모델' 칸에 주문번호를 다시
                    # 박으면 사용자가 이미 지적한 그 문제가 돌아온다.
                    orders.setdefault(_norm_order(m), (m, vendor, nm_of(pr)))
            nm = nm_of(pr)
            if len(nm) >= 8:
                names.setdefault(_norm(nm), (nm, vendor, nm))
    return Vocabulary(orders, names, vendors)


@dataclass(frozen=True)
class Hit:
    """프로젝트 파일에서 찾은 것 하나. **어디서 나왔는지를 반드시 들고 다닌다.**"""

    kind: str                 # order_number | product_name | vendor | version
    value: str                # 파일에 있던 원문
    known_as: Optional[str]   # 권고문 쪽 표기 (version 은 None)
    vendor: Optional[str]
    member: str               # 아카이브 안의 파일명 ("" = 단일 XML)
    path: str                 # 원소 경로 (사람이 읽는 것)
    attribute: Optional[str]  # 속성 이름 (본문 텍스트면 None)
    #: 형제를 구분한 경로. `/a[0]/b[2]/c[0]` — 묶을 때만 쓴다. 색인이 없으면
    #: 같은 장비의 주문번호와 옆 장비의 펌웨어가 한 덩어리로 보인다.
    ipath: str = ""
    model: Optional[str] = None    # 권고문 쪽 제품명 — 화면의 '모델' 칸이 된다
    #: 엔지니어가 붙인 장비 이름 (`Name="PLC_1"`). 같은 모델이 여러 대일 때
    #: 이것으로 구분한다 — 없으면 주문번호만으로 id 를 만들어 전부 합쳐진다.
    name: Optional[str] = None

    @property
    def source_id(self) -> str:
        """계보용 출처 식별자. 파일 해시는 `Scan` 이 들고 있다."""
        loc = "%s#%s" % (self.member, self.path) if self.member else self.path
        return "%s@%s" % (loc, self.attribute) if self.attribute else loc


@dataclass
class Scan:
    source_path: str
    sha256: str
    file_mtime: Optional[str]
    members_read: int = 0
    elements: int = 0
    hits: List[Hit] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    refused: List[str] = field(default_factory=list)

    def by_kind(self, kind: str) -> List[Hit]:
        return [h for h in self.hits if h.kind == kind]

    def summary(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for h in self.hits:
            out[h.kind] = out.get(h.kind, 0) + 1
        return out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _mtime_iso(path: Path) -> Optional[str]:
    """파일의 수정 시각. **시계를 읽는 것이 아니다** — 파일이 들고 있는 값이다.

    `otai/` 안에서 wall-clock 을 읽는 것은 금지지만(재현성 게이트), 입력 파일의
    타임스탬프를 읽는 것은 관측이다. 이 값이 `observed_at` 이 된다.
    """
    try:
        import datetime as _dt
        ts = path.stat().st_mtime
        return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        return None


def _walk(root, vocab: Vocabulary, member: str, scan: Scan) -> None:
    """XML 한 그루를 훑으며 사전에 있는 값을 찾는다."""
    seen: Set[Tuple[str, str, str]] = set()

    def visit(el, path: str, ipath: str, label: Optional[str] = None,
              names: Tuple[str, ...] = ()) -> None:
        scan.elements += 1
        tag = el.tag.rsplit("}", 1)[-1]
        here = "%s/%s" % (path, tag)
        attrs = {k.rsplit("}", 1)[-1]: v for k, v in el.attrib.items()}
        # AutomationML 의 관용형: `<Attribute Name="FirmwareVersion"><Value>V2.9</Value>`
        # 값은 자식 원소의 **본문**에 있고 이름은 부모의 속성에 있다. 이름을
        # 아래로 물려주지 않으면 이 형태를 통째로 놓친다 — 실측에서 놓쳤다.
        own = attrs.get("Name") or attrs.get("name") or attrs.get("ID")
        # 조상들의 Name 을 전부 든다. 장비 이름은 이 중 **속성 이름표가 아닌**
        # 가장 가까운 것이다 — `<InternalElement Name="PLC_1"><Attribute
        # Name="OrderNumber">` 에서 PLC_1 이지 OrderNumber 가 아니다.
        chain = names + ((own,) if own else ())
        pairs: List[Tuple[Optional[str], str]] = list(attrs.items())
        if el.text and el.text.strip():
            pairs.append((own or label, el.text.strip()))
        for attr, raw in pairs:
            val = raw.strip()
            if not val or len(val) > 200:
                continue
            key, okey = _norm(val), _norm_order(val)
            kind = known = vendor = model = None
            if okey in vocab.order_numbers:
                kind, (known, vendor, model) = ("order_number",
                                                vocab.order_numbers[okey])
            elif key in vocab.product_names:
                kind, (known, vendor, model) = ("product_name",
                                                vocab.product_names[key])
            elif key in vocab.vendors:
                kind, known, vendor = "vendor", vocab.vendors[key], vocab.vendors[key]
            elif (attr and _VERSION_HINT.search(attr)
                  and not _NOT_DEVICE_VERSION.search(attr)
                  and _VERSION_SHAPE.match(val)):
                # 속성 이름으로 추측한 것이다. 확정하지 않고 후보로만 싣는다.
                kind = "version"
            if kind is None:
                continue
            dedup = (kind, key, ipath)
            if dedup in seen:
                continue
            seen.add(dedup)
            device_name = next((n for n in reversed(chain)
                                if n != attr and n != val), None)
            scan.hits.append(Hit(kind, val, known, vendor, member, here, attr, ipath,
                                 model or None, device_name))
        for i, child in enumerate(el):
            visit(child, here, "%s/%d" % (ipath, i), own or label, chain)

    visit(root, "", "0")


def _read_xml(path: Path, vocab: Vocabulary, member: str, scan: Scan) -> None:
    try:
        size = path.stat().st_size
        if size > MAX_MEMBER_BYTES:
            scan.refused.append("%s — 크기 %d 바이트" % (member or path.name, size))
            return
        root = bounded_xml_parse(path, member=member or path.name)
    except UnsafeInput as exc:
        # 거부는 조용히 넘어가지 않는다. 화면이 몇 개를 왜 안 읽었는지 말해야 한다.
        scan.refused.append("%s — %s" % (member or path.name, exc.reason))
        return
    scan.members_read += 1
    _walk(root, vocab, member, scan)


def scan_file(path, vocab: Vocabulary, *, workdir=None,
              mtime: Optional[str] = None) -> Scan:
    """프로젝트 파일 하나를 읽는다. 아카이브면 열어서 XML 멤버를 훑는다.

    아무것도 쓰지 않는다 — 읽고 무엇을 찾았는지 돌려줄 뿐이다.
    """
    path = Path(path)
    # **관측 시각은 파일이 들고 있는 값이다.** 호출자가 진짜 값을 알면(브라우저가
    # 보낸 `File.lastModified`) 그것이 이긴다 — 임시 파일에 써 놓고 그 mtime 을
    # 읽으면 '업로드한 순간' 이 관측 시각이 되어 없는 사실을 기록하게 된다.
    scan = Scan(source_path=str(path), sha256=_sha256(path),
                file_mtime=mtime or _mtime_iso(path))
    suffix = path.suffix.lower()

    if suffix in XML_SUFFIXES:
        _read_xml(path, vocab, "", scan)
        _drop_orphan_versions(scan)
        return scan

    # **확장자를 믿지 않고 매직 바이트를 본다.** `.gx3` 처럼 압축일 수도 아닐 수도
    # 있는 확장자가 있고, 도구마다 이름도 다르다. 아니면 그렇게 말해준다.
    try:
        with path.open("rb") as f:
            magic = f.read(2)
    except OSError as exc:
        scan.warnings.append("파일을 열지 못했습니다: %s" % exc)
        return scan
    if magic != b"PK":
        scan.warnings.append(
            "XML 도 아니고 압축 파일도 아닙니다 — 이 도구의 독자 형식은 읽지 "
            "못합니다. 엔지니어링 도구에서 AutomationML(.aml) 또는 XML 로 "
            "내보낸 파일을 주세요.")
        return scan

    import zipfile as _zip
    try:
        info = inspect_zip(path, max_members=MAX_MEMBERS)
    except UnsafeInput as exc:
        scan.warnings.append("압축 파일을 거부했습니다: %s" % exc.reason)
        return scan
    except _zip.BadZipFile as exc:
        scan.warnings.append("압축 파일이 깨져 있습니다: %s" % exc)
        return scan

    import tempfile
    with tempfile.TemporaryDirectory(dir=workdir) as tmp:
        try:
            names = safe_extract(path, tmp)
        except UnsafeInput as exc:
            scan.warnings.append("압축 해제를 거부했습니다: %s" % exc.reason)
            return scan
        except _zip.BadZipFile as exc:
            scan.warnings.append("압축 파일이 깨져 있습니다: %s" % exc)
            return scan
        xml_members = [n for n in names if Path(n).suffix.lower() in XML_SUFFIXES]
        if not xml_members:
            scan.warnings.append(
                "압축 안에 XML 이 없습니다. 이 도구의 독자 형식은 읽지 못합니다 — "
                "도구에서 AutomationML(.aml) 또는 XML 로 내보낸 뒤 주세요.")
        if len(xml_members) > MAX_XML_MEMBERS:
            scan.warnings.append(
                "XML 이 %d개라 앞에서 %d개만 읽었습니다."
                % (len(xml_members), MAX_XML_MEMBERS))
            xml_members = xml_members[:MAX_XML_MEMBERS]
        for name in xml_members:
            _read_xml(Path(tmp) / name, vocab, name, scan)
    # 압축 멤버의 시각은 **도구가 저장한 때**다. 압축 파일 자체의 mtime 보다
    # 정확하다 — 복사·업로드로 바뀌지 않기 때문이다.
    if mtime is None:
        stamps = [i.date_time for i in info
                  if Path(i.filename).suffix.lower() in XML_SUFFIXES]
        if stamps:
            y, mo, d, h, mi, s = max(stamps)
            scan.file_mtime = "%04d-%02d-%02dT%02d:%02d:%02dZ" % (y, mo, d, h, mi, s)
    _drop_orphan_versions(scan)
    return scan


def _shared(a: str, b: str) -> int:
    """두 색인 경로가 몇 마디까지 같은가. 길수록 가깝다."""
    x, y = a.split("/"), b.split("/")
    n = 0
    for i, j in zip(x, y):
        if i != j:
            break
        n += 1
    return n


@dataclass
class Device:
    """프로젝트 파일에서 알아본 장비 하나."""

    order_number: str
    known_as: Optional[str]
    vendor: Optional[str]
    member: str
    path: str
    versions: List[Hit] = field(default_factory=list)
    model: Optional[str] = None
    name: Optional[str] = None           # 엔지니어가 붙인 이름 (PLC_1)
    ipath: str = ""                      # 파일 안의 위치 — 이름이 없을 때의 구분자
    same_model_count: int = 1            # 이 파일에 같은 주문번호가 몇 대인가
    id_suffix: str = ""                  # 그래도 겹칠 때 붙인 꼬리 ("-2")

    @property
    def version(self) -> Optional[str]:
        """가장 가까운 버전 하나. 여럿이면 **고르지 않는다** (추측 금지)."""
        return self.versions[0].value if len(self.versions) == 1 else None

    @property
    def ambiguous(self) -> bool:
        return len(self.versions) > 1

    def suggested_asset_id(self) -> str:
        """자산 id. **주문번호만으로 만들지 않는다** — 같은 모델 5대가 1대가 된다.

        주문번호 + 장비 이름. 이름이 없으면 파일 안의 위치(`member#ipath`)의 짧은
        해시다 — 같은 파일을 다시 넣으면 같은 id 가 나오고, 순번처럼 앞 장비를
        지웠다고 밀리지 않는다. 그래도 겹치면 `devices()` 가 꼬리를 붙인다.
        """
        base = _slug(self.order_number) or "device"
        if self.name:
            tail = _slug(self.name)
        else:
            tail = hashlib.sha256(("%s#%s" % (self.member, self.ipath))
                                  .encode("utf-8")).hexdigest()[:8]
        return "%s-%s%s" % (base, tail, self.id_suffix)


def _slug(s: Optional[str]) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")


def devices(scan: Scan) -> List[Device]:
    """주문번호마다 장비를 만들고, 버전을 **가장 가까운** 장비에 붙인다.

    스키마를 모르므로 이름이 아니라 거리로 정한다. 같은 거리에 둘이면 어느
    쪽인지 모르는 것이므로 양쪽에 다 붙이고 `ambiguous` 로 표시한다 — 하나를
    임의로 고르면 없는 사실을 만드는 것이다.
    """
    out = [Device(h.value, h.known_as, h.vendor, h.member, h.path, model=h.model,
                  name=h.name, ipath=h.ipath)
           for h in scan.by_kind("order_number")]
    anchors = scan.by_kind("order_number")
    for v in scan.by_kind("version"):
        same = [(i, _shared(v.ipath, a.ipath)) for i, a in enumerate(anchors)
                if a.member == v.member]
        if not same:
            continue
        best = max(s for _i, s in same)
        for i, s in same:
            if s == best:
                out[i].versions.append(v)

    # 같은 모델이 몇 대인지 — 사용자가 '이름으로 구분됐다' 는 걸 알아야 한다
    per_model: Dict[str, int] = {}
    for d in out:
        per_model[d.order_number] = per_model.get(d.order_number, 0) + 1
    for d in out:
        d.same_model_count = per_model[d.order_number]

    # 그래도 id 가 겹치면(같은 모델·같은 이름) 꼬리를 붙인다. **조용히 덮어쓰지
    # 않는다** — 그게 이 결함의 원형이었다.
    taken: Dict[str, int] = {}
    for d in out:
        base = d.suggested_asset_id()
        n = taken.get(base, 0)
        if n:
            d.id_suffix = "-%d" % (n + 1)
        taken[base] = n + 1
    return out


def _drop_orphan_versions(scan: Scan) -> None:
    """장비를 못 알아본 파일의 버전 후보는 버린다.

    어느 장비의 버전인지 모르는 숫자는 자산에 넣을 수 없다. 남겨두면 화면에서
    '뭔가 찾았다' 처럼 보이는데 정작 붙일 곳이 없다.
    """
    if any(h.kind in ("order_number", "product_name") for h in scan.hits):
        return
    dropped = sum(1 for h in scan.hits if h.kind == "version")
    if dropped:
        scan.hits[:] = [h for h in scan.hits if h.kind != "version"]
        scan.warnings.append(
            "버전처럼 보이는 값 %d개를 찾았지만 어느 장비의 것인지 알 수 없어 "
            "버렸습니다. 아는 제품이 이 파일에 없습니다." % dropped)


def to_asset(device: Device, scan: Scan) -> dict:
    """알아본 장비 하나를 자산 기록으로. **모르는 것은 비워 둔다.**

    CLI 와 API 가 **같은 이 함수**를 부른다. `method="project_file"` 표시가
    설정값 가드를 켜는 스위치인데(ADR-038), 그게 두 곳에 있으면 한쪽만 고쳐져
    조용히 어긋난다.

    구역·안전등급·원격접속은 프로젝트 파일에 없다. 지어내지 않는다 — 화면이
    `미상` 으로 보여주고 다음 질문이 그것을 묻는다.
    """
    comps = []
    if device.version and not device.ambiguous:
        comps.append({
            "type": "controller_firmware",
            "version": {"state": "known", "raw": device.version},
            "method": "project_file",      # 이 표시가 CLAIMED_METHODS 를 켠다
            "evidence_id": "proj-%s" % scan.sha256[:12],
            "observed_at": scan.file_mtime,
        })
    return {
        "asset_id": device.suggested_asset_id(),
        "identity": {"vendor_raw": device.vendor or None,
                     "model_raw": device.model or device.known_as or device.order_number,
                     "order_number": device.order_number},
        "label": device.name,          # 엔지니어가 붙인 이름 — 화면에 그대로
        "components": comps,
        "source": {"kind": "project_file", "sha256": scan.sha256,
                   "member": device.member or None, "path": device.path,
                   "device_name": device.name,
                   "same_model_in_file": device.same_model_count},
    }
