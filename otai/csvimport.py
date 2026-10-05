# -*- coding: utf-8 -*-
"""CSV 자산 Import (FR-ASSET-003).

인수 기준 그대로: **Dry run · 오류 · 중복 · 변경 요약.**
`--apply` 를 주지 않으면 아무것도 쓰지 않는다.

원칙 세 가지:
  1. **추측하지 않는다.** 매핑되지 않은 헤더는 *보고*하고 버린다.
     자동 추론은 후보를 제시할 뿐이고, 매핑 파일이 항상 이긴다.
  2. **빈 칸은 빈 문자열이 아니라 미상이다.** `{"state": "unknown"}` 으로 들어간다
     (불변 규칙 2: unknown 을 다른 값으로 붕괴시키지 않는다).
  3. **모든 셀은 safeio 를 거친다.** CSV 수식 인젝션 무해화 (표 40).
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .safeio import (UnsafeInput, bounded_csv_rows, is_formula,
                     sanitize_csv_cell)

MAX_CSV_BYTES = 32 * 1024 * 1024
MAX_ROWS = 100_000

# 헤더 동의어 → 자산 필드. 후보를 제시할 뿐 확정하지 않는다.
SYNONYMS: Dict[str, Tuple[str, ...]] = {
    "asset_id": ("asset_id", "자산id", "자산 id", "설비번호", "tag", "태그"),
    "asset_type": ("asset_type", "장치종류", "장치 종류", "유형", "type",
                   "설비구분", "설비유형", "종류", "구분"),
    # 사람이 읽는 설비명. **식별에 쓰지 않는다** — 현장이 붙인 이름이다.
    # 이게 없으면 목록에 설비번호만 떠서 현장 사람이 자기 설비를 못 찾는다.
    "label": ("label", "설비명", "설비 명", "장비명", "설비이름", "name",
              "equipment_name", "호기", "설비"),
    "identity.vendor_raw": ("vendor", "제조사", "manufacturer", "maker", "벤더"),
    "identity.family_raw": ("family", "제품군", "series", "시리즈"),
    "identity.model_raw": ("model", "모델", "모델명", "product", "제품명"),
    "identity.order_number": ("order_number", "주문번호", "article", "품번", "sku"),
    "firmware": ("firmware", "펌웨어", "fw", "firmware_version", "펌웨어버전"),
    "location.factory": ("factory", "공장", "site", "사업장", "위치", "동"),
    "location.zone": ("zone", "구역", "cell", "셀", "라인"),
    "operations.safety_criticality": ("safety", "안전중요도", "safety_criticality", "안전"),
    "lifecycle_status": ("lifecycle", "수명주기", "eol", "lifecycle_status"),
    # CISA 자산 인벤토리 지침의 고우선 속성 (ADR-042). 사람이 아는 것은 사람이 넣는다.
    "address.ip": ("ip", "ip address", "ip주소", "아이피", "ipaddress"),
    "address.mac": ("mac", "mac address", "mac주소", "맥주소", "macaddress"),
    "address.hostname": ("hostname", "호스트명", "host name", "컴퓨터이름"),
    # 조치를 사람에게 붙이는 고리. CISA 지침의 Department/Owner.
    "ownership.contact": ("contact", "담당자", "담당", "owner", "책임자", "관리자"),
    "ownership.department": ("department", "부서", "팀", "소속", "담당부서"),
    "address.vlan": ("vlan", "vlan id", "브이랜"),
}

REQUIRED = ("asset_id",)


def infer_mapping(headers) -> Tuple[Dict[str, str], List[str]]:
    """헤더 → 필드 후보를 추론한다. 반환: (매핑, 매핑 못 한 헤더)"""
    mapping: Dict[str, str] = {}
    unmapped: List[str] = []
    for h in headers:
        key = (h or "").strip().lower().replace("_", " ")
        hit = None
        for field_name, names in SYNONYMS.items():
            if key in [n.lower().replace("_", " ") for n in names]:
                hit = field_name
                break
        if hit and hit not in mapping.values():
            mapping[h] = hit
        else:
            unmapped.append(h)
    return mapping, unmapped


@dataclass
class RowResult:
    line: int
    asset_id: Optional[str]
    action: str            # create | duplicate | error
    message: str = ""
    asset: Optional[dict] = None
    sanitized_cells: List[str] = field(default_factory=list)


@dataclass
class ImportReport:
    rows: int = 0
    created: int = 0
    duplicates: int = 0
    errors: int = 0
    unmapped_headers: List[str] = field(default_factory=list)
    mapping: Dict[str, str] = field(default_factory=dict)
    results: List[RowResult] = field(default_factory=list)
    sanitized_count: int = 0
    applied: bool = False
    #: 무엇으로 읽었는지. 한국 Excel 기본 저장은 CP949 다 (ADR-046).
    encoding: str = "utf-8-sig"

    def summary(self) -> str:
        L = ["행 %d · 생성 대상 %d · 중복 %d · 오류 %d"
             % (self.rows, self.created, self.duplicates, self.errors)]
        if self.encoding != "utf-8-sig":
            L.append("글자 인코딩 %s 로 읽었습니다 — 한글이 깨져 보이면 "
                     "멈추고 알려 주세요 (깨진 제조사명은 '일치 항목 없음' 이 "
                     "됩니다)." % self.encoding)
        if self.unmapped_headers:
            L.append("매핑되지 않은 헤더 %d개 (추측하지 않고 버립니다): %s"
                     % (len(self.unmapped_headers), ", ".join(self.unmapped_headers)))
        if self.sanitized_count:
            L.append("수식 인젝션 무해화 셀 %d개" % self.sanitized_count)
        L.append("적용됨" if self.applied else "**dry-run — 아무것도 쓰지 않았습니다**")
        return "\n".join(L)


def _set_path(obj: dict, dotted: str, value) -> None:
    parts = dotted.split(".")
    cur = obj
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def load_rows(csv_path):
    """신뢰할 수 없는 바이트는 `safeio` 를 거친다 (ADR-041).

    크기·행 수·인코딩 한계는 전부 거기 있다 — 여기서 다시 세면 두 벌이 어긋난다.
    `(헤더, 행, 인코딩)` 을 돌려준다.
    """
    return bounded_csv_rows(csv_path, max_bytes=MAX_CSV_BYTES, max_rows=MAX_ROWS)


def build_report(csv_path, mapping_override: Optional[dict] = None,
                 existing_ids=()) -> ImportReport:
    """CSV 한 장을 읽어 dry-run 보고서를 만든다."""
    headers, rows, encoding = load_rows(csv_path)
    return build_report_from_rows(headers, rows, Path(csv_path).stem,
                                  mapping_override=mapping_override,
                                  existing_ids=existing_ids, encoding=encoding)


def build_report_from_rows(headers, rows, source_stem: str, *,
                           mapping_override: Optional[dict] = None,
                           existing_ids=(),
                           encoding: str = "utf-8-sig") -> ImportReport:
    """**형식과 무관한** 뒤 단계: 매핑 → 무해화 → 미상 보존 → 중복 검사.

    CSV 와 엑셀이 이 함수를 공유한다 (ADR-046). 입구를 둘로 두고 뒤 단계를
    복사하면 한쪽을 고칠 때 다른 쪽이 조용히 달라진다 — 이 저장소가 반복해서
    겪은 실수다 (`_cmd_controls` 의 kev 누락, `evidence_for` 의 코드별 분기).
    """
    mapping, unmapped = infer_mapping(headers)
    if mapping_override:
        # 매핑 파일이 항상 이긴다
        for h, f in mapping_override.items():
            mapping[h] = f
        unmapped = [h for h in unmapped if h not in mapping_override]

    rep = ImportReport(mapping=mapping, unmapped_headers=unmapped,
                       encoding=encoding)
    seen = set(existing_ids)

    for line, row in rows:
        rep.rows += 1
        asset: dict = {}
        sanitized: List[str] = []

        for header, raw in row.items():
            field_name = mapping.get(header)
            if field_name is None:
                continue
            if is_formula(raw):
                sanitized.append(header)
                rep.sanitized_count += 1
            value = sanitize_csv_cell(raw).strip()

            if field_name == "firmware":
                # 빈 칸은 "" 가 아니라 미상이다
                asset.setdefault("components", [{}])
                asset["components"][0].update({
                    "type": "controller_firmware",
                    "version": {"raw": value} if value else {"state": "unknown"},
                    "method": "import",
                    "evidence_id": "ev-%s-line%d" % (source_stem, line),
                })
            elif value:
                _set_path(asset, field_name, value)

        # 주소 네 칸은 **한 레코드**로 모은다 — 따로 흩어 두면 어느 IP 의 MAC
        # 인지 알 수 없다. 사람이 적은 값이므로 method 는 import 다 (ADR-042).
        a = asset.pop("address", None)
        if a:
            rec = {"method": "import",
                   "evidence_id": "ev-%s-line%d" % (source_stem, line)}
            for k in ("ip", "mac", "hostname"):
                if a.get(k):
                    rec[k] = a[k]
            if a.get("vlan"):
                try:
                    rec["vlan"] = int(str(a["vlan"]).strip())
                except ValueError:
                    pass          # 숫자가 아니면 **버린다** — 추측해서 넣지 않는다
            if len(rec) > 2:      # method·evidence_id 말고 실제 값이 있을 때만
                asset.setdefault("network", {}).setdefault("addresses", []).append(rec)

        aid = asset.get("asset_id")
        if not aid:
            rep.errors += 1
            rep.results.append(RowResult(line, None, "error", "asset_id 없음"))
            continue
        if aid in seen:
            rep.duplicates += 1
            rep.results.append(RowResult(line, aid, "duplicate", "이미 존재하는 asset_id"))
            continue

        seen.add(aid)
        asset.setdefault("asset_type", "unknown")
        asset.setdefault("components", [{"type": "controller_firmware",
                                         "version": {"state": "unknown"},
                                         "method": "import"}])
        rep.created += 1
        rep.results.append(RowResult(line, aid, "create", asset=asset,
                                     sanitized_cells=sanitized))
    return rep


def apply_report(rep: ImportReport, out_dir) -> List[Path]:
    """dry-run 결과를 실제 자산 파일로 쓴다."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for r in rep.results:
        if r.action != "create" or r.asset is None:
            continue
        p = out_dir / ("%s.json" % r.asset_id)
        p.write_text(json.dumps(r.asset, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                     encoding="utf-8")
        written.append(p)
    rep.applied = True
    return written


# --------------------------------------------------------------------------
# 매핑 프로파일 (ADR-046)
# --------------------------------------------------------------------------
#: 사람이 고른 것을 남겨 두는 곳. **매달 다시 묻지 않기 위해서**다.
#: 추론은 후보를 제시할 뿐이고 프로파일이 항상 이긴다 — 그 규칙은 원래부터
#: `build_report(mapping_override=...)` 가 쥐고 있었고, 여기는 그 값을 담는다.
PROFILE_DIR = "data/import-profiles"


@dataclass
class ImportProfile:
    """한 대장을 어떻게 읽을지에 대한 사람의 결정."""
    name: str
    mapping: Dict[str, str] = field(default_factory=dict)
    #: 엑셀일 때만. 시트 이름 → 머리글 행 번호. **짐작하지 않기 위해 적어 둔다.**
    sheets: Dict[str, int] = field(default_factory=dict)
    note: Optional[str] = None

    def to_dict(self) -> dict:
        return {"name": self.name, "mapping": self.mapping,
                "sheets": self.sheets, "note": self.note}


#: 파일명에 쓸 수 없는 글자. 백슬래시를 빠뜨리면 윈도우에서 경로가 갈라진다.
_BAD_NAME_CHARS = set('\\/:*?"<>|')


def profile_path(name: str, root=PROFILE_DIR) -> Path:
    """프로파일 파일 경로. 이름이 파일명으로 쓰이므로 경로 조각을 막는다.

    구분자만 지우면 `../../etc/passwd` 가 `....etcpasswd.json` 이 된다 — 디렉터리를
    벗어나지는 않지만 점이 남아 읽기 어렵다. 점 뭉치를 하나로 줄이고 양끝 점·공백을
    뗀다. 가운데 점(`1공장.상반기`)은 지킬 이유가 있으니 남긴다.
    """
    cleaned = "".join(ch for ch in name
                      if ch not in _BAD_NAME_CHARS and ch.isprintable())
    while ".." in cleaned:
        cleaned = cleaned.replace("..", ".")
    cleaned = cleaned.strip(". \t")
    return Path(root) / ("%s.json" % (cleaned or "profile"))


def save_profile(profile: ImportProfile, root=PROFILE_DIR) -> Path:
    p = profile_path(profile.name, root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(profile.to_dict(), ensure_ascii=False,
                            indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return p


def load_profile(name_or_path, root=PROFILE_DIR) -> ImportProfile:
    """외부 파일이므로 `safeio` 를 거친다 (ADR-041)."""
    from .safeio import bounded_json_load
    p = Path(name_or_path)
    if not p.exists():
        p = profile_path(str(name_or_path), root)
    doc = bounded_json_load(p)
    return ImportProfile(
        name=doc.get("name") or p.stem,
        mapping=dict(doc.get("mapping") or {}),
        sheets={k: int(v) for k, v in (doc.get("sheets") or {}).items()},
        note=doc.get("note"),
    )


def list_profiles(root=PROFILE_DIR) -> List[Path]:
    d = Path(root)
    return sorted(d.glob("*.json")) if d.exists() else []
