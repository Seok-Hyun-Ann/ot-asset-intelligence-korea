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
    "asset_type": ("asset_type", "장치종류", "장치 종류", "유형", "type"),
    "identity.vendor_raw": ("vendor", "제조사", "manufacturer", "maker", "벤더"),
    "identity.family_raw": ("family", "제품군", "series", "시리즈"),
    "identity.model_raw": ("model", "모델", "모델명", "product", "제품명"),
    "identity.order_number": ("order_number", "주문번호", "article", "품번", "sku"),
    "firmware": ("firmware", "펌웨어", "fw", "firmware_version", "펌웨어버전"),
    "location.factory": ("factory", "공장", "site", "사업장"),
    "location.zone": ("zone", "구역", "cell", "셀", "라인"),
    "operations.safety_criticality": ("safety", "안전중요도", "safety_criticality", "안전"),
    "lifecycle_status": ("lifecycle", "수명주기", "eol", "lifecycle_status"),
    # CISA 자산 인벤토리 지침의 고우선 속성 (ADR-042). 사람이 아는 것은 사람이 넣는다.
    "address.ip": ("ip", "ip address", "ip주소", "아이피", "ipaddress"),
    "address.mac": ("mac", "mac address", "mac주소", "맥주소", "macaddress"),
    "address.hostname": ("hostname", "호스트명", "host name", "장비명", "컴퓨터이름"),
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

    def summary(self) -> str:
        L = ["행 %d · 생성 대상 %d · 중복 %d · 오류 %d"
             % (self.rows, self.created, self.duplicates, self.errors)]
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


def load_rows(csv_path) -> Tuple[List[str], List[Tuple[int, Dict[str, str]]]]:
    """신뢰할 수 없는 바이트는 `safeio` 를 거친다 (ADR-041).

    크기·행 수·디코딩 한계는 전부 거기 있다 — 여기서 다시 세면 두 벌이 어긋난다.
    """
    return bounded_csv_rows(csv_path, max_bytes=MAX_CSV_BYTES, max_rows=MAX_ROWS)


def build_report(csv_path, mapping_override: Optional[dict] = None,
                 existing_ids=()) -> ImportReport:
    headers, rows = load_rows(csv_path)
    mapping, unmapped = infer_mapping(headers)
    if mapping_override:
        # 매핑 파일이 항상 이긴다
        for h, f in mapping_override.items():
            mapping[h] = f
        unmapped = [h for h in unmapped if h not in mapping_override]

    rep = ImportReport(mapping=mapping, unmapped_headers=unmapped)
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
                    "evidence_id": "ev-csv-%s-line%d" % (Path(csv_path).stem, line),
                })
            elif value:
                _set_path(asset, field_name, value)

        # 주소 네 칸은 **한 레코드**로 모은다 — 따로 흩어 두면 어느 IP 의 MAC
        # 인지 알 수 없다. 사람이 적은 값이므로 method 는 import 다 (ADR-042).
        a = asset.pop("address", None)
        if a:
            rec = {"method": "import",
                   "evidence_id": "ev-csv-%s-line%d" % (Path(csv_path).stem, line)}
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
