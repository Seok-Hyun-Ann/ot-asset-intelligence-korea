# -*- coding: utf-8 -*-
"""CISA KEV 커넥터 (표 13: 실제 악용의 1차 권위).

검증된 엔드포인트 (2026-09-09):
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  → catalogVersion 2026.09.08, 1,699건, `vulnerabilities[].cveID`

**스냅샷을 고정한다.** KEV 는 매일 바뀌므로 오늘의 KEV 로 과거 판정을 재현하면
안 된다. 파일은 `data/kev/<catalogVersion>/` 에 원문 그대로 두고, sha256 과
카탈로그 버전을 우선순위 판정의 input_hash 에 넣는다 (ADR-009).

**KEV 는 OT 를 거의 다루지 않는다.** 1,699건 중 주요 ICS 벤더(Siemens·Mitsubishi·
Schneider·Rockwell·Delta·Moxa)는 4건뿐이다. 따라서 KEV 부재는 '안전' 의 근거가
아니라 '강제 상황이 아님' 의 근거일 뿐이다 — 이 구분이 H01 설계의 핵심이다.
"""
from __future__ import annotations

import hashlib
import json
from .safeio import bounded_json_loads
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Tuple


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    due_date: Optional[str]
    known_ransomware: Optional[str]


@dataclass(frozen=True)
class KevCatalog:
    catalog_version: str
    date_released: str
    sha256: str
    source_path: str
    entries: Dict[str, KevEntry]

    @property
    def cve_ids(self) -> FrozenSet[str]:
        return frozenset(self.entries)

    def intersect(self, cves) -> Tuple[str, ...]:
        """이 자산에 적용되는 CVE 중 실제 악용이 알려진 것."""
        return tuple(sorted(set(cves) & self.cve_ids))

    def entry(self, cve_id: str) -> Optional[KevEntry]:
        return self.entries.get(cve_id)


def load_kev(path) -> KevCatalog:
    path = Path(path)
    raw = path.read_bytes()
    doc = bounded_json_loads(raw, name=path.name)      # 외부 스냅샷 — safeio 경유

    entries = {}
    for v in doc.get("vulnerabilities", ()):
        cid = v.get("cveID")
        if not cid:
            continue
        entries[cid] = KevEntry(
            cve_id=cid,
            vendor_project=v.get("vendorProject", ""),
            product=v.get("product", ""),
            vulnerability_name=v.get("vulnerabilityName", ""),
            date_added=v.get("dateAdded", ""),
            due_date=v.get("dueDate"),
            known_ransomware=v.get("knownRansomwareCampaignUse"),
        )

    return KevCatalog(
        catalog_version=doc.get("catalogVersion", ""),
        date_released=doc.get("dateReleased", ""),
        sha256=hashlib.sha256(raw).hexdigest(),
        source_path=path.name,
        entries=entries,
    )


def find_snapshot(root="data/kev") -> Optional[Path]:
    """가장 최근 스냅샷 디렉터리의 KEV 파일을 찾는다."""
    base = Path(root)
    if not base.exists():
        return None
    cands = sorted(base.glob("*/known_exploited_vulnerabilities.json"))
    return cands[-1] if cands else None
