# -*- coding: utf-8 -*-
"""CSAF 2.0 파서.

검증된 두 공급자를 모두 읽는다:
  CISA    coordinator, product_tree 3단(vendor/product_name/product_version_range),
          범위는 자유 문자열, product_identification_helper 없음
  Siemens vendor, 동일 3단 구조지만 범위는 vers: URI,
          product_identification_helper.model_numbers 에 주문번호 제공

원문 불변 보존(FR-SRC-004): 파일 바이트의 sha256 을 그대로 들고 다닌다.
"""
from __future__ import annotations

import hashlib
import json
import re
from .safeio import bounded_json_loads
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 2: tracking 의 initial_release_date 와 개정 횟수를 뽑는다 (시간 축, ADR-037).
#    파싱 결과가 늘었으므로 버전을 올린다 — 불변 규칙 5 가 요구하는 것이다.
PARSER_VERSION = "csaf-2.0/2"


# "R08/16/32/120PCPU" 처럼 모델 여러 개를 한 문자열에 압축한 표기를 전개한다.
# CISA/Mitsubishi 실데이터에서 확인된 패턴 — 전개하지 않으면 정확한 모델을 가진
# 자산이 오히려 no_known_match 로 떨어진다 (R02, 표 39 후보 Recall 98%).
_COMPRESSED_MODEL_RE = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z]+)(\d+(?:/\d+)+)([A-Za-z][A-Za-z0-9]*)"
)


def expand_product_names(name: str) -> Tuple[str, ...]:
    """압축 모델 표기를 개별 모델명으로 전개한다. 원문은 항상 첫 항목으로 남는다."""
    if not name:
        return ()
    m = _COMPRESSED_MODEL_RE.search(name)
    if not m:
        return (name,)
    prefix, numbers, suffix = m.group(1), m.group(2), m.group(3)
    variants = [name]
    for n in numbers.split("/"):
        variants.append(name[: m.start()] + prefix + n + suffix + name[m.end():])
    return tuple(dict.fromkeys(variants))


@dataclass(frozen=True)
class ProductEntry:
    """product_tree 를 평탄화한 한 줄. 하나의 product_id 에 대응."""
    product_id: str
    vendor: str
    product_name: str
    full_name: str
    version_raw: Optional[str]          # 원문 그대로 (raw_expression)
    version_category: Optional[str]     # product_version_range | product_version
    model_numbers: Tuple[str, ...] = ()

    @property
    def name_variants(self) -> Tuple[str, ...]:
        return expand_product_names(self.product_name)


@dataclass(frozen=True)
class VulnEntry:
    cve: Optional[str]
    product_status: Dict[str, Tuple[str, ...]]
    remediations: Tuple[dict, ...] = ()
    scores: Tuple[dict, ...] = ()

    def status_of(self, product_id: str) -> Tuple[str, ...]:
        return tuple(k for k, ids in self.product_status.items() if product_id in ids)

    def cvss(self) -> Tuple[Optional[float], Optional[str]]:
        """(최대 baseScore, 그 벡터 문자열). 없으면 (None, None).

        벡터가 능력 부여(capability grants)의 유일한 근거이므로 점수와 함께 들고 다닌다.
        """
        best, vector = None, None
        for sc in self.scores:
            for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
                node = sc.get(key) or {}
                score = node.get("baseScore")
                if score is None:
                    continue
                if best is None or score > best:
                    best, vector = score, node.get("vectorString")
        return best, vector


@dataclass(frozen=True)
class Advisory:
    advisory_id: str
    title: str
    publisher_name: str
    publisher_category: str
    current_release_date: Optional[str]
    sha256: str
    source_path: str
    products: Tuple[ProductEntry, ...]
    vulnerabilities: Tuple[VulnEntry, ...]
    parser_version: str = PARSER_VERSION
    # 언제 처음 나왔는가. 이 날짜 이전에는 **이 권고문이 존재하지 않았다** —
    # 과거 시점으로 되돌릴 때 이것을 빼지 않으면 그때 몰랐던 것을 안 것처럼 계산한다.
    initial_release_date: Optional[str] = None
    revisions: int = 1

    def product_by_id(self, pid: str) -> Optional[ProductEntry]:
        for p in self.products:
            if p.product_id == pid:
                return p
        return None


_VERSION_CATEGORIES = ("product_version_range", "product_version")


def _walk(branches, vendor=None, product_name=None, out=None):
    out = [] if out is None else out
    for b in branches or ():
        cat = b.get("category")
        name = b.get("name")
        v, pn = vendor, product_name
        if cat == "vendor":
            v = name
        elif cat == "product_name":
            pn = name
        # product_family 등 중간 분기는 product_name 을 덮어쓰지 않고 통과시킨다

        prod = b.get("product")
        if prod and prod.get("product_id"):
            helper = prod.get("product_identification_helper") or {}
            models = tuple(helper.get("model_numbers") or ())
            out.append(
                ProductEntry(
                    product_id=prod["product_id"],
                    vendor=v or "",
                    product_name=pn or (name or ""),
                    full_name=prod.get("name") or "",
                    version_raw=name if cat in _VERSION_CATEGORIES else None,
                    version_category=cat if cat in _VERSION_CATEGORIES else None,
                    model_numbers=models,
                )
            )
        _walk(b.get("branches"), v, pn, out)
    return out


def load_advisory(path) -> Advisory:
    path = Path(path)
    raw_bytes = path.read_bytes()
    # 권고문은 외부(CISA·제조사·번들)에서 온다. 서명은 보낸 이를 증명할 뿐 잘
    # 만들어졌음을 증명하지 않는다 — safeio 의 한계 검사를 거친다 (ADR-041).
    doc = bounded_json_loads(raw_bytes, name=str(path))
    d = doc["document"]
    tracking = d.get("tracking", {})
    publisher = d.get("publisher", {})

    products = tuple(_walk((doc.get("product_tree") or {}).get("branches")))

    vulns = []
    for v in doc.get("vulnerabilities", ()):
        status = {k: tuple(ids) for k, ids in (v.get("product_status") or {}).items()}
        vulns.append(
            VulnEntry(
                cve=v.get("cve"),
                product_status=status,
                remediations=tuple(v.get("remediations") or ()),
                scores=tuple(v.get("scores") or ()),
            )
        )

    return Advisory(
        advisory_id=tracking.get("id") or path.stem.upper(),
        title=d.get("title", ""),
        publisher_name=publisher.get("name", ""),
        publisher_category=publisher.get("category", ""),
        current_release_date=tracking.get("current_release_date"),
        initial_release_date=tracking.get("initial_release_date"),
        revisions=len(tracking.get("revision_history") or ()) or 1,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        source_path=path.name,
        products=products,
        vulnerabilities=tuple(vulns),
    )
