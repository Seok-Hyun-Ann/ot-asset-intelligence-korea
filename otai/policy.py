# -*- coding: utf-8 -*-
"""정책 거버넌스 (FR-GOV-001, 표 41).

**규칙 DSL 을 만들지 않는다.** 대신 이미 매개변수인 것들을 파일로 빼고,
파일 내용 해시로 버전을 만든다. 규칙의 *구조*는 코드가, *임계값*은 정책이 쥔다.

  POLICY_VERSION = "policy/<sha256[:12]>"

승인·롤백은 번들의 `current` 포인터 패턴을 그대로 쓴다 (ADR-018).
영향 미리보기는 "같은 입력을 정책 A·B 로 돌려 diff" 다 — 지금 구조(`input_hash`,
`as_of`, append-only decision)가 이미 그 형태다.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

CURRENT_FILE = "current"

# 판정에 영향을 주지 않는 필드 — 변경돼도 영향 미리보기에 나오지 않는다
METADATA_FIELDS = frozenset({"author", "approved_by", "basis"})


@dataclass(frozen=True)
class Policy:
    """기본값은 코드의 현재 상수와 동일하다 — `policy/default` 로 기존 해시가 재현된다."""
    freshness_days: int = 365
    vendor_critical_cvss: float = 9.0
    max_hops: int = 5
    base_bucket: Dict[str, str] = field(default_factory=lambda: {
        "affected_confirmed": "P2",
        "affected_likely": "P3",
        "candidate": "P3",
        "insufficient_information": "P3",
        "stale": "P3",
        "conflicting_evidence": "P3",
        "not_affected_confirmed": "P4",
        "fixed": "P4",
        "no_known_match": "P4",
    })
    hard_rule_floors: Dict[str, str] = field(default_factory=lambda: {
        "H01": "P1", "H02": "P0", "H03": "P1", "H04": "P1", "H05": "P1",
    })
    lens_presets: Dict[str, Dict[str, float]] = field(default_factory=lambda: {
        "default": {"안전": 1.0, "악용": 1.0, "도달성": 1.0, "기술": 1.0, "수명": 1.0, "정비": 1.0},
        "ops": {"안전": 2.0, "악용": 1.0, "도달성": 1.0, "기술": 0.5, "수명": 1.0, "정비": 2.0},
        "security": {"안전": 1.0, "악용": 2.5, "도달성": 2.0, "기술": 1.5, "수명": 1.0, "정비": 0.3},
    })
    # 표 41: 승인자 자리를 비워두지 않는다
    author: str = "project owner"
    approved_by: str = "project owner"
    basis: str = "슬라이스 2~4 의 코드 상수와 동일한 기본값"

    # ---- 버전 -----------------------------------------------------------
    def canonical(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    @property
    def version(self) -> str:
        return "policy/%s" % self.sha256[:12]

    # ---- 변경 추적 -------------------------------------------------------
    def diff(self, other: "Policy") -> Dict[str, Tuple[object, object]]:
        a, b = asdict(self), asdict(other)
        return {k: (a[k], b[k]) for k in sorted(a) if a[k] != b[k]}

    def touched_evaluators(self, other: "Policy") -> Tuple[str, ...]:
        """바뀐 필드가 어느 평가자를 건드리는가 — 영향 범위를 좁히는 데 쓴다 (2C).

        메타데이터(작성자·승인자·근거)는 판정에 영향을 주지 않으므로 제외한다.
        """
        mapping = {
            "freshness_days": ("신선도",),
            "vendor_critical_cvss": ("벤더 Critical",),
            "max_hops": ("유효 경로", "중요 자산 도달", "외부 상위 Zone 도달"),
            "base_bucket": ("기본 버킷",),
            "hard_rule_floors": ("강제규칙 floor",),
            "lens_presets": ("정렬만",),
        }
        out = []
        for k in self.diff(other):
            if k in METADATA_FIELDS:
                continue
            out.extend(mapping.get(k, (k,)))
        return tuple(sorted(set(out)))

    def affects_verdicts(self, other: "Policy") -> bool:
        """판정을 바꿀 수 있는 변경인가. 메타데이터만 바뀌었으면 False."""
        return bool(set(self.diff(other)) - METADATA_FIELDS)


DEFAULT_POLICY = Policy()


def load_policy(path) -> Policy:
    from .safeio import bounded_json_load
    data = bounded_json_load(path)
    known = {f for f in Policy.__dataclass_fields__}
    unknown = set(data) - known
    if unknown:
        raise ValueError("알 수 없는 정책 필드: %s" % ", ".join(sorted(unknown)))
    return Policy(**data)


def save_policy(policy: Policy, path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(asdict(policy), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                 encoding="utf-8")
    return p


# --------------------------------------------------------------------------
# 승인과 롤백 — 번들과 같은 패턴
# --------------------------------------------------------------------------
def _root(data_dir) -> Path:
    return Path(data_dir) / "policy"


def read_current(data_dir) -> Optional[str]:
    p = _root(data_dir) / CURRENT_FILE
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8").strip() or None


def approve(policy: Policy, data_dir) -> str:
    """정책을 승인해 활성화한다. 이전 버전은 지우지 않는다."""
    root = _root(data_dir)
    version_dir = root / policy.sha256[:12]
    version_dir.mkdir(parents=True, exist_ok=True)
    save_policy(policy, version_dir / "policy.json")

    tmp = root / (CURRENT_FILE + ".tmp")
    tmp.write_text(policy.sha256[:12] + "\n", encoding="utf-8")
    os.replace(tmp, root / CURRENT_FILE)
    return policy.version


def rollback(data_dir, to_id: str) -> bool:
    root = _root(data_dir)
    if not (root / to_id / "policy.json").exists():
        return False
    tmp = root / (CURRENT_FILE + ".tmp")
    tmp.write_text(to_id + "\n", encoding="utf-8")
    os.replace(tmp, root / CURRENT_FILE)
    return True


def active_policy(data_dir) -> Policy:
    cur = read_current(data_dir)
    if cur is None:
        return DEFAULT_POLICY
    p = _root(data_dir) / cur / "policy.json"
    return load_policy(p) if p.exists() else DEFAULT_POLICY


# --------------------------------------------------------------------------
# 영향 미리보기 (FR-GOV-001)
# --------------------------------------------------------------------------
@dataclass
class PreviewRow:
    asset_id: str
    advisory_id: str
    status_a: str
    status_b: str
    bucket_a: str
    bucket_b: str

    @property
    def changed(self) -> bool:
        return self.status_a != self.status_b or self.bucket_a != self.bucket_b


@dataclass
class PreviewReport:
    policy_a: str
    policy_b: str
    touched: Tuple[str, ...]
    rows: List[PreviewRow]

    @property
    def changed(self) -> List[PreviewRow]:
        return [r for r in self.rows if r.changed]

    def summary(self) -> str:
        L = ["정책 %s → %s" % (self.policy_a, self.policy_b)]
        L.append("영향 평가자: %s" % (", ".join(self.touched) or "없음"))
        L.append("검사 %d건 · 변경 %d건" % (len(self.rows), len(self.changed)))
        for r in self.changed:
            L.append("  %-24s %-18s %s→%s  %s→%s"
                     % (r.asset_id, r.advisory_id, r.status_a, r.status_b,
                        r.bucket_a, r.bucket_b))
        if not self.changed:
            L.append("  판정이 뒤집히는 항목이 없습니다.")
        return "\n".join(L)


def preview(assets, advisories, policy_a: Policy, policy_b: Policy, *,
            as_of: str, kev=None, topology=None) -> PreviewReport:
    """같은 입력을 두 정책으로 돌려 뒤집히는 판정을 찾는다."""
    from .applicability import decide_applicability
    from .priority import evaluate_priority

    rows: List[PreviewRow] = []
    for asset in assets:
        for adv in advisories:
            da = decide_applicability(asset, adv, as_of=as_of,
                                      freshness_days=policy_a.freshness_days)
            db = decide_applicability(asset, adv, as_of=as_of,
                                      freshness_days=policy_b.freshness_days)
            ia = evaluate_priority(da, asset, kev=kev, topology=topology, policy=policy_a)
            ib = evaluate_priority(db, asset, kev=kev, topology=topology, policy=policy_b)
            rows.append(PreviewRow(asset.asset_id, adv.advisory_id,
                                   da.status, db.status, ia.bucket, ib.bucket))
    return PreviewReport(policy_a.version, policy_b.version,
                         policy_a.touched_evaluators(policy_b), rows)
