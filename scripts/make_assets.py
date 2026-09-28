# -*- coding: utf-8 -*-
"""권고문의 **실제 제품 식별자**에서 합성 자산을 파생한다 (ADR-006 확장).

    python scripts/make_assets.py                 # 미리보기
    python scripts/make_assets.py --apply         # fixtures/assets-scale/ 에 쓰기
    python scripts/make_assets.py --apply --per-vendor 3 --vendors 80

자산 측만 합성이다. **제조사·제품명·버전 표기는 실제 CSAF 원문에서 그대로 가져온다** —
지어낸 식별자로는 식별 사다리(표 18)도 버전 비교기도 의미 있게 돌지 않는다.

만들지 않는 것:
  * `network` 블록 — 토폴로지에 없는 노드에 통신을 지어내면 도달성이 거짓이 된다
    (ADR-013/014). 새 자산의 도달성은 UNKNOWN 으로 남는 것이 정직하다.
  * `operations.safety_criticality` 대부분 — 공정 영향을 지어내면 우선순위가 거짓이 된다.

**결정적이다.** 정렬된 순서로만 순회하고 난수를 쓰지 않는다. 두 번 돌리면 바이트 동일이다.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import zlib
from collections import OrderedDict, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

from otai.applicability import decide_applicability       # noqa: E402
from otai.csaf import load_advisory                       # noqa: E402
from otai.model import asset_from_dict                    # noqa: E402

OUT = ROOT / "fixtures" / "assets-scale"
AS_OF = "2026-09-11"

ap = argparse.ArgumentParser()
ap.add_argument("--apply", action="store_true", help="실제로 파일을 쓴다")
ap.add_argument("--vendors", type=int, default=80, help="대상 제조사 수")
ap.add_argument("--per-vendor", type=int, default=2, help="제조사당 제품 수")
ap.add_argument("--advisory", default=str(ROOT / "data" / "csaf"))
args = ap.parse_args()

# ── 장치 종류 추정 — 제품명에서만. 모르면 'unknown' 이지 지어내지 않는다 ──────
KIND = [
    (r"\bplc\b|controller|cpu|melsec|simatic|modicon|micrologix|compactlogix", "PLC"),
    (r"\bhmi\b|panel|touch|comfort", "HMI"),
    (r"\brtu\b|telecontrol", "RTU"),
    (r"drive|inverter|servo|sinamics", "Drive"),
    (r"switch|router|gateway|firewall|scalance|ruggedcom", "NetworkDevice"),
    (r"camera|nvr|ptz|mobotix", "Camera"),
    (r"scada|historian|server|software|studio|workbench|suite", "Software"),
    (r"meter|relay|protection|rtac", "ProtectionRelay"),
    (r"charger|charging station|wallbox", "EVCharger"),
    (r"\breader\b|badge|access control|door ?bell|intercom", "AccessControl"),
    (r"mobile application|\bapp\b|toolkit|\bsdk\b|web\+", "Software"),
    (r"sensor|monitoring|seismic|tank |detector", "Sensor"),
    (r"^[\w.-]+\.(com|ie|hu|net|io|kr)$|^https?://", "WebService"),
]


def kind_of(name: str) -> str:
    low = name.lower()
    for pat, k in KIND:
        if re.search(pat, low):
            return k
    return "unknown"


def slug(*parts: str) -> str:
    s = "-".join(str(p) for p in parts if p)
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()
    return re.sub(r"-{2,}", "-", s)[:58]


# ── 실제 버전 표기에서 '범위 안/밖' 값을 만든다 ─────────────────────────────
_NUM = re.compile(r"\d+(?:\.\d+)*")


def versions_from(raw: str | None):
    """(범위 안으로 보이는 값, 범위 밖으로 보이는 값). 못 만들면 (None, None).

    권고문의 표기를 그대로 읽어 파생한다 — 정답이 구현이 아니라 원문에서 나오도록.
    """
    if not raw:
        return None, None
    m = _NUM.search(raw)
    if not m:
        return None, None
    base = m.group(0)
    parts = base.split(".")
    try:
        last = int(parts[-1])
    except ValueError:
        return None, None
    lower = ".".join(parts[:-1] + [str(max(last - 1, 0))]) if last > 0 else base
    upper = ".".join(parts[:-1] + [str(last + 1)])
    if raw.strip().startswith(("<=", "<")) or "|<" in raw:
        return (lower if last > 0 else base), upper       # 이하 → 낮은 값이 안쪽
    if raw.strip().startswith((">=", ">")):
        return upper, (lower if last > 0 else base)
    return base, upper                                     # 단일 버전 표기


# ── 자산 한 건 ──────────────────────────────────────────────────────────────
def asset(aid, kind, vendor, family, model, version, *, lifecycle="supported",
          order_number=None, observed="2026-08-20T09:00:00Z", factory=None,
          zone=None, note=""):
    body = OrderedDict()
    body["asset_id"] = aid
    body["asset_type"] = kind
    if version is not None:
        body["components"] = [OrderedDict([
            ("evidence_id", "ev-synth-" + aid[:28]),
            ("method", "manual"),
            ("observed_at", observed),
            ("type", "controller_firmware" if kind in ("PLC", "RTU") else "application"),
            ("version", {"raw": version}),
        ])]
    ident = OrderedDict()
    if vendor:
        ident["vendor_raw"] = vendor
    if family:
        ident["family_raw"] = family
    if model:
        ident["model_raw"] = model
    if order_number:
        ident["order_number"] = order_number
    body["identity"] = ident
    body["lifecycle_status"] = lifecycle
    # 공장·구역을 지어내지 않는다. `network` 를 만들지 않는 것과 같은 이유다 —
    # 없는 배치 정보를 채우면 화면이 실제 인벤토리처럼 보이고, 그 순간 거짓이 된다.
    loc = OrderedDict()
    if factory:
        loc["factory"] = factory
    if zone:
        loc["zone"] = zone
    if loc:
        body["location"] = loc
    # 합성임을 자산 스스로 선언한다 — 토폴로지 픽스처와 같은 규칙 (ADR-013)
    body["synthetic"] = True
    body["synthetic_note"] = note or "실제 CSAF 제품 식별자에서 파생한 합성 자산입니다."
    return body


# 판정 결과 → 이름 조각. 이름이 곧 그 자산이 무엇을 보여주는 예시인지 말한다.
SUFFIX = {
    "affected_confirmed": "affected",
    "affected_likely": "likely",
    "not_affected_confirmed": "notaffected",
    "fixed": "fixed",
    "candidate": "candidate",
    "insufficient_information": "unknown",
    "conflicting_evidence": "conflict",
    "stale": "stale",
    "no_known_match": "nomatch",
}


def named_by_result(body, adv, base, version):
    """이 자산을 실제로 판정해 보고 그 결과로 id 를 정한다."""
    try:
        st = decide_applicability(asset_from_dict(body), adv, as_of=AS_OF).status
    except Exception:
        st = "unknown"
    body["asset_id"] = slug(base, SUFFIX.get(st, "v"), str(version).replace(".", "-"))
    body["synthetic_note"] += " 판정 결과: %s" % st
    return body


def main() -> int:
    paths = sorted(Path(args.advisory).rglob("*.json"))
    by_vendor: dict = defaultdict(list)
    advs_by_id: dict = {}
    for p in paths:
        try:
            adv = load_advisory(p)
        except Exception:
            continue
        advs_by_id[adv.advisory_id] = adv
        for prod in adv.products:
            if not prod.vendor or not prod.product_name:
                continue
            by_vendor[prod.vendor].append((adv.advisory_id, prod))

    # 제품이 많은 제조사부터. 동수면 이름 순 — 결정적이어야 한다.
    vendors = sorted(by_vendor, key=lambda v: (-len(by_vendor[v]), v))[:args.vendors]

    out, per_vendor_count = [], {}
    for vendor in vendors:
        seen_names, picked = set(), []
        for adv_id, prod in sorted(by_vendor[vendor],
                                   key=lambda x: (x[1].product_name, x[0], x[1].product_id)):
            if prod.product_name in seen_names:
                continue
            seen_names.add(prod.product_name)
            picked.append((adv_id, prod))
            if len(picked) >= args.per_vendor:
                break
        per_vendor_count[vendor] = len(picked)

        for adv_id, prod in picked:
            name = prod.product_name
            kind = kind_of(name)
            fam = name.split(",")[0].strip()[:80]
            base = slug(vendor.split()[0], name)
            inside, outside = versions_from(prod.version_raw)
            order = prod.model_numbers[0] if prod.model_numbers else None

            # L1 — 제조사만 안다
            out.append(asset(slug(base, "l1"), kind, vendor, None, None, None,
                             note="제조사만 아는 상태 (L1). 출처 %s" % adv_id))
            # L2 — 정확한 모델까지, 버전 미상
            out.append(asset(slug(base, "l2"), kind, vendor, fam, name, None,
                             note="모델까지 아는 상태 (L2). 출처 %s" % adv_id))
            # L3 — 버전이 있는 두 변형. **이름은 추측이 아니라 실제 판정 결과로 짓는다.**
            src = advs_by_id.get(adv_id)
            for v in (inside, outside):
                if not v or (v == outside and outside == inside):
                    continue
                b = asset(slug(base, "v"), kind, vendor, fam, name, v,
                          order_number=order,
                          note="영향 범위 표기 %r 에서 파생한 버전 %s. 출처 %s"
                               % (prod.version_raw, v, adv_id))
                out.append(named_by_result(b, src, base, v) if src else b)
            # L3 — 지원 종료 + 버전 미상 (H04 가 걸리는 조합)
            #
            # **전 제품에 만들지 않는다.** H04 는 적용성 전제 없이 발화하는 수명주기
            # 규칙이라, EOL 자산이 많으면 큐의 과반이 P? 가 된다 (ADR-007 이 피하려던
            # 실패 모드). 실제 현장 비율에 가깝게 5개 중 1개만 만든다.
            # 난수가 아니라 이름 해시라 두 번 돌려도 같은 집합이 나온다.
            if zlib.crc32(base.encode()) % 5 == 0:
                out.append(asset(slug(base, "eol"), kind, vendor, fam, name, None,
                                 lifecycle="end_of_life",
                                 note="지원 종료 + 버전 미상 (H04 전제). 출처 %s" % adv_id))

    # 중복 id 제거 — 결정적으로 앞선 것을 남긴다
    uniq = OrderedDict()
    for b in out:
        uniq.setdefault(b["asset_id"], b)
    assets = list(uniq.values())

    print("제조사 %d종 · 자산 %d개" % (len(vendors), len(assets)))
    kinds = defaultdict(int)
    for b in assets:
        kinds[b["asset_type"]] += 1
    print("장치 종류: " + " · ".join("%s %d" % kv for kv in sorted(kinds.items())))
    print("\n예시 5건:")
    for b in assets[:5]:
        i = b["identity"]
        print("  %-52s %-14s %s" % (b["asset_id"], b["asset_type"],
                                    (i.get("model_raw") or i.get("vendor_raw"))[:44]))

    if not args.apply:
        print("\n미리보기입니다. 쓰려면 --apply 를 붙이세요.")
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for stale in OUT.glob("*.json"):
        stale.unlink()
    for b in assets:
        (OUT / (b["asset_id"] + ".json")).write_text(
            json.dumps(b, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
    print("\n%s 에 %d개 기록" % (OUT.relative_to(ROOT).as_posix(), len(assets)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
