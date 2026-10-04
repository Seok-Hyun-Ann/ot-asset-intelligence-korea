# -*- coding: utf-8 -*-
"""지금 이 설치본이 실제로 무엇을 들고 있는지 센다.

    python scripts/inventory.py
    python scripts/inventory.py --db postgresql://otai:otai@127.0.0.1:5433/otai

숫자를 손으로 적어두면 반드시 틀린다. 원문 파일과 저장소에서 직접 센다.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

from otai.attack import find_bundle, load_attack           # noqa: E402
from otai.csaf import load_advisory                        # noqa: E402
from otai.kev import find_snapshot, load_kev               # noqa: E402
from otai.repo import Repo, completeness                   # noqa: E402
from otai.safeio import bounded_json_load                  # noqa: E402
from otai.topology import load_topology                    # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--db", default=str(ROOT / "data" / "otai.db"))
ap.add_argument("--advisory", default=str(ROOT / "data" / "csaf"))
args = ap.parse_args()


def rule(title: str) -> None:
    print("\n" + title)
    print("─" * 66)


# ── 권고문 ────────────────────────────────────────────────────────────────
paths = sorted(Path(args.advisory).rglob("*.json"))
advs, cves, products, per_pub = [], set(), 0, Counter()
cwes, cwe_missing = Counter(), 0
scored, kev_hits = [], set()

for p in paths:
    try:
        a = load_advisory(p)
    except Exception:
        continue
    advs.append((p, a))
    per_pub[a.publisher_name] += 1
    products += len(a.products)
    for v in a.vulnerabilities:
        if v.cve:
            cves.add(v.cve)
        s, _ = v.cvss()
        if s is not None:
            scored.append(s)
    # CWE 는 파서가 뽑지 않는다. 원문에 있는지는 여기서 직접 확인한다.
    raw = bounded_json_load(p)
    for v in raw.get("vulnerabilities") or []:
        w = v.get("cwe")
        if isinstance(w, dict) and w.get("id"):
            cwes[(w["id"], w.get("name", ""))] += 1
        elif isinstance(w, list):
            for one in w:
                if one.get("id"):
                    cwes[(one["id"], one.get("name", ""))] += 1
        else:
            cwe_missing += 1

rule("권고문 (CSAF 2.0)")
print("파일 %d개 · 파싱 성공 %d개" % (len(paths), len(advs)))
for pub, n in per_pub.most_common():
    print("  %-38s %3d건" % (pub, n))
print("대상 제품 항목  %d개" % products)
vend_adv = Counter()
for _, a in advs:
    for pr in a.products:
        if pr.vendor:
            vend_adv[pr.vendor] += 1
print("제품을 가진 제조사 %d종. 상위 10:" % len(vend_adv))
for v, n in vend_adv.most_common(10):
    print("  %-44s 제품 %5d" % (v[:44], n))
big = sorted(advs, key=lambda x: -len(x[1].products))[:5]
print("제품이 가장 많은 권고문 5:")
for p, a in big:
    print("  %-16s 제품 %4d · CVE %4d"
          % (a.advisory_id, len(a.products),
             len({v.cve for v in a.vulnerabilities if v.cve})))

rule("CVE")
print("고유 CVE  %d개" % len(cves))
years = Counter(c.split("-")[1] for c in cves if c.count("-") >= 2)
print("연도별: " + " · ".join("%s년 %d" % (y, n) for y, n in sorted(years.items())))
head = sorted(cves)[:6]
print("예: " + ", ".join(head) + (" … 외 %d개" % (len(cves) - len(head)) if len(cves) > 6 else ""))
if scored:
    print("CVSS 점수가 붙은 항목 %d개 · 최고 %.1f · 최저 %.1f"
          % (len(scored), max(scored), min(scored)))

rule("CWE")
if cwes:
    print("원문에 있는 CWE %d종. 상위 12:" % len(cwes))
    for (cid, name), n in cwes.most_common(12):
        print("  %-12s %-44s %d건" % (cid, name[:44], n))
else:
    print("원문 권고문에 CWE 항목이 없습니다.")
print("CWE 없이 기술된 취약점 항목 %d개" % cwe_missing)
print()
print("※ 파서(otai/csaf.py)는 CWE 를 뽑지 않습니다 — 적용성 판정에 쓰이지 않기")
print("   때문입니다. 판정은 제품·버전·조건으로만 갈립니다. 화면에도 나오지 않습니다.")

# ── KEV · ATT&CK ─────────────────────────────────────────────────────────
rule("보조 신호")
snap = find_snapshot()
if snap:
    kev = load_kev(snap)
    ids = getattr(kev, "cves", None) or getattr(kev, "entries", {})
    known = set(ids) if not isinstance(ids, dict) else set(ids)
    kev_hits = cves & known
    print("CISA KEV  카탈로그 %s · 전체 %d건 · 우리 CVE 중 등재 %d건"
          % (kev.catalog_version, len(known), len(kev_hits)))
    for c in sorted(kev_hits):
        print("  " + c)
else:
    print("CISA KEV  미로드")

bundle = find_bundle()
if bundle:
    at = load_attack(bundle)
    techs = getattr(at, "techniques", {})
    print("ATT&CK for ICS  %s · 기법 %d개" % (at.version, len(techs)))
else:
    print("ATT&CK for ICS  미로드")

# ── 토폴로지 ──────────────────────────────────────────────────────────────
topo_path = ROOT / "fixtures" / "topology" / "purdue-62443-reference.json"
if topo_path.exists():
    t = load_topology(topo_path)
    rule("토폴로지 (합성)")
    print("노드 %d · 엣지 %d · 합성 여부 %s"
          % (len(t.nodes), len(t.edges), t.provenance.get("synthetic")))

# ── 자산 ──────────────────────────────────────────────────────────────────
repo = Repo(args.db)
rows = repo.list()
rule("자산 (%s · %s)" % (repo.backend, args.db))
print("등록된 자산 %d개" % len(rows))
lv = Counter(r["level"] for r in rows)
for k in ("L0", "L1", "L2", "L3", "L4", "L5"):
    if lv.get(k):
        print("  %-3s %2d개" % (k, lv[k]))
vendors = Counter(r["vendor"] or "미상" for r in rows)
print("제조사: " + " · ".join("%s %d" % (k, n) for k, n in vendors.most_common()))
synth = sum(1 for r in rows if r.get("synthetic"))
print("합성 자산 %d개 / 실제 인벤토리 %d개" % (synth, len(rows) - synth))
print()
for r in rows[:8]:
    print("  %-40s %-3s %-24s 펌웨어 %s"
          % (r["asset_id"][:40], r["level"], (r["vendor"] or "미상")[:24],
             r["firmware"] or "미상"))
if len(rows) > 8:
    print("  … 외 %d개" % (len(rows) - 8))

# ── 판정 ──────────────────────────────────────────────────────────────────
# "몇 개나 적용되어 있나" 의 정확한 답은 자산 × 권고문 쌍을 실제로 돌려봐야 나온다.
from otai.applicability import PHRASES, decide_applicability   # noqa: E402
from otai.kev import find_snapshot as _fs, load_kev as _lk     # noqa: E402
from otai.policy import active_policy                          # noqa: E402
from otai.priority import evaluate_priority                    # noqa: E402

AS_OF = "2026-09-11"
_snap = _fs()
_kev = _lk(_snap) if _snap else None
_topo = load_topology(topo_path) if topo_path.exists() else None
_pol = active_policy(ROOT / "data")

from otai.identity import could_match, index_advisory     # noqa: E402
_ix = [(a, index_advisory(a)) for _, a in advs]

by_status, by_bucket = Counter(), Counter()
assets_hit, pairs, skipped = set(), 0, 0
for row in rows:
    asset = repo.asset(row["asset_id"])
    if asset is None:
        continue
    for a, ix in _ix:
        pairs += 1
        # 가망 없는 쌍은 건너뛴다. 결과는 no_known_match 로 확정이다 (ADR-030).
        if not could_match(asset, ix):
            skipped += 1
            by_status["no_known_match"] += 1
            by_bucket["P4"] += 1
            continue
        d = decide_applicability(asset, a, as_of=AS_OF)
        it = evaluate_priority(d, asset, kev=_kev, topology=_topo,
                               lens="default", policy=_pol)
        by_status[d.status] += 1
        by_bucket[it.bucket] += 1
        if d.status in ("affected_confirmed", "affected_likely", "candidate"):
            assets_hit.add(row["asset_id"])

rule("판정 결과 (자산 × 권고문 %d쌍, 기준 %s)" % (pairs, AS_OF))
print("사전 필터가 %d쌍(%.1f%%)을 걸렀습니다 — 제조사·모델이 달라 대상이 아닙니다."
      % (skipped, 100.0 * skipped / max(pairs, 1)))
print("**대상이 아니라는 것은 안전하다는 뜻이 아닙니다.**")
print()
print("적용성 9상태:")
for st, n in by_status.most_common():
    print("  %-26s %-16s %3d쌍" % (st, PHRASES.get(st, ""), n))
print()
print("행동 등급:")
for b in ("P0", "P?", "P1", "P2", "P3", "P4"):
    if by_bucket.get(b):
        print("  %-3s %3d쌍" % (b, by_bucket[b]))
print()
print("무언가 해당하는(해당함 그룹) 자산 %d개 / 전체 %d개"
      % (len(assets_hit), len(rows)))

repo.close()

rule("한 줄 요약")
print("권고문 %d건 · 고유 CVE %d개 · CWE %d종(원문에만) · 대상 제품 %d개"
      % (len(advs), len(cves), len(cwes), products))
print("자산 %d개 · 판정 %d쌍 · 해당하는 자산 %d개 · KEV 등재 %d건"
      % (len(rows), pairs, len(assets_hit), len(kev_hits)))
