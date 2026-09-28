# -*- coding: utf-8 -*-
"""출처 처리(7장 · 표 13 · ADR-024)가 실제로 어떻게 도는지 실측한다.

    python scripts/audit_sources.py

주장하지 않고 센다. 통과/실패가 아니라 **지금 무엇이 어떻게 결정되고 있는지**를
숫자로 보여주는 것이 목적이다.
"""
from __future__ import annotations

import io
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

from otai.csaf import load_advisory                              # noqa: E402
from otai.sources import (                                       # noqa: E402
    FIELD_AUTHORITY, KNOWN_PUBLISHERS, compare_cvss, compare_products,
    link_advisories, provenance_table, publisher_role,
)


def rule(t: str) -> None:
    print("\n" + t)
    print("─" * 70)


advs = []
for p in sorted((ROOT / "data" / "csaf").rglob("*.json")):
    try:
        advs.append(load_advisory(p))
    except Exception:
        continue

# ── 1. 발행처 역할 판정 ───────────────────────────────────────────────────
rule("1. 발행처 역할은 어떻게 정해지나 (ADR-024)")
basis, roles = Counter(), Counter()
by_pub = {}
for a in advs:
    role, why = publisher_role(a)
    basis[why] += 1
    roles[role] += 1
    by_pub.setdefault(a.publisher_name, (role, why))
print("권고문 %d건 · 서로 다른 발행처 %d곳" % (len(advs), len(by_pub)))
print("판단 근거:")
for k, v in basis.most_common():
    print("   %-32s %5d건 (%.0f%%)" % (k, v, 100.0 * v / max(len(advs), 1)))
print("부여된 역할:", dict(roles))
print()
print("발행처별:")
for pub, (role, why) in sorted(by_pub.items()):
    mark = "  " if why.startswith("known") else "!!"
    print("  %s %-34s → %-12s %s" % (mark, pub[:34], role, why))
print()
print("KNOWN_PUBLISHERS 표에 등재된 곳: %d" % len(KNOWN_PUBLISHERS))
print("!! 는 표에 없어 스스로 밝힌 값을 그대로 쓴 경우다 —")
print("   ADR-024 가 믿지 말라고 한 바로 그 값이다.")

# ── 2. 선언값 vs 우리 판단 ────────────────────────────────────────────────
rule("2. 스스로 밝힌 역할과 우리가 판단한 역할이 다른가")
mismatch = Counter()
for a in advs:
    role, why = publisher_role(a)
    declared = a.publisher_category or "(없음)"
    if why.startswith("known") and declared != role:
        mismatch[(a.publisher_name, declared, role)] += 1
if mismatch:
    for (pub, dec, role), n in mismatch.most_common():
        print("  %-24s 선언 %-12s → 판단 %-12s %5d건" % (pub[:24], dec, role, n))
    print("\n같은 발행처가 파일마다 다른 값을 선언하기도 한다 — 그래서 표로 판단한다.")
else:
    print("  선언값과 판단이 모두 일치")

# ── 3. 필드별 권위 ────────────────────────────────────────────────────────
rule("3. 필드별 권위 (표 13)")
for f, order in FIELD_AUTHORITY.items():
    print("  %-16s %s" % (f, " > ".join(order)))
print()
print("표 13 이 요구하는 판정 필드 8개 중 구현된 것:")
SPEC_FIELDS = [
    ("제품 영향·수정 범위", "version_range/product_status/remediation", True),
    ("CVE 기본 기록", "cvss (CNA 우선)", True),
    ("제품 식별", "identity.py 사다리 — 소스 권위가 아니라 식별 수준", True),
    ("실제 악용", "KEV (단일 소스라 충돌 없음)", True),
    ("향후 악용 가능성", "EPSS — 의도적 미구현 (ADR-022)", False),
    ("공격 기법", "ATT&CK 고정 버전 (단일 소스)", True),
    ("도달성·공정 영향", "현장 증거 — 외부 소스로 대체 불가", True),
    ("수명주기", "lifecycle.py — 제조사 no_fix_planned > 현장 기록 (ADR-034)", True),
]
for name, how, done in SPEC_FIELDS:
    print("  %s %-22s %s" % ("O" if done else "X", name, how))

# ── 4. 실제 충돌 ──────────────────────────────────────────────────────────
rule("4. 실제로 값이 갈리는 곳")
groups = [g for g in link_advisories(advs) if len(g.advisories) >= 2]
tot_products = tot_conflict = multi = disj = und = 0
cross_vendor = 0
examples = []
for g in groups:
    comps = compare_products(g)
    tot_products += len(comps)
    prov = provenance_table(g)
    if len({p["role"] for p in prov}) > 1:
        cross_vendor += 1
    for c in comps:
        if c.conflicting:
            tot_conflict += 1
            if len(examples) < 3:
                v = c.views["version_range"]
                examples.append((c.key, v.disputed[:2]))
        elif c.disjoint:
            disj += 1
        elif c.undecidable:
            und += 1
        elif c.multivalued:
            multi += 1
print("연결된 묶음 %d개 · 대조한 제품 %d건" % (len(groups), tot_products))
print("  진짜 충돌  (출처 다름 + 범위 겹침)  %5d건 (%.1f%%)"
      % (tot_conflict, 100.0 * tot_conflict / max(tot_products, 1)))
print("  다른 분기  (출처 다름 + 안 겹침)    %5d건" % disj)
print("  판단 보류  (범위 파싱 실패)         %5d건" % und)
print("  범위 여럿  (한 출처 · 충돌 아님)     %5d건" % multi)
print("  값이 하나                          %5d건"
      % (tot_products - tot_conflict - disj - und - multi))
print("서로 다른 역할(vendor/coordinator)이 함께 있는 묶음: %d개 / %d개"
      % (cross_vendor, len(groups)))
print()
print("진짜 충돌 예시 — 무엇과 무엇이 부딪히는가:")
for key, disputed in examples:
    print("  제품 %s" % key[:52])
    for a, sa, b, sb in disputed:
        print("    %-46s ← %s" % (a[-46:], sa))
        print("    %-46s ← %s" % (b[-46:], sb))

# ── 4b. 수명주기 근거 (ADR-034) ───────────────────────────────────────────
rule("4b. 수명주기 근거는 실제로 어디서 오나 (표 13)")
from otai.lifecycle import from_advisory                       # noqa: E402
lc = Counter()
lc_ex = []
for a in advs:
    for cl in from_advisory(a, [p.product_id for p in a.products],
                            role=publisher_role(a)[0]):
        lc["구조화(no_fix_planned)" if cl.structured else "문장에서 읽음"] += 1
        if cl.structured and len(lc_ex) < 2:
            lc_ex.append((a.advisory_id, cl.basis[:100]))
print("권고문에서 뽑은 수명주기 주장:", dict(lc) or "없음")
for aid, b in lc_ex:
    print("  [%s] %s" % (aid, b))
print()
print("`none_available` 은 EOL 로 세지 않는다 — '수정이 없다' 와 '지원이 끝났다' 는 다르다.")
print("제조사가 아무 말도 하지 않으면 미상이다. '지원 중' 으로 붕괴시키지 않는다.")

# ── 5. CVSS 권위 ──────────────────────────────────────────────────────────
rule("5. CVSS 는 CNA 가 이기게 되어 있는가")
cn = Counter()
for g in groups:
    cv = compare_cvss(g)
    if cv is None:
        continue
    cn[(cv.current.source_role, cv.conflicting)] += 1
print("묶음별 CVSS 채택 (역할, 충돌여부):", dict(cn))
print("주의: 지금 corpus 에는 CNA 역할이 없다 — CVE Program/NVD 커넥터가 없기 때문이다.")
print("      그래서 CVSS 는 사실상 vendor > coordinator 로만 결정된다.")

rule("한 줄 요약")
known = sum(1 for a in advs if publisher_role(a)[1].startswith("known"))
print("권고문 %d건 중 %d건(%.0f%%)만 발행처 표로 역할을 판단하고,"
      % (len(advs), known, 100.0 * known / max(len(advs), 1)))
print("나머지 %d건은 스스로 밝힌 값을 그대로 쓴다." % (len(advs) - known))
print("값이 갈리는 제품 %d건은 모두 보관되고 화면에 노출된다." % tot_conflict)
