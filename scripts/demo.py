# -*- coding: utf-8 -*-
"""전 과정 시연 — 정보가 늘면서 결론이 움직이는 것을 한 흐름으로 보여준다.

    python scripts/demo.py            # 콘솔 출력 + out/demo/ 에 결과 저장
    python scripts/demo.py --quiet    # 저장만

부록 E 의 확장이다. 같은 자산이 L0 에서 P4 까지 가는 동안 무엇이 결론을 바꾸는지
단계별로 보여준다. 각 단계는 실제 엔진 호출이며 미리 만든 문자열이 아니다.
"""
from __future__ import annotations

import argparse
import io
import shutil
import sys
from pathlib import Path

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from otai.applicability import decide_applicability            # noqa: E402
from otai.attack import find_bundle, load_attack               # noqa: E402
from otai.bundle import (apply_bundle, export_bundle,          # noqa: E402
                         generate_keypair, read_current, verify_bundle)
from otai.card import render_text                              # noqa: E402
from otai.csaf import load_advisory                            # noqa: E402
from otai.csvimport import build_report                        # noqa: E402
from otai.kev import find_snapshot, load_kev                   # noqa: E402
from otai.model import load_asset                              # noqa: E402
from otai.paths import blocking_candidates, find_paths         # noqa: E402
from otai.policy import DEFAULT_POLICY, preview, save_policy   # noqa: E402
from otai.priority import evaluate_priority, sort_queue        # noqa: E402
from otai.queue_view import render_queue                       # noqa: E402
from otai.render import render_html                            # noqa: E402
from otai.safeio import UnsafeInput, inspect_zip, sanitize_csv_cell  # noqa: E402
from otai.sources import (compare_products, link_advisories,   # noqa: E402
                          provenance_table, publisher_role)
from otai.store import Store                                   # noqa: E402
from otai.topology import load_topology                        # noqa: E402

AS_OF = "2026-09-09"
ASSETS = ROOT / "fixtures" / "assets"
TOPO = ROOT / "fixtures" / "topology" / "purdue-62443-reference.json"
CISA = ROOT / "data" / "csaf" / "cisa" / "2026" / "icsa-26-036-02.json"
CISA_SIEMENS = ROOT / "data" / "csaf" / "cisa" / "2026" / "icsa-26-071-04.json"
SSA = ROOT / "data" / "csaf" / "siemens" / "ssa-452276.json"
OUT = ROOT / "out" / "demo"

_buf = []
_quiet = False


def say(text=""):
    _buf.append(text)
    if not _quiet:
        print(text)


def head(n, title):
    say()
    say("=" * 76)
    say("[%s] %s" % (n, title))
    say("=" * 76)


def need(path, what):
    if not Path(path).exists():
        say("  건너뜀 — %s 이(가) 없습니다. `python scripts/fetch_advisories.py` 를 먼저 실행하세요." % what)
        return False
    return True


# --------------------------------------------------------------------------
def step1_applicability():
    head(1, "적용성 판정 — 정보가 늘면 결론이 바뀐다 (슬라이스 1)")
    adv = load_advisory(CISA)
    say("권고문 %s · %s · 원문 sha256 %s"
        % (adv.advisory_id, adv.title, adv.sha256[:16]))
    say("영향 범위 원문: %r   ← 자유 문자열, 구조화 객체가 아니다" % adv.products[0].version_raw)
    say()

    seq = [
        ("melsec-iqr-family-only", "제품군만 안다 (L1)"),
        ("melsec-iqr-partial", "버전은 알지만 모델이 제품군 수준"),
        ("melsec-iqr-fwunknown", "모델 확정, 버전 미상"),
        ("melsec-iqr-fw48", "버전 48 확보 — 경계 안쪽"),
        ("melsec-iqr-fw49", "버전 49 — 경계 바깥"),
        ("melsec-iqr-patched", "패치 증거까지 확보"),
        ("plc-l2-014", "다른 벤더"),
    ]
    for name, note in seq:
        d = decide_applicability(load_asset(ASSETS / (name + ".json")), adv, as_of=AS_OF)
        say("  %-24s %-24s %-13s  %s"
            % (name, d.status, d.identity_level or "-", note))

    say()
    say("정보 부족 항목은 '다음 최적 질문' 을 돌려준다:")
    d = decide_applicability(load_asset(ASSETS / "melsec-iqr-fwunknown.json"), adv, as_of=AS_OF)
    say("  " + (d.next_best_question or "-"))
    (OUT / "1-decision-card.txt").write_text(render_text(d), encoding="utf-8")


def step2_as_of():
    head(2, "as_of — 과거 시점의 판정을 그대로 재현한다")
    adv = load_advisory(CISA)
    asset = load_asset(ASSETS / "melsec-iqr-fw48.json")
    for as_of in ("2026-08-01", "2026-09-09"):
        d = decide_applicability(asset, adv, as_of=as_of)
        say("  as_of=%s  →  %-24s input_hash=%s" % (as_of, d.status, d.input_hash[:16]))
    say()
    say("  8/20 관측 이전 시점에서는 버전을 몰랐으므로 '정보 부족' 이 정확한 답이다.")


def step3_queue(kev, topo):
    head(3, "행동 큐 — P? 는 '낮은 우선순위' 가 아니라 '막힌 P0/P1' 이다 (슬라이스 2)")
    adv = load_advisory(CISA)
    assets = [load_asset(p) for p in sorted(ASSETS.glob("*.json"))]

    for label, t in (("토폴로지 없음", None), ("토폴로지 있음", topo)):
        items = []
        for a in assets:
            d = decide_applicability(a, adv, as_of=AS_OF)
            if d.status == "no_known_match":
                continue
            items.append(evaluate_priority(d, a, kev=kev, topology=t))
        q = sort_queue(items)
        say()
        say("── %s ──" % label)
        for it in q:
            extra = ""
            if it.bucket == "P?":
                extra = "확정 시 최소 %s" % it.floor_if_confirmed
            elif it.fired_rules:
                extra = "강제규칙 %s" % ",".join(it.fired_rules)
            say("  %-4s %-24s %-24s %s" % (it.bucket, it.asset_id, it.status, extra))
        if t is not None:
            (OUT / "3-queue.txt").write_text(
                render_queue(q, "default", kev.catalog_version if kev else None),
                encoding="utf-8")

    say()
    say("  같은 자산이 P? → P0 로 확정된다. 바뀐 것은 판정이 아니라 **도달성 근거**다.")


def step4_paths(topo, attack):
    head(4, "공격 경로와 차단 후보 (슬라이스 3)")
    say("토폴로지: %s" % topo.provenance.get("basis", ""))
    say("  ** %s" % topo.provenance.get("warning", ""))
    say()
    paths = find_paths(topo, "plc-fw48", as_of=AS_OF)
    say("경로 %d개 (관측 엣지만으로 된 경로가 있어야 도달성이 확정된다)" % len(paths))
    p = paths[0]
    say("  [%s] 확신도 %.2f · %d홉" % (p.status, p.confidence, len(p.hops)))
    for h in p.hops:
        say("      %s" % h.describe())
    say("      가장 약한 엣지: %s" % (p.weakest.key if p.weakest else "-"))

    say()
    say("차단 후보 — 점수가 아니라 정수 두 개로 비교한다:")
    for c in blocking_candidates(topo, ["plc-fw48"], as_of=AS_OF):
        say("  %s" % c.describe())

    blocks = blocking_candidates(topo, ["plc-fw48"], as_of=AS_OF)
    doc = render_html(topo, paths, blocks, as_of=AS_OF,
                      target_label="MELSEC iQ-R (fw48)", attack_catalog=attack)
    (OUT / "4-attack-paths.html").write_text(doc, encoding="utf-8")
    say()
    say("  → out/demo/4-attack-paths.html (외부 자원 0개 · JS 0줄 · 두 번 만들면 바이트 동일)")


def step5_offline():
    head(5, "폐쇄망 왕복과 적대적 입력 방어 (슬라이스 4)")
    work = OUT / "offline"
    if work.exists():
        shutil.rmtree(work)
    key, pub = generate_keypair(work / "keys")

    files = [("csaf/icsa-26-036-02.json", CISA)]
    snap = find_snapshot(ROOT / "data" / "kev")
    if snap:
        files.append(("kev/known_exploited_vulnerabilities.json", snap))
    b1, b2 = work / "k1.zip", work / "k2.zip"
    export_bundle(files, b1, as_of=AS_OF, key_path=key)
    export_bundle(files, b2, as_of=AS_OF, key_path=key)
    say("  번들 생성 · 두 번 만든 결과가 바이트 동일: %s" % (b1.read_bytes() == b2.read_bytes()))

    res = verify_bundle(b1, pub)
    say("  검증: %s (파일 %d개)" % (res.reason, len(res.files)))
    ap = apply_bundle(b1, pub, work / "data")
    say("  적용: %s · current=%s" % (ap.reason, read_current(work / "data")))

    _, attacker_pub = generate_keypair(work / "attacker")
    bad = apply_bundle(b1, attacker_pub, work / "data")
    say("  위조 키로 적용 시도: %s · current 는 그대로 %s"
        % (bad.reason, read_current(work / "data")))

    say()
    say("적대적 입력 (정답이 객관적이라 정확도를 주장할 수 있는 유일한 구간):")
    import zipfile
    evil = work / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../escape.txt", b"x")
    try:
        inspect_zip(evil)
        say("  경로순회: **거부되지 않았다 — 문제**")
    except UnsafeInput as exc:
        say("  경로순회 zip → 거부: %s" % exc)
    payload = "=cmd|' /C calc'!A1"
    say("  CSV 수식 %r → 무해화 %r" % (payload, sanitize_csv_cell(payload)))

    rep = build_report(ROOT / "fixtures" / "csv" / "assets-sample.csv")
    say()
    say("CSV Import (dry-run 이 기본):")
    for line in rep.summary().splitlines():
        say("  " + line)


def step6_sources(kev):
    head(6, "소스 권위와 계보, 정책 거버넌스 (슬라이스 5)")
    if not (CISA_SIEMENS.exists() and SSA.exists()):
        say("  건너뜀 — 연결 쌍 권고문이 없습니다.")
    else:
        advs = [load_advisory(CISA_SIEMENS), load_advisory(SSA)]
        for a in advs:
            role, basis = publisher_role(a)
            say("  %-18s 선언 category=%-12s → 판정 %-12s (%s)"
                % (a.advisory_id, a.publisher_category, role, basis))
        say("  ** 같은 CISA 가 파일마다 다른 category 를 선언한다. 선언 값을 믿지 않는다.")
        g = link_advisories(advs)[0]
        comps = compare_products(g)
        conflicts = sum(1 for c in comps if c.conflicting)
        say()
        say("  CVE %s 로 연결 · 제품 비교 %d건 · 충돌 %d건"
            % (", ".join(g.cves), len(comps), conflicts))
        v = comps[0].views["version_range"]
        say("  현재값 %s ← %s (%s) · 교차 확인 %s"
            % (v.current.value, v.current.source_id, v.current.source_role,
               ", ".join(v.corroborated_by)))
        say("  ** CISA 가 Siemens 문서를 재발행한다 — 흔한 것은 모순이 아니라 일치다.")

    say()
    say("병합 — 과거 판정을 다시 쓰지 않는다:")
    db = OUT / "lineage.db"
    if db.exists():
        db.unlink()
    st = Store(db)
    adv = load_advisory(CISA)
    for n in ("melsec-iqr-fw48", "melsec-iqr-r08pcpu"):
        st.record(decide_applicability(load_asset(ASSETS / (n + ".json")), adv, as_of=AS_OF))
    st.merge_identity("melsec-iqr-r08pcpu", "melsec-iqr-fw48",
                      approver="ot-lead", as_of="2026-09-05", reason="동일 랙 CPU")
    say("  계보: %s" % ", ".join(st.lineage("melsec-iqr-fw48", AS_OF)))
    for r in st.history("melsec-iqr-fw48", include_lineage=True):
        say("    #%d %-24s %-22s %s" % (r["id"], r["asset_id"], r["status"], r["input_hash"][:12]))
    say("  ** 각 행이 원래 asset_id 를 그대로 유지한다.")

    say()
    say("정책 영향 미리보기 — 규칙을 바꾸면 무엇이 뒤집히는가:")
    from dataclasses import replace
    strict = replace(DEFAULT_POLICY, freshness_days=3, basis="엄격 신선도 검토안")
    save_policy(strict, OUT / "candidate-policy.json")
    assets = [load_asset(p) for p in sorted(ASSETS.glob("*.json"))]
    rep = preview(assets, [adv], DEFAULT_POLICY, strict, as_of=AS_OF, kev=kev)
    for line in rep.summary().splitlines():
        say("  " + line)
    st.close()


def main() -> int:
    global _quiet
    ap = argparse.ArgumentParser(description="OT Asset Intelligence 전 과정 시연")
    ap.add_argument("--quiet", action="store_true", help="콘솔 출력 없이 저장만")
    args = ap.parse_args()
    _quiet = args.quiet

    OUT.mkdir(parents=True, exist_ok=True)
    if not need(CISA, "CISA 권고문"):
        return 1
    kev_path = find_snapshot(ROOT / "data" / "kev")
    kev = load_kev(kev_path) if kev_path else None
    topo = load_topology(TOPO)
    bundle = find_bundle(ROOT / "data" / "attack")
    attack = load_attack(bundle) if bundle else None

    say("OT 자산 취약점·공격 경로 관리 플랫폼 — 전 과정 시연")
    say("as_of=%s · KEV=%s · ATT&CK=%s"
        % (AS_OF, kev.catalog_version if kev else "미로드",
           ("v" + attack.version) if attack else "미로드"))

    step1_applicability()
    step2_as_of()
    step3_queue(kev, topo)
    step4_paths(topo, attack)
    step5_offline()
    step6_sources(kev)

    head("끝", "정리")
    say("정보가 늘면서 결론이 움직인다:")
    say("  제품군만 → candidate")
    say("  버전 확보 → affected_confirmed · P?  (도달성 미상)")
    say("  토폴로지 확보 → P0  (H02 발화)")
    say("  차단 적용 → 경로 소멸")
    say("  패치 증거 → fixed · P4")
    say()
    say("주장하는 것: 적용성 판정(권고문 파생 골드셋) · 적대적 입력 거부(정답 객관적)")
    say("주장하지 않는 것: 우선순위 정확도 · 경로 탐지 정확도 (근거가 없다)")

    (OUT / "demo.txt").write_text("\n".join(_buf) + "\n", encoding="utf-8")
    if _quiet:
        print("out/demo/ 에 저장했습니다.")
    else:
        print()
        print("→ out/demo/demo.txt · 3-queue.txt · 4-attack-paths.html 저장 완료")
    return 0


if __name__ == "__main__":
    sys.exit(main())
