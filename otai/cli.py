# -*- coding: utf-8 -*-
"""otai CLI — 슬라이스 1 진입점.

    python -m otai decide --asset A.json --advisory B.json --as-of 2026-09-09
"""
from __future__ import annotations

import argparse
import io
import os
import json
import sys
from pathlib import Path

from .applicability import decide_applicability
from .card import render_text
from .csaf import load_advisory
from .kev import find_snapshot, load_kev
from .model import DEFAULT_FRESHNESS_DAYS, load_asset
from .attack import find_bundle, load_attack
from .bundle import (apply_bundle, export_bundle, generate_keypair,
                     read_current, rollback, verify_bundle)
from .csvimport import apply_report, build_report
from .safeio import UnsafeInput
from .policy import (DEFAULT_POLICY, active_policy, approve as policy_approve,
                     load_policy, preview as policy_preview,
                     rollback as policy_rollback, save_policy)
from .sources import compare_cvss, compare_products, link_advisories, provenance_table
from .paths import blocking_candidates, evaluate_reachability, find_paths
from .priority import LENS_PRESETS, evaluate_priority, sort_queue
from .queue_view import render_queue
from .render import render_html
from .topology import load_topology


# 기준 시점 기본값. **시계를 읽지 않는다** — `otai/` 안에서 wall-clock 을 읽는 순간
# 재현성 게이트가 깨진다 (전용 테스트가 소스를 스캔한다). 데이터를 갱신할 때
# 사람이 의도적으로 올리는 값이다. KEV 스냅샷을 버전으로 고정하는 것과 같다.
#
# 2026-09-11: 권고문 1,304건 · KEV 2026.09.10 기준으로 갱신.
DEFAULT_AS_OF = "2026-09-11"


def _cmd_decide(args) -> int:
    asset = load_asset(args.asset)
    advisory = load_advisory(args.advisory)
    d = decide_applicability(asset, advisory, as_of=args.as_of,
                             freshness_days=args.freshness_days)
    out = d.canonical_json() if args.json else render_text(d)
    sys.stdout.write(out + "\n")
    if args.store:
        from .store import Store
        Store(args.store).record(d)
    return 0


def _max_cvss(advisory, cves) -> float:
    """권고문이 준 CVSS 중 최대값. 없으면 None."""
    want = set(cves)
    best = None
    for v in advisory.vulnerabilities:
        if v.cve and v.cve not in want:
            continue
        for sc in v.scores:
            for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
                node = sc.get(key) or {}
                score = node.get("baseScore")
                if score is not None:
                    best = score if best is None else max(best, score)
    return best


def _cmd_queue(args) -> int:
    kev = None
    snap = args.kev or find_snapshot()
    if snap:
        kev = load_kev(snap)

    topo = load_topology(args.topology) if args.topology else None
    advisories = [load_advisory(p) for p in args.advisory]
    assets = []
    for pattern in args.assets:
        p = Path(pattern)
        assets.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])

    # 규모가 커지면 전부 판정할 수 없다. 가망 없는 쌍은 색인으로 거른다 (ADR-030).
    from .identity import could_match, index_advisory
    indexes = [index_advisory(a) for a in advisories]

    items = []
    for ap in assets:
        asset = load_asset(ap)
        for adv, ix in zip(advisories, indexes):
            if not could_match(asset, ix) and not args.show_all:
                continue          # 건너뛴 쌍은 no_known_match 로 확정이다
            d = decide_applicability(asset, adv, as_of=args.as_of,
                                     freshness_days=args.freshness_days)
            if d.status == "no_known_match" and not args.show_all:
                continue
            items.append(
                evaluate_priority(d, asset, kev=kev,
                                  max_cvss=_max_cvss(adv, d.cves), lens=args.lens,
                                  topology=topo)
            )

    ordered = sort_queue(items)
    if args.json:
        import json as _json
        out = _json.dumps([i.to_dict() for i in ordered], ensure_ascii=False,
                          sort_keys=True, indent=2)
    else:
        out = render_queue(ordered, args.lens, kev.catalog_version if kev else None)
    sys.stdout.write(out + "\n")
    return 0


def _resolve_target(topo, args):
    if args.target in topo.nodes:
        return topo.nodes[args.target]
    node = topo.node_for_asset(args.target)
    if node is None:
        raise SystemExit("토폴로지에서 %r 를 찾지 못했습니다 (노드 id 또는 asset_id)" % args.target)
    return node


def _cmd_paths(args) -> int:
    topo = load_topology(args.topology)
    node = _resolve_target(topo, args)
    paths = find_paths(topo, node.node_id, as_of=args.as_of)
    blocks = blocking_candidates(topo, [node.node_id], as_of=args.as_of, top=args.top)
    reach = evaluate_reachability(topo, node.asset_id, as_of=args.as_of) if node.asset_id else None

    L = []
    L.append("=" * 78)
    L.append("공격 경로  대상=%s  as_of=%s  토폴로지=%s" % (node.node_id, args.as_of, topo.source_path))
    L.append("=" * 78)
    if topo.provenance.get("synthetic"):
        L.append("[합성 토폴로지] %s" % topo.provenance.get("warning", ""))
        L.append("")
    # 레벨이 빈 노드가 있으면 경로 판정이 반쪽이다. 조용히 계산하지 않는다.
    from .topology import unknown_level_nodes
    _need = unknown_level_nodes(topo)
    if _need:
        L.append("[레벨·구역 미상 %d대] 도달성이 확정되지 않습니다 — %s%s"
                 % (len(_need), ", ".join(n.node_id for n in _need[:5]),
                    " 외 %d대" % (len(_need) - 5) if len(_need) > 5 else ""))
        L.append("")
    if reach is not None:
        L.append("도달성: %s — %s" % (reach.verdict.value, reach.reason))
        L.append("")
    L.append("경로 %d개" % len(paths))
    for p in paths[: args.limit]:
        L.append("  [%s] 확신도 %.2f · %d홉  %s" % (p.status, p.confidence, len(p.hops),
                                                 " -> ".join(p.nodes)))
        for h in p.hops:
            L.append("      %s" % h.describe())
        if p.weakest is not None:
            L.append("      가장 약한 엣지: %s" % p.weakest.key)
    if blocks:
        L.append("")
        L.append("차단 후보 (끊기는 공격 경로 / 영향받는 정상 통신)")
        for b in blocks:
            L.append("  %s" % b.describe())
        L.append("  점수가 아니라 정수 두 개로 비교합니다 (설계 원칙 P6).")
    sys.stdout.write("\n".join(L) + "\n")
    return 0


def _cmd_render(args) -> int:
    topo = load_topology(args.topology)
    node = _resolve_target(topo, args)
    paths = find_paths(topo, node.node_id, as_of=args.as_of)
    blocks = blocking_candidates(topo, [node.node_id], as_of=args.as_of, top=args.top)

    catalog = None
    if not args.no_attack:
        bundle = args.attack or find_bundle()
        if bundle:
            catalog = load_attack(bundle)

    doc = render_html(topo, paths, blocks, as_of=args.as_of,
                      target_label=node.label, attack_catalog=catalog)
    Path(args.out).write_text(doc, encoding="utf-8")
    sys.stdout.write("%s 작성 (%d bytes, 경로 %d개)\n"
                     % (args.out, len(doc.encode("utf-8")), len(paths)))
    return 0


def _audit(args, action, **kw):
    """감사 이벤트 (FR-GOV-002). actor 는 인증되지 않은 주장이다 (ADR-019)."""
    if not getattr(args, "store", None):
        return
    from .store import Store
    Store(args.store).log(action, as_of=args.as_of,
                          actor=getattr(args, "actor", "unknown"),
                          actor_authenticated=False, **kw)


def _cmd_keygen(args) -> int:
    key, pub = generate_keypair(args.out)
    sys.stdout.write("비밀키 %s  (저장소에 커밋하지 마세요)\n공개키 %s\n" % (key, pub))
    return 0


def _cmd_bundle_export(args) -> int:
    files = []
    for spec in args.include:
        rel, _, src = spec.partition("=")
        if not src:
            raise SystemExit("--include 형식은 번들내경로=원본파일 입니다: %r" % spec)
        files.append((rel, Path(src)))
    manifest = export_bundle(files, args.out, as_of=args.as_of, key_path=args.key)
    _audit(args, "bundle_exported", subject=str(args.out),
           detail={"files": len(manifest["files"])})
    sys.stdout.write("%s 작성 · 파일 %d개 · sig_alg=%s\n"
                     % (args.out, len(manifest["files"]), manifest["sig_alg"]))
    return 0


def _cmd_bundle_verify(args) -> int:
    res = verify_bundle(args.bundle, args.pub)
    _audit(args, "bundle_verified" if res.ok else "bundle_rejected",
           subject=str(args.bundle), correlation_id=res.manifest_sha256,
           detail={"reason": res.reason})
    sys.stdout.write("%s — %s\n" % ("검증 통과" if res.ok else "거부", res.reason))
    if res.ok:
        sys.stdout.write("번들 id %s · 파일 %d개\n" % (res.bundle_id, len(res.files)))
        for f in res.files:
            sys.stdout.write("  %s  %s\n" % (f["sha256"][:12], f["path"]))
    return 0 if res.ok else 1


def _cmd_bundle_apply(args) -> int:
    res = apply_bundle(args.bundle, args.pub, args.data)
    _audit(args, "bundle_applied" if res.ok else "bundle_rejected",
           subject=res.bundle_id, correlation_id=res.bundle_id,
           detail={"reason": res.reason, "previous": res.previous})
    sys.stdout.write("%s — %s\n" % ("적용" if res.ok else "거부", res.reason))
    if not res.ok:
        sys.stdout.write("current 는 그대로입니다: %s\n" % (res.previous or "없음"))
    return 0 if res.ok else 1


def _cmd_bundle_rollback(args) -> int:
    res = rollback(args.data, args.to)
    _audit(args, "bundle_rolled_back", subject=args.to,
           detail={"reason": res.reason, "previous": res.previous})
    sys.stdout.write("%s — %s\n" % ("롤백" if res.ok else "실패", res.reason))
    return 0 if res.ok else 1


def _cmd_capture(args) -> int:
    """캡처 파일에서 토폴로지를 만든다. **장비에 붙지 않는다** (불변 규칙 6).

    관측된 통신만 담는다 — 캡처는 시간 창이라 안 보인 경로가 없는 것이 아니다.
    Purdue 레벨과 구역은 패킷에 없어 비워 두고, 사람이 채워야 한다.
    """
    from .capture import scan_capture, to_topology

    scan = scan_capture(args.file)
    doc = to_topology(scan)

    sys.stdout.write("캡처 — %s\n" % args.file)
    sys.stdout.write("  원문 해시 %s\n" % scan.sha256)
    sys.stdout.write("  패킷 %d개 · 관측 창 %s ~ %s\n"
                     % (scan.packets, doc["provenance"]["window"][0] or "미상",
                        doc["provenance"]["window"][1] or "미상"))
    for w in scan.warnings:
        sys.stdout.write("  주의: %s\n" % w)
    if scan.counters:
        sys.stdout.write("  못 읽은 패킷: %s\n"
                         % " · ".join("%s %d" % (k, v)
                                      for k, v in sorted(scan.counters.items())))

    sys.stdout.write("\n장비 %d대 · 통신 %d개\n" % (len(doc["nodes"]), len(doc["edges"])))
    for n in doc["nodes"][:40]:
        ev = n.get("evidence") or {}
        bits = []
        if n.get("vendor_hint"):
            bits.append("제조사 %s (MAC 추정)" % n["vendor_hint"])
        if ev.get("type_hint"):
            bits.append("%s 인 듯 — %s" % (ev["type_hint"], ev["type_hint_reason"]))
        if ev.get("mac_ambiguous"):
            bits.append("MAC 여럿 — 제조사 귀속 불가")
        sys.stdout.write("  %-16s %s\n" % (n["node_id"], " · ".join(bits) or "단서 없음"))
    if len(doc["nodes"]) > 40:
        sys.stdout.write("  … 외 %d대\n" % (len(doc["nodes"]) - 40))

    for e in doc["edges"][:40]:
        ev = e["evidence"]
        note = "" if ev["direction_known"] else " · 방향 미상"
        if not e["protocol"] and ev.get("sport_protocol"):
            note += " · 출발지 포트는 %s" % ev["sport_protocol"]
        if ev.get("return_packets"):
            note += " · 응답 %d패킷 포함" % ev["return_packets"]
        sys.stdout.write("  %-15s → %-15s %s:%d (%d패킷)%s\n"
                         % (e["src"], e["dst"], e["protocol"] or "미상", e["port"],
                            ev["packets"], note))
    if len(doc["edges"]) > 40:
        sys.stdout.write("  … 외 %d개\n" % (len(doc["edges"]) - 40))

    sys.stdout.write(
        "\n**관측된 통신만 담았습니다.** 캡처는 시간 창이므로 여기 없는 경로가\n"
        "없다는 뜻이 아닙니다.\n")

    # 무엇을 채워야 하는지 **이름을 대서** 말한다. '사용자가 채운다' 만 쓰고
    # 목록을 안 주면 채울 방법이 없다.
    need = [n["node_id"] for n in doc["nodes"] if n["purdue_level"] is None]
    if need:
        sys.stdout.write(
            "\n다음에 할 일 — 아래 %d대의 **Purdue 레벨과 구역**을 채워 주세요.\n"
            "  채우기 전에는 도달성이 확정되지 않고 H01~H03 이 발화하지 않습니다.\n"
            % len(need))
        for nid in need[:20]:
            sys.stdout.write("    %s\n" % nid)
        if len(need) > 20:
            sys.stdout.write("    … 외 %d대\n" % (len(need) - 20))

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(doc, ensure_ascii=False, indent=1,
                                       sort_keys=True) + "\n", encoding="utf-8")
        _audit(args, "capture_applied", subject=str(args.file),
               detail={"sha256": scan.sha256, "nodes": len(doc["nodes"]),
                       "edges": len(doc["edges"])})
        sys.stdout.write("\n토폴로지 작성: %s\n" % args.out)
    else:
        _audit(args, "capture_scanned", subject=str(args.file),
               detail={"sha256": scan.sha256, "packets": scan.packets,
                       "nodes": len(doc["nodes"]), "edges": len(doc["edges"])})
        sys.stdout.write("\n**아무것도 쓰지 않았습니다.** --out 으로 저장합니다.\n")
    return 0


def _cmd_project(args) -> int:
    """엔지니어링 프로젝트 파일을 읽는다. **장비에 붙지 않는다** (불변 규칙 6).

    권고문에서 만든 식별자 목록과 맞춰본다 — 저쪽 도구의 스키마를 모르기 때문이다.
    기본은 dry-run 이다.
    """
    from .projectfile import build_vocabulary, devices, scan_file, to_asset

    paths = []
    for x in args.advisory:
        paths.extend(sorted(x.rglob("*.json")) if x.is_dir() else [x])
    advisories = []
    for x in paths:
        try:
            advisories.append(load_advisory(x))
        except Exception:
            continue          # CSAF 가 아닌 JSON 이 섞여 있어도 멈추지 않는다
    vocab = build_vocabulary(advisories)
    scan = scan_file(args.file, vocab)
    found = devices(scan)

    sys.stdout.write("프로젝트 파일 — %s\n" % args.file)
    sys.stdout.write("  원문 해시 %s\n" % scan.sha256)
    sys.stdout.write("  권고문 %d건에서 만든 목록: 주문번호 %d · 제품명 %d · 제조사 %d\n"
                     % ((len(advisories),) + vocab.size))
    sys.stdout.write("  읽은 파일 %d개 · 원소 %d개\n" % (scan.members_read, scan.elements))
    for w in scan.warnings:
        sys.stdout.write("  주의: %s\n" % w)
    for r in scan.refused[:10]:
        sys.stdout.write("  안전하지 않아 읽지 않음: %s\n" % r)

    if not found:
        sys.stdout.write("\n아는 제품을 찾지 못했습니다.\n")
        _audit(args, "project_file_scanned", subject=str(args.file),
               detail={"sha256": scan.sha256, "devices": 0})
        return 0

    sys.stdout.write("\n알아본 장비 %d대\n" % len(found))
    for d in found:
        ver = ("여럿(%s) — 고르지 않음" % ", ".join(v.value for v in d.versions)
               if d.ambiguous else (d.version or "미상"))
        sys.stdout.write("  %-22s %-18s 펌웨어(설정값)=%s\n"
                         % (d.order_number, d.vendor or "미상", ver))
        sys.stdout.write("      ← %s%s\n" % (d.member and (d.member + "#") or "", d.path))

    # 등급만 낮추고 말하지 않으면 아무도 모른다 (ADR-038)
    sys.stdout.write(
        "\n펌웨어는 **설정값**입니다. 장비에서 읽은 값이 아니므로 '확인'으로 쓰지 "
        "않고,\n실제 버전을 확인할 때까지 '가능성 높음' 또는 '정보 부족'으로 둡니다.\n")

    if args.apply:
        if args.out is None:
            sys.stdout.write("\n--apply 에는 --out 이 필요합니다.\n")
            return 2
        args.out.mkdir(parents=True, exist_ok=True)
        n = 0
        for d in found:
            body = to_asset(d, scan)
            path = args.out / ("%s.json" % d.suggested_asset_id())
            if path.exists():
                sys.stdout.write("  이미 있음: %s\n" % path.name)
                continue
            path.write_text(json.dumps(body, ensure_ascii=False, indent=1,
                                       sort_keys=True) + "\n", encoding="utf-8")
            n += 1
        _audit(args, "project_file_applied", subject=str(args.file),
               detail={"sha256": scan.sha256, "created": n})
        sys.stdout.write("\n자산 파일 %d개 작성\n" % n)
    else:
        _audit(args, "project_file_scanned", subject=str(args.file),
               detail={"sha256": scan.sha256, "devices": len(found)})
        sys.stdout.write("\n**dry-run — 아무것도 쓰지 않았습니다.** --apply 로 씁니다.\n")
    return 0


def _cmd_import(args) -> int:
    mapping = None
    if args.mapping:
        mapping = json.loads(Path(args.mapping).read_text(encoding="utf-8"))
    existing = []
    if args.out.exists():
        existing = [p.stem for p in args.out.glob("*.json")]
    try:
        rep = build_report(args.csv, mapping, existing_ids=existing)
    except UnsafeInput as exc:
        sys.stdout.write("거부: %s\n" % exc)
        _audit(args, "import_dry_run", subject=str(args.csv),
               detail={"rejected": str(exc)})
        return 1

    sys.stdout.write("CSV Import — %s\n" % args.csv)
    sys.stdout.write("매핑: %s\n" % json.dumps(rep.mapping, ensure_ascii=False))
    for r in rep.results:
        if r.action != "create":
            sys.stdout.write("  %d행 %s: %s\n" % (r.line, r.action, r.message))
    if args.apply:
        written = apply_report(rep, args.out)
        _audit(args, "import_applied", subject=str(args.csv),
               detail={"created": len(written)})
        sys.stdout.write("자산 파일 %d개 작성\n" % len(written))
    else:
        _audit(args, "import_dry_run", subject=str(args.csv),
               detail={"rows": rep.rows, "created": rep.created})
    sys.stdout.write(rep.summary() + "\n")
    return 0


def _cmd_audit(args) -> int:
    from .store import Store
    rows = Store(args.store).events(args.action)
    sys.stdout.write("감사 이벤트 %d건\n" % len(rows))
    for r in rows:
        sys.stdout.write("  #%d %s  %-18s actor=%s(인증=%s)  %s\n"
                         % (r["id"], r["as_of"], r["action"], r["actor"],
                            "예" if r["actor_authenticated"] else "아니오",
                            r["subject"] or ""))
    sys.stdout.write("\n인증되지 않은 actor 는 '주장' 이지 사실이 아닙니다 (ADR-019).\n")
    return 0


def _load_assets(patterns):
    out = []
    for pattern in patterns:
        p = Path(pattern)
        out.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
    return [load_asset(p) for p in out]


def _cmd_sources(args) -> int:
    missing = [str(p) for p in args.advisory if not Path(p).exists()]
    if missing:
        raise SystemExit(
            "권고문 파일이 없습니다: %s\n  저장소에는 골드셋 2건만 들어 있습니다. "
            "나머지는  python scripts/fetch_advisories.py  로 받습니다."
            % ", ".join(missing))
    advs = [load_advisory(p) for p in args.advisory]
    links = link_advisories(advs)
    L = []
    for g in links:
        L.append("=" * 78)
        L.append("연결 그룹 · CVE %s" % ", ".join(g.cves))
        L.append("=" * 78)
        L.append("출처 (시점 차이는 충돌이 아니라 출처 정보입니다)")
        for r in provenance_table(g):
            L.append("  %-18s %-24s role=%-11s (%s)"
                     % (r["advisory_id"], r["publisher"], r["role"], r["role_basis"]))
            L.append("      선언 category=%-12s released=%s  sha256=%s"
                     % (r["declared_category"], (r["released_at"] or "-")[:10],
                        r["sha256"][:12]))
        comps = compare_products(g)
        conflicting = [c for c in comps if c.conflicting]
        L.append("")
        L.append("제품 비교 %d건 · 충돌 %d건" % (len(comps), len(conflicting)))
        for c in (conflicting or comps)[: args.limit]:
            v = c.views["version_range"]
            L.append("  %s" % c.key)
            L.append("      현재값 %s  ← %s (%s)"
                     % (v.current.value, v.current.source_id, v.current.source_role))
            if v.conflicting:
                for d in v.dissenting:
                    L.append("      반대 주장 %s  ← %s (보존됨)" % (d.value, d.source_id))
            else:
                L.append("      교차 확인 %s" % ", ".join(v.corroborated_by))
        cv = compare_cvss(g)
        if cv is not None:
            L.append("  CVSS: %s ← %s%s"
                     % (cv.current.value, cv.current.source_id,
                        "  **충돌**" if cv.conflicting else ""))
    sys.stdout.write("\n".join(L) + "\n")
    return 0


def _cmd_merge(args) -> int:
    from .store import Store
    st = Store(args.store)
    st.merge_identity(args.source, args.into, approver=args.approver,
                      as_of=args.as_of, reason=args.reason)
    sys.stdout.write("병합 기록: %s → %s (승인 %s)\n" % (args.source, args.into, args.approver))
    sys.stdout.write("과거 판정은 다시 쓰지 않습니다. 계보: %s\n"
                     % ", ".join(st.lineage(args.into, args.as_of)))
    return 0


def _cmd_split(args) -> int:
    from .store import Store
    st = Store(args.store)
    st.split_identity(args.source, args.into, approver=args.approver,
                      as_of=args.as_of, reason=args.reason)
    sys.stdout.write("분리 기록: %s → %s (승인 %s)\n" % (args.source, args.into, args.approver))
    return 0


def _cmd_lineage(args) -> int:
    from .store import Store
    st = Store(args.store)
    ids = st.lineage(args.asset, args.as_of)
    sys.stdout.write("계보 (as_of %s): %s\n" % (args.as_of, ", ".join(ids)))
    rows = st.history(args.asset, include_lineage=True, as_of=args.as_of)
    sys.stdout.write("판정 이력 %d건\n" % len(rows))
    for r in rows:
        sys.stdout.write("  #%d %s  %-24s %-24s %s\n"
                         % (r["id"], r["as_of"], r["asset_id"], r["status"],
                            r["input_hash"][:12]))
    return 0


def _cmd_policy(args) -> int:
    if args.action == "show":
        pol = active_policy(args.data) if args.data else DEFAULT_POLICY
        sys.stdout.write("활성 정책 %s\n" % pol.version)
        sys.stdout.write(save_policy.__doc__ or "")
        sys.stdout.write(json.dumps(json.loads(pol.canonical()), ensure_ascii=False,
                                    indent=2, sort_keys=True) + "\n")
        return 0

    candidate = load_policy(args.candidate) if args.candidate else DEFAULT_POLICY
    current = active_policy(args.data) if args.data else DEFAULT_POLICY

    if args.action == "preview":
        kev = None
        snap = find_snapshot()
        if snap:
            kev = load_kev(snap)
        topo = load_topology(args.topology) if args.topology else None
        rep = policy_preview(_load_assets(args.assets),
                             [load_advisory(p) for p in args.advisory],
                             current, candidate, as_of=args.as_of, kev=kev, topology=topo)
        sys.stdout.write(rep.summary() + "\n")
        return 0

    if args.action == "approve":
        version = policy_approve(candidate, args.data)
        _audit(args, "policy_approved", subject=version,
               detail={"approved_by": candidate.approved_by})
        sys.stdout.write("승인: %s\n" % version)
        return 0

    if args.action == "rollback":
        ok = policy_rollback(args.data, args.to)
        _audit(args, "policy_rolled_back", subject=args.to, detail={"ok": ok})
        sys.stdout.write("%s: %s\n" % ("롤백" if ok else "실패", args.to))
        return 0 if ok else 1
    return 1


def _cmd_ask(args) -> int:
    from .server import serve
    advs = []
    for pat in args.advisory:
        pp = Path(pat)
        advs.extend(sorted(pp.rglob("*.json")) if pp.is_dir() else [pp])
    if not advs:
        raise SystemExit("권고문을 찾지 못했습니다: %s" % args.advisory)
    return serve(advs, args.as_of, port=args.port, topology=args.topology,
                 outdir=args.out, open_browser=not args.no_open)


PG_DOWN = """PostgreSQL 에 연결하지 못했습니다: %s
  %s

기본 저장소는 PostgreSQL 입니다 (표 27). 조용히 SQLite 로 내려가지 않습니다 —
그러면 감사 기록이 두 저장소로 갈라져 계보가 끊깁니다 (불변 규칙 5).

  띄우기:  .toolchain/pgsql/bin/pg_ctl.exe -D .toolchain/pgdata \\
             -o "-p 5433 -h 127.0.0.1" -l .toolchain/pg.log start
  SQLite 로 쓰려면 명시적으로:  python -m otai web --db data/otai.db"""


def _cmd_web(args) -> int:
    """표 27 의 웹앱 — FastAPI + React/TypeScript(Vite) + Cytoscape.js."""
    try:
        import uvicorn
    except ImportError:
        raise SystemExit("웹앱에는 fastapi·uvicorn 이 필요합니다:  python -m pip install -e \".[web]\"")
    try:
        from .api import DIST, build_app
    except ImportError as exc:                    # fastapi 가 없다
        raise SystemExit(
            "웹앱에는 fastapi 가 필요합니다:  python -m pip install -e \".[web]\"\n"
            "  (%s)" % exc)
    from .db import Conn, is_postgres
    advs = []
    for pat in args.advisory:
        pp = Path(pat)
        advs.extend(sorted(pp.rglob("*.json")) if pp.is_dir() else [pp])
    if not advs:
        raise SystemExit("권고문을 찾지 못했습니다: %s" % args.advisory)

    # 연결 실패는 여기서 크게 터뜨린다. build_app 안에서 터지면 메시지가 묻힌다.
    if is_postgres(args.db):
        try:
            Conn(args.db).close()
        except Exception as exc:
            raise SystemExit(PG_DOWN % (args.db, exc))

    # 적재가 먼저다. build_app 이 곧바로 전수 계산을 시작하므로, 뒤에 넣으면
    # 빈 저장소를 대상으로 계산하고 큐가 비어 버린다.
    if args.seed:
        from .repo import Repo
        r = Repo(args.db)
        n = sum(r.import_dir(d, args.as_of) for d in args.seed)
        r.close()
        sys.stdout.write("자산 %d건을 %s 에서 불러왔습니다\n"
                         % (n, ", ".join(str(d) for d in args.seed)))
        sys.stdout.flush()

    app = build_app(db=args.db, advisory_paths=advs, as_of=args.as_of,
                    topology=args.topology, kev_path=args.kev)

    url = "http://127.0.0.1:%d/" % args.port
    sys.stdout.write("웹앱: %s   (API 문서 %sapi/docs)\n" % (url, url))
    sys.stdout.write("  저장소 %s\n" % args.db)
    if not DIST.exists():
        sys.stdout.write("  web/dist 가 없어 UMD 판으로 뜹니다."
                         "  빌드:  cd frontend && npm run build\n")
    sys.stdout.write("  127.0.0.1 에만 열려 있습니다. 인증이 없으므로 외부에 노출하지 마세요.\n")
    sys.stdout.flush()
    if not args.no_open:
        import threading, webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="otai", description="OT 자산 적용성 판정 커널")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("decide", help="자산 1건 + 권고 1건 → 적용성 판정 카드")
    d.add_argument("--asset", required=True, type=Path, help="자산 JSON 경로")
    d.add_argument("--advisory", required=True, type=Path, help="CSAF 2.0 권고 JSON 경로")
    d.add_argument("--as-of", required=True, dest="as_of",
                   help="판정 기준 시점 (YYYY-MM-DD). 이후 관측은 사용하지 않는다")
    d.add_argument("--json", action="store_true", help="정규 JSON 으로 출력")
    d.add_argument("--store", type=Path, default=None,
                   help="판정을 append-only 저장소에 기록 (SQLite 경로)")
    d.add_argument("--freshness-days", type=int, default=DEFAULT_FRESHNESS_DAYS,
                   dest="freshness_days", help="확정 상태에 요구할 관측 신선도(일)")
    d.set_defaults(func=_cmd_decide)

    q = sub.add_parser("queue", help="행동 큐 — P0 → P? → P1 → P2 → P3 → P4")
    q.add_argument("--assets", required=True, nargs="+", type=Path,
                   help="자산 JSON 파일 또는 디렉터리")
    q.add_argument("--advisory", required=True, nargs="+", type=Path,
                   help="CSAF 2.0 권고 JSON (여러 개 가능)")
    q.add_argument("--as-of", required=True, dest="as_of", help="판정 기준 시점")
    q.add_argument("--lens", default="default", choices=sorted(LENS_PRESETS),
                   help="사용자 렌즈 — 같은 버킷 안의 정렬만 바꾼다")
    q.add_argument("--kev", type=Path, default=None,
                   help="KEV 스냅샷 경로 (기본: data/kev 의 최신)")
    q.add_argument("--json", action="store_true")
    q.add_argument("--show-all", action="store_true",
                   help="no_known_match 항목도 표시")
    q.add_argument("--freshness-days", type=int, default=DEFAULT_FRESHNESS_DAYS,
                   dest="freshness_days")
    q.add_argument("--topology", type=Path, default=None,
                   help="토폴로지 JSON — 있으면 P? 가 실제 등급으로 확정된다")
    q.set_defaults(func=_cmd_queue)

    pa = sub.add_parser("paths", help="공격 경로 탐색과 차단 후보")
    pa.add_argument("--topology", required=True, type=Path)
    pa.add_argument("--target", required=True, help="노드 id 또는 asset_id")
    pa.add_argument("--as-of", required=True, dest="as_of")
    pa.add_argument("--limit", type=int, default=3, help="출력할 경로 수")
    pa.add_argument("--top", type=int, default=3, help="차단 후보 수")
    pa.set_defaults(func=_cmd_paths)

    r = sub.add_parser("render", help="결정적 SVG 를 담은 자기완결 HTML 생성")
    r.add_argument("--topology", required=True, type=Path)
    r.add_argument("--target", required=True)
    r.add_argument("--as-of", required=True, dest="as_of")
    r.add_argument("--out", required=True, type=Path)
    r.add_argument("--top", type=int, default=3)
    r.add_argument("--attack", type=Path, default=None, help="ATT&CK ICS STIX 번들")
    r.add_argument("--no-attack", action="store_true")
    r.set_defaults(func=_cmd_render)

    k = sub.add_parser("keygen", help="번들 서명 키쌍 생성 (Ed25519)")
    k.add_argument("--out", required=True, type=Path)
    k.set_defaults(func=_cmd_keygen)

    def _audited(sp):
        sp.add_argument("--store", type=Path, default=None, help="감사 로그 SQLite")
        sp.add_argument("--actor", default="unknown",
                        help="행위자 (인증되지 않은 주장으로 기록된다)")
        return sp

    be = _audited(sub.add_parser("bundle-export", help="서명된 오프라인 번들 생성"))
    be.add_argument("--include", required=True, nargs="+",
                    help="번들내경로=원본파일 (여러 개 가능)")
    be.add_argument("--out", required=True, type=Path)
    be.add_argument("--key", required=True, type=Path)
    be.add_argument("--as-of", required=True, dest="as_of")
    be.set_defaults(func=_cmd_bundle_export)

    bv = _audited(sub.add_parser("bundle-verify", help="서명·해시·미신고 멤버 검증"))
    bv.add_argument("--bundle", required=True, type=Path)
    bv.add_argument("--pub", required=True, type=Path)
    bv.add_argument("--as-of", required=True, dest="as_of")
    bv.set_defaults(func=_cmd_bundle_verify)

    ba = _audited(sub.add_parser("bundle-apply", help="검증 후 원자적 적용"))
    ba.add_argument("--bundle", required=True, type=Path)
    ba.add_argument("--pub", required=True, type=Path)
    ba.add_argument("--data", required=True, type=Path)
    ba.add_argument("--as-of", required=True, dest="as_of")
    ba.set_defaults(func=_cmd_bundle_apply)

    br = _audited(sub.add_parser("bundle-rollback", help="이전 번들로 되돌리기"))
    br.add_argument("--data", required=True, type=Path)
    br.add_argument("--to", required=True)
    br.add_argument("--as-of", required=True, dest="as_of")
    br.set_defaults(func=_cmd_bundle_rollback)

    cap = _audited(sub.add_parser(
        "capture", help="캡처(pcap·pcapng)에서 토폴로지 만들기 (기본 dry-run)"))
    cap.add_argument("--file", required=True, type=Path, help="pcap 또는 pcapng")
    cap.add_argument("--out", type=Path, default=None, help="토폴로지 JSON 출력 경로")
    cap.add_argument("--as-of", required=True, dest="as_of")
    cap.set_defaults(func=_cmd_capture)

    pf = _audited(sub.add_parser(
        "project", help="엔지니어링 프로젝트 파일에서 자산 읽기 (기본 dry-run)"))
    pf.add_argument("--file", required=True, type=Path,
                    help="AutomationML(.aml)·XML·압축 프로젝트")
    pf.add_argument("--advisory", nargs="+", required=True, type=Path,
                    help="식별자 목록을 만들 권고문 (파일 또는 디렉터리)")
    pf.add_argument("--out", type=Path, default=None, help="자산 JSON 출력 디렉터리")
    pf.add_argument("--apply", action="store_true", help="실제로 쓴다 (기본은 dry-run)")
    pf.add_argument("--as-of", required=True, dest="as_of")
    pf.set_defaults(func=_cmd_project)

    im = _audited(sub.add_parser("import", help="CSV 자산 Import (기본 dry-run)"))
    im.add_argument("--csv", required=True, type=Path)
    im.add_argument("--mapping", type=Path, default=None, help="헤더→필드 매핑 JSON")
    im.add_argument("--out", required=True, type=Path, help="자산 JSON 출력 디렉터리")
    im.add_argument("--apply", action="store_true", help="실제로 쓴다 (기본은 dry-run)")
    im.add_argument("--as-of", required=True, dest="as_of")
    im.set_defaults(func=_cmd_import)

    au = sub.add_parser("audit", help="감사 이벤트 조회")
    au.add_argument("--store", required=True, type=Path)
    au.add_argument("--action", default=None)
    au.set_defaults(func=_cmd_audit)

    so = sub.add_parser("sources", help="다중 소스 비교 — 필드별 권위와 충돌 보존")
    so.add_argument("--advisory", required=True, nargs="+", type=Path)
    so.add_argument("--limit", type=int, default=3)
    so.set_defaults(func=_cmd_sources)

    mg = sub.add_parser("merge", help="자산 병합 (과거 판정은 보존)")
    mg.add_argument("--actor", default="unknown")
    mg.add_argument("--source", required=True)
    mg.add_argument("--into", required=True)
    mg.add_argument("--approver", required=True)
    mg.add_argument("--reason", required=True)
    mg.add_argument("--as-of", required=True, dest="as_of")
    mg.add_argument("--store", required=True, type=Path)
    mg.set_defaults(func=_cmd_merge)

    sp = sub.add_parser("split", help="자산 분리")
    sp.add_argument("--actor", default="unknown")
    sp.add_argument("--source", required=True)
    sp.add_argument("--into", required=True)
    sp.add_argument("--approver", required=True)
    sp.add_argument("--reason", required=True)
    sp.add_argument("--as-of", required=True, dest="as_of")
    sp.add_argument("--store", required=True, type=Path)
    sp.set_defaults(func=_cmd_split)

    ln = sub.add_parser("lineage", help="병합·분리 계보와 합친 판정 이력")
    ln.add_argument("--asset", required=True)
    ln.add_argument("--store", required=True, type=Path)
    ln.add_argument("--as-of", default="9999-12-31", dest="as_of")
    ln.set_defaults(func=_cmd_lineage)

    po = sub.add_parser("policy", help="정책 조회·미리보기·승인·롤백")
    po.add_argument("--actor", default="unknown")
    po.add_argument("--store", type=Path, default=None, help="감사 로그 SQLite")
    po.add_argument("action", choices=["show", "preview", "approve", "rollback"])
    po.add_argument("--candidate", type=Path, default=None, help="후보 정책 JSON")
    po.add_argument("--data", type=Path, default=None, help="정책 저장 디렉터리")
    po.add_argument("--to", default=None, help="롤백 대상 정책 id")
    po.add_argument("--assets", nargs="+", type=Path, default=[])
    po.add_argument("--advisory", nargs="+", type=Path, default=[])
    po.add_argument("--topology", type=Path, default=None)
    po.add_argument("--as-of", default=DEFAULT_AS_OF, dest="as_of")
    po.set_defaults(func=_cmd_policy)

    ak = sub.add_parser("ask", help="장치를 직접 입력하고 판정받기 (로컬 서버)")
    ak.add_argument("--advisory", nargs="+", type=Path, default=[Path("data/csaf")],
                    help="권고문 파일 또는 디렉터리 (기본: data/csaf 전체)")
    ak.add_argument("--as-of", default=DEFAULT_AS_OF, dest="as_of")
    ak.add_argument("--port", type=int, default=8765)
    ak.add_argument("--topology", type=Path, default=None)
    ak.add_argument("--out", type=Path, default=Path("fixtures/assets"),
                    help="자산 파일 저장 위치")
    ak.add_argument("--no-open", action="store_true", help="브라우저를 자동으로 열지 않음")
    ak.set_defaults(func=_cmd_ask)

    w = sub.add_parser("web", help="웹앱 실행 (표 25 화면 · 표 29 API)")
    w.add_argument("--advisory", nargs="+", type=Path, default=[Path("data/csaf")])
    # DSN 은 문자열로 둔다. Path 로 받으면 Windows 에서
    # `postgresql://…` 이 `postgresql:\…` 로 바뀌어 조용히 SQLite 파일이 만들어진다.
    # 기본값은 **개발용**이다 (비밀번호 otai). 운영에서는 OTAI_DB 환경변수로 덮어쓴다 —
    # 소스에 박힌 자격 증명을 그대로 쓰지 않는다.
    w.add_argument("--db",
                   default=os.environ.get("OTAI_DB",
                                          "postgresql://otai:otai@127.0.0.1:5433/otai"),
                   help="PostgreSQL DSN (기본) 또는 SQLite 파일 경로")
    w.add_argument("--as-of", default=DEFAULT_AS_OF, dest="as_of")
    w.add_argument("--port", type=int, default=8000)
    w.add_argument("--topology", type=Path,
                   default=Path("fixtures/topology/purdue-62443-reference.json"))
    w.add_argument("--kev", type=Path, default=None)
    w.add_argument("--seed", type=Path, nargs="+", default=None,
                   help="이 디렉터리들의 자산 JSON 을 처음에 불러온다")
    w.add_argument("--no-open", action="store_true")
    w.set_defaults(func=_cmd_web)
    return p


def main(argv=None) -> int:
    # 윈도우 콘솔에서도 한국어와 ∈/∉ 가 깨지지 않도록 UTF-8 로 고정
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")
    args = build_parser().parse_args(argv)
    return args.func(args)
