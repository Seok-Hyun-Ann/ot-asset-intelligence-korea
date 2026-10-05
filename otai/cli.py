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
from .safeio import UnsafeInput, bounded_json_load
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

    pol = _policy(args)          # 승인된 정책을 본다 — 웹앱과 같아야 한다
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
                                  topology=topo, policy=pol)
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
        L.append("도달성: %s — %s" % (reach.verdict.ko, reach.reason))
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


def _policy(args):
    """승인된 정책을 읽는다. **CLI 와 웹이 같은 정책을 봐야 한다.**

    감사에서 나온 것: `queue` 와 `decide` 가 `policy=` 를 아예 넘기지 않아
    `DEFAULT_POLICY` 로 판정했다. 웹앱만 `active_policy()` 를 읽었으므로 **같은
    자산이 CLI 와 화면에서 다른 등급**으로 나올 수 있었다. 정책 파일을 고치고
    "왜 안 변하지" 로 반나절 태울 자리다.
    """
    data = getattr(args, "data", None)
    if data:
        return active_policy(Path(data))
    default = Path("data")
    return active_policy(default) if default.exists() else DEFAULT_POLICY


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


def _cmd_zeek(args) -> int:
    """Zeek / ICSNPP 로그에서 토폴로지와 관측 식별을 만든다 (ADR-051).

    **장비에 접속하지 않는다.** 이미 떠 있는 센서가 남긴 로그를 읽을 뿐이다.
    """
    from .zeeklog import identity_proposals, scan_logs, to_topology

    scan = scan_logs(args.logs)
    doc = to_topology(scan)
    if args.zones:
        from .zonemap import apply_zonemap, load_zonemap
        zres = apply_zonemap(doc, load_zonemap(args.zones))
        sys.stdout.write("구역 선언 — %d대에 레벨·구역을 채웠습니다 "
                         "(**선언은 관측이 아닙니다**)\n" % zres.declared)

    sys.stdout.write("Zeek 로그 — %s\n" % (args.logs if isinstance(args.logs, (str, Path))
                                          else ", ".join(str(p) for p in args.logs)))
    for name, n in sorted(scan.logs_read.items()):
        sys.stdout.write("  %-26s %8d행\n" % (name + ".log", n))
    if scan.skipped_logs:
        sys.stdout.write("  읽지 않은 로그 %d개 — 열 이름을 짐작하지 않습니다: %s%s\n"
                         % (len(scan.skipped_logs),
                            ", ".join(scan.skipped_logs[:5]),
                            " 외" if len(scan.skipped_logs) > 5 else ""))
    w0, w1 = scan.window
    sys.stdout.write("  관측 창 %s ~ %s\n" % (w0 or "미상", w1 or "미상"))
    for k, v in sorted(scan.counters.items()):
        sys.stdout.write("  %s: %d\n" % (k, v))

    sys.stdout.write("\n장비 %d대 · 통신 %d개\n"
                     % (len(doc["nodes"]), len(doc["edges"])))
    for n in doc["nodes"][:30]:
        ev = n.get("evidence") or {}
        bits = []
        if ev.get("identity_vendor") or ev.get("identity_product"):
            bits.append("%s %s" % (ev.get("identity_vendor") or "",
                                   ev.get("identity_product") or ""))
        if ev.get("identity_revision"):
            bits.append("리비전 %s" % ev["identity_revision"])
        if ev.get("type_hint"):
            bits.append("%s 인 듯 — %s" % (ev["type_hint"], ev["type_hint_reason"]))
        sys.stdout.write("  %-16s %s\n" % (n["node_id"], " · ".join(bits).strip()))

    if scan.identities:
        sys.stdout.write("\n관측에서 나온 식별 %d건 — **MAC OUI 추측과 다른 급입니다**\n"
                         % len(scan.identities))
        for ip, i in sorted(scan.identities.items()):
            sys.stdout.write("  %-16s %s\n" % (ip, " · ".join(filter(None, [
                i.vendor, i.product,
                "코드 %s" % i.product_code if i.product_code else None,
                "리비전 %s" % i.revision if i.revision else None,
                "S/N %s" % i.serial if i.serial else None,
                "식별 수준 힌트 %s" % i.level_hint, "출처 %s.log" % i.source_log]))))
        sys.stdout.write("  **자산을 새로 만들지 않습니다** — 토폴로지가 그 IP 를 "
                         "자산으로 선언했을 때만 붙일 후보로 올립니다 (ADR-042).\n")

    if scan.control_events:
        sys.stdout.write("\n관측된 제어 행위 %d건 — 포트가 열렸다는 추론이 아니라 "
                         "**일어난 일**입니다\n" % len(scan.control_events))
        for c in scan.control_events[:15]:
            sys.stdout.write("  [%s] %s → %s  %s\n"
                             % (c.kind, c.src, c.dst, c.detail))
        if len(scan.control_events) > 15:
            sys.stdout.write("  … 외 %d건\n" % (len(scan.control_events) - 15))

    sys.stdout.write("\n**로그도 시간 창입니다.** 여기 없는 경로가 없다는 뜻이 "
                     "아니고,\n도달성은 FALSE 가 아니라 미상으로 남습니다 "
                     "(ADR-048).\n")
    need = [n["node_id"] for n in doc["nodes"] if n["purdue_level"] is None]
    if need and not args.zones:
        sys.stdout.write("\n다음에 할 일 — %d대의 Purdue 레벨·구역을 채워 주세요 "
                         "(`--zones`).\n" % len(need))

    if args.assets:
        from .topology import load_topology as _lt
        props, unlinked = identity_proposals(scan, _lt(args.assets))
        sys.stdout.write("\n자산에 붙일 식별 후보 — 토폴로지가 선언한 것만\n")
        for p in props:
            sys.stdout.write("  %s ← %s  %s %s\n"
                             % (p["asset_id"], p["ip"], p["vendor"] or "",
                                p["product"] or ""))
        if unlinked:
            sys.stdout.write("  어느 자산인지 모르는 IP %d개 — 토폴로지에 "
                             "asset_id 를 선언하면 붙습니다\n" % len(unlinked))

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(doc, ensure_ascii=False, indent=1,
                                  sort_keys=True) + "\n", encoding="utf-8")
        sys.stdout.write("\n토폴로지 작성: %s\n" % out)
    _audit(args, "zeek_logs_read",
           subject=str(args.out or args.logs),
           detail={"logs": dict(sorted(scan.logs_read.items())),
                   "rows": scan.rows, "window": list(scan.window),
                   "identities": len(scan.identities),
                   "control_events": len(scan.control_events)})
    return 0


def _cmd_topology(args) -> int:
    """자산대장의 `구역` 으로 토폴로지 골격을 만든다 (ADR-050).

    **노드가 생기게 하는 것**이 목적이다. 자산이 그래프에 없으면 H01~H03 이
    "이 자산이 토폴로지에 없습니다" 로 막혀 전부 `P?` 가 된다.
    """
    from .site import from_assets, load_site, template

    bodies = []
    for pattern in args.assets:
        p = Path(pattern)
        for q in (sorted(p.glob("*.json")) if p.is_dir() else [p]):
            bodies.append(bounded_json_load(q))
    if not bodies:
        sys.stderr.write("자산 파일을 찾지 못했습니다: %s\n" % args.assets)
        return 2

    if args.site_template:
        Path(args.site_template).write_text(
            json.dumps(template(bodies), ensure_ascii=False, indent=1) + "\n",
            encoding="utf-8")
        sys.stdout.write(
            "사이트 프로파일 서식: %s\n"
            "  구역마다 Purdue 레벨·안전 중요도를 적고, 아는 연결을 conduits 에 "
            "넣은 뒤\n  `--site` 로 주세요.\n" % args.site_template)
        if not args.site:
            return 0

    if not args.site:
        sys.stderr.write(
            "--site 가 필요합니다. 먼저 `--site-template site.json` 으로 서식을 "
            "받아 채워 주세요.\n")
        return 2

    site = load_site(args.site)
    doc, res = from_assets(bodies, site)

    sys.stdout.write("토폴로지 골격 — 사이트 '%s'\n" % site.name)
    sys.stdout.write("  자산 %d대를 구역 %d개에 넣었습니다 · 구역 간 연결 %d개\n"
                     % (res.assets_placed, len(res.zones_used),
                        sum(1 for e in doc["edges"]
                            if e["src"].startswith("zone:")
                            and e["dst"].startswith("zone:"))))
    entries = [n["node_id"] for n in doc["nodes"] if n.get("is_entry_point")]
    if entries:
        sys.stdout.write("  진입점 %d개: %s\n"
                         % (len(entries), ", ".join(entries[:4])))
    else:
        sys.stdout.write("  **진입점이 없습니다** — 도달성은 미상으로 남습니다. "
                         "'닿지 않는다' 가 아닙니다 (ADR-045).\n")

    sys.stdout.write("\n  만들어진 엣지는 `inferred`·`unknown` 입니다 — "
                     "**관측이 아닙니다.**\n"
                     "  그래서 이 골격만으로 도달성이 확정되지 않습니다. 눈으로 "
                     "확인한 구간을\n  사이트 프로파일에서 \"status\": "
                     "\"observed\" 로 올려 주세요.\n")

    if res.undeclared_zones:
        sys.stdout.write("\n선언되지 않은 구역 — 이 설비는 그래프에 넣지 "
                         "않았습니다\n")
        for name, n in sorted(res.undeclared_zones.items(), key=lambda kv: -kv[1]):
            sys.stdout.write("    %s  설비 %d대\n" % (name, n))
        sys.stdout.write("  프로파일의 zones 에 추가해 주세요.\n")
    if res.without_zone:
        sys.stdout.write("\n구역이 비어 있는 설비 %d대 — 대장의 '구역' 열을 "
                         "채워 주세요\n" % len(res.without_zone))
        for aid in res.without_zone[:10]:
            sys.stdout.write("    %s\n" % aid)
    if res.levels_missing:
        sys.stdout.write("\nPurdue 레벨이 비어 있는 구역: %s\n"
                         "  레벨이 미상이면 H03(외부 상위 Zone)이 발화하지 "
                         "않습니다.\n" % ", ".join(res.levels_missing))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True)
                   + "\n", encoding="utf-8")
    sys.stdout.write("\n토폴로지 작성: %s  (노드 %d · 엣지 %d)\n"
                     % (out, len(doc["nodes"]), len(doc["edges"])))
    _audit(args, "topology_built", subject=str(out),
           detail={"site": site.name, "site_sha256": site.sha256,
                   "assets": res.assets_placed, "zones": len(res.zones_used),
                   "undeclared_zones": sorted(res.undeclared_zones)})
    return 0


def _cmd_report(args) -> int:
    """보고서를 낸다 — 엑셀 · 인쇄용 HTML · CSV (ADR-049).

    `queue` 와 **같은 파이프라인**을 쓴다. 보고서가 따로 계산하면 화면과 다른 수를
    말하게 된다. 확장자로 형식을 고른다.
    """
    from .report import build

    assets = []
    for pattern in args.assets:
        p = Path(pattern)
        assets.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
    if not assets:
        sys.stderr.write("자산 파일을 찾지 못했습니다: %s\n" % args.assets)
        return 2

    bodies, objs = [], []
    for ap in assets:
        bodies.append(bounded_json_load(ap))
        objs.append(load_asset(ap))

    advisories = []
    for pattern in (args.advisory or ()):
        p = Path(pattern)
        for q in (sorted(p.glob("*.json")) if p.is_dir() else [p]):
            advisories.append(load_advisory(q))

    kev = None
    snap = args.kev or find_snapshot()
    if snap:
        kev = load_kev(snap)
    topo = load_topology(args.topology) if args.topology else None

    sys.stdout.write("보고서를 만듭니다 — 자산 %d대 · 권고문 %d건 · 기준 시점 %s\n"
                     % (len(objs), len(advisories), args.as_of))
    rep = build(bodies=bodies, assets=objs, advisories=advisories,
                as_of=args.as_of, topology=topo, kev=kev,
                policy=_policy(args), lens=args.lens)

    out = Path(args.out)
    suffix = out.suffix.lower()
    if suffix == ".xlsx":
        from .report_xlsx import write as _write
    elif suffix == ".csv":
        from .report_html import write_csv as _write
    elif suffix in (".html", ".htm"):
        from .report_html import write as _write
    else:
        sys.stderr.write("확장자로 형식을 고릅니다 — .xlsx · .html · .csv 중에서 "
                         "주세요 (받은 것: %s)\n" % (suffix or "없음"))
        return 2

    try:
        path = _write(rep, out)
    except UnsafeInput as exc:
        sys.stderr.write("%s\n" % exc)
        return 2

    size = path.stat().st_size
    sys.stdout.write("%s  (%.1fKB)\n" % (path, size / 1024))
    sys.stdout.write("  할 일 %d건 · 통신 방식 위험 %d건 · 점검 항목 %d행 · "
                     "자산 %d대\n" % (len(rep.actions), len(rep.exposures),
                                    len(rep.controls), len(rep.assets)))
    if rep.synthetic_assets:
        sys.stdout.write("  합성 자산 %d대가 포함됐습니다 — 보고서가 그 사실을 "
                         "싣습니다\n" % rep.synthetic_assets)
    for c in rep.thin_vendors:
        sys.stdout.write("  주의: %s 자산 %d대 · 공개 권고문 %d건 — CVE 축이 "
                         "비고 **안전하다는 뜻이 아닙니다**\n"
                         % (c.vendor, c.our_assets, c.advisories))
    if suffix in (".html", ".htm"):
        sys.stdout.write("  브라우저에서 열어 '인쇄 → PDF 로 저장' 하면 됩니다 "
                         "(외부 자원 0개)\n")
    _audit(args, "report_written", subject=str(path),
           detail={"format": suffix.lstrip("."), "assets": len(rep.assets),
                   "actions": len(rep.actions), "bytes": size})
    return 0


def _cmd_controls(args) -> int:
    """점검 항목에 **근거를 댄다** — 준수 여부를 판정하지 않는다 (ADR-043/044).

    규칙을 다시 쓰지 않는다. `queue` 와 **같은 파이프라인**으로 판정·노출·도달성을
    만들고 그것을 근거로 넘긴다 — 여기서 따로 계산하면 두 화면이 다른 수를 말한다.
    """
    from .controls import evidence_for, load_all
    from .controls_view import render_controls
    from .exposure import find as find_exposure

    sets = load_all(args.standards)
    if not sets:
        sys.stderr.write("점검 항목 표가 없습니다: %s\n" % args.standards)
        return 2
    if args.standard:
        want = args.standard.lower()
        sets = [cs for cs in sets if want in cs.standard_id.lower()]
        if not sets:
            sys.stderr.write("그런 표준이 없습니다: %s\n" % args.standard)
            return 2

    asset = load_asset(args.asset)
    topo = load_topology(args.topology) if args.topology else None
    # **`queue` 와 같은 입력을 준다.** `kev` 와 `max_cvss` 를 빼면 H01·H03 이 절대
    # 발화하지 않는다 — 지금은 `hard_rule_H01` 을 가리키는 항목이 없어서 안 보이지만,
    # 누군가 더하는 순간 CLI 에서만 조용히 침묵하게 된다 (ADR-044 의 그 함정이다).
    snap = args.kev or find_snapshot()
    kev = load_kev(snap) if snap else None

    # 적용성 판정 — queue 와 같은 사전 필터를 거친다 (ADR-030)
    from .identity import could_match, index_advisory
    findings = []
    for pattern in (args.advisory or ()):
        p = Path(pattern)
        for ap in (sorted(p.glob("*.json")) if p.is_dir() else [p]):
            adv = load_advisory(ap)
            if not could_match(asset, index_advisory(adv)):
                continue              # 건너뛴 쌍은 no_known_match 로 확정이다
            d = decide_applicability(asset, adv, as_of=args.as_of)
            findings.append(evaluate_priority(
                d, asset, kev=kev, max_cvss=_max_cvss(adv, d.cves),
                topology=topo, lens="default"))

    # 노출은 (발견, 질문) 튜플을 돌려준다 — 풀어서 넘긴다
    h02 = any("H02" in (f.fired_rules or ()) for f in findings)
    exposures, _questions = find_exposure(asset, topology=topo, as_of=args.as_of,
                                          h02_fired=h02)
    reach = (evaluate_reachability(topo, asset.asset_id, as_of=args.as_of)
             if topo else None)

    endpoints = ()
    if args.capture:
        from .capture import scan_capture
        endpoints = tuple(sorted(scan_capture(args.capture).endpoints))

    reports = [(cs, [evidence_for(c, asset, findings=findings,
                                  exposures=exposures, reachability=reach,
                                  capture_endpoints=endpoints)
                     for c in cs.controls])
               for cs in sets]

    # '대조한 수' 와 '해당한 수' 는 다르다. 전자만 쓰면 큰 수가 근거처럼 읽힌다.
    seen = ["권고문 %d건 대조" % len(findings),
            "토폴로지 %s" % ("있음" if topo else "없음 — 도달성은 미상으로 남는다"),
            "캡처 %s" % ("끝점 %d개" % len(endpoints) if endpoints else "없음"),
            "노출 %d건" % len(exposures)]

    if args.json:
        out = json.dumps(
            [{"standard": cs.standard_id,
              "controls": [{"code": e.control.code, "status": e.status,
                            "status_ko": e.status_ko,
                            "our_scope": e.control.our_scope,
                            "basis": list(e.basis),
                            "pointers": list(e.pointers)} for e in evs]}
             for cs, evs in reports],
            ensure_ascii=False, sort_keys=True, indent=2)
    else:
        out = render_controls(reports, asset.asset_id, args.as_of,
                              show_all=args.all, inputs=seen)
    sys.stdout.write(out + "\n")
    _audit(args, "controls_evidence_listed", subject=asset.asset_id,
           detail={"standards": [cs.standard_id for cs, _ in reports],
                   "advisories_compared": len(findings),
                   "topology": bool(topo), "capture_endpoints": len(endpoints)})
    return 0


def _cmd_capture(args) -> int:
    """캡처 파일에서 토폴로지를 만든다. **장비에 붙지 않는다** (불변 규칙 6).

    관측된 통신만 담는다 — 캡처는 시간 창이라 안 보인 경로가 없는 것이 아니다.
    Purdue 레벨과 구역은 패킷에 없어 비워 두고, 사람이 채워야 한다.
    """
    from .capture import address_proposals, merge_address, scan_capture, to_topology
    from .zonemap import apply_zonemap, load_zonemap, template

    scan = scan_capture(args.file)
    doc = to_topology(scan)

    # 구역 선언을 적용한다. **선언은 관측이 아니다** — 누가 적었는지 증거에 남는다.
    zres = None
    if args.zones:
        zres = apply_zonemap(doc, load_zonemap(args.zones))

    if args.zones_template:
        Path(args.zones_template).write_text(
            json.dumps(template(doc), ensure_ascii=False, indent=1) + "\n",
            encoding="utf-8")
        sys.stdout.write("구역 선언 서식: %s — zone 과 purdue_level 을 채워 "
                         "`--zones` 로 주세요\n" % args.zones_template)

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
    if zres is not None:
        sys.stdout.write("\n구역 선언 — %s\n" % args.zones)
        sys.stdout.write("  %d대에 레벨·구역을 채웠습니다" % zres.declared)
        if zres.entry_points:
            sys.stdout.write(" · 진입점 %d개 (%s)"
                             % (len(zres.entry_points),
                                ", ".join(zres.entry_points[:4])))
        sys.stdout.write("\n  **선언한 값은 관측이 아닙니다** — 통신(엣지)만 캡처에서\n"
                         "  본 것이고, 레벨·구역은 사람이 적은 값으로 증거에 남습니다.\n")
        if not zres.entry_points:
            sys.stdout.write("  진입점이 하나도 선언되지 않았습니다 — 도달성은 "
                             "**미상**으로 남습니다.\n  '닿지 않는다' 가 아닙니다 "
                             "(ADR-045).\n")

    need = [n["node_id"] for n in doc["nodes"] if n["purdue_level"] is None]
    if need:
        sys.stdout.write(
            "\n다음에 할 일 — 아래 %d대의 **Purdue 레벨과 구역**을 채워 주세요.\n"
            "  채우기 전에는 도달성이 확정되지 않고 H01~H03 이 발화하지 않습니다.\n"
            "  `--zones-template z.json` 으로 서식을 받아 채운 뒤 `--zones z.json`.\n"
            % len(need))
        for nid in need[:20]:
            sys.stdout.write("    %s\n" % nid)
        if len(need) > 20:
            sys.stdout.write("    … 외 %d대\n" % (len(need) - 20))

    # 캡처가 본 주소를 **이미 선언된 자산에만** 제안한다 (ADR-042).
    if args.topology:
        from .topology import load_topology as _lt
        props, unlinked = address_proposals(scan, _lt(args.topology))
        sys.stdout.write("\n자산에 붙일 주소 — 토폴로지가 선언한 것만\n")
        if not props:
            sys.stdout.write("  없음. 토폴로지에 asset_id 와 IP 를 함께 적어야 이어집니다.\n")
        for p in props:
            a = p["address"]
            sys.stdout.write("  %-18s → %-24s IP %s%s%s\n"
                             % (a["ip"], p["asset_id"], a["ip"],
                                " · MAC %s" % a["mac"] if a.get("mac") else
                                (" · MAC 여럿이라 뺌" if p["mac_ambiguous"] else ""),
                                " · VLAN %s" % a["vlan"] if a.get("vlan") else ""))
        if unlinked:
            sys.stdout.write("  어느 자산인지 모르는 주소 %d개: %s%s\n"
                             % (len(unlinked), ", ".join(unlinked[:6]),
                                " 외" if len(unlinked) > 6 else ""))
        if args.apply_addresses:
            if not args.assets:
                sys.stdout.write("\n--apply-addresses 에는 --assets 가 필요합니다.\n")
                return 2
            n = 0
            for p in props:
                f = args.assets / ("%s.json" % p["asset_id"])
                if not f.exists():
                    sys.stdout.write("  자산 파일 없음: %s\n" % f.name)
                    continue
                body = bounded_json_load(f)
                if merge_address(body, p["address"]):
                    f.write_text(json.dumps(body, ensure_ascii=False, indent=1,
                                            sort_keys=True) + "\n", encoding="utf-8")
                    n += 1
            _audit(args, "capture_applied", subject=str(args.file),
                   detail={"sha256": scan.sha256, "addresses": n})
            sys.stdout.write("\n자산 %d개에 주소를 더했습니다 (덮어쓰지 않습니다).\n" % n)
        elif props:
            sys.stdout.write("  **아직 쓰지 않았습니다.** "
                             "--apply-addresses --assets <디렉터리> 로 더합니다.\n")

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
    """CSV 또는 엑셀 자산대장을 읽는다. 기본은 dry-run 이다.

    엑셀은 **머리글 행을 짐작하지 않는다** — 후보를 보여주고, 사람이 고른 것을
    프로파일에 남겨 다음 달에 다시 묻지 않는다 (ADR-046).
    """
    from .csvimport import (ImportProfile, build_report_from_rows, load_profile,
                           save_profile)

    if not args.csv and not args.xlsx:
        sys.stderr.write("--csv 또는 --xlsx 중 하나는 주셔야 합니다.\n")
        return 2

    profile = None
    mapping = None
    if args.profile:
        try:
            profile = load_profile(args.profile)
            mapping = dict(profile.mapping)
            sys.stdout.write("프로파일 '%s' 를 씁니다%s\n"
                             % (profile.name,
                                " — %s" % profile.note if profile.note else ""))
        except (UnsafeInput, FileNotFoundError, OSError) as exc:
            sys.stderr.write("프로파일을 읽지 못했습니다: %s\n" % exc)
            return 2
    if args.mapping:
        # 명시한 매핑 파일이 프로파일보다 세다 — 사람이 지금 준 것이다
        mapping = dict(mapping or {})
        mapping.update(bounded_json_load(args.mapping))

    existing = []
    if args.out.exists():
        existing = [q.stem for q in args.out.glob("*.json")]

    source = args.xlsx or args.csv
    reports = []
    try:
        if args.xlsx:
            from .xlsxread import rows_of, scan
            sheets = scan(args.xlsx)
            chosen = _choose_sheets(sheets, args, profile)
            if chosen is None:
                return 0 if not args.apply else 2
            for name, header_row in chosen:
                hdr, rows = rows_of(args.xlsx, name, header_row)
                rep = build_report_from_rows(
                    hdr, rows, "%s-%s" % (Path(args.xlsx).stem, name),
                    mapping_override=mapping, existing_ids=existing)
                existing.extend(r.asset_id for r in rep.results
                                if r.action == "create" and r.asset_id)
                reports.append((name, header_row, rep))
        else:
            reports.append((None, None, build_report(args.csv, mapping,
                                                     existing_ids=existing)))
    except UnsafeInput as exc:
        sys.stdout.write("거부: %s\n" % exc)
        _audit(args, "import_dry_run", subject=str(source),
               detail={"rejected": str(exc)})
        return 1

    total_written = 0
    for name, header_row, rep in reports:
        head = "자산대장 Import — %s" % source
        if name:
            head += "  [시트 %s · 머리글 %d행]" % (name, header_row)
        sys.stdout.write("\n" + head + "\n")
        sys.stdout.write("매핑: %s\n" % json.dumps(rep.mapping, ensure_ascii=False))
        for r in rep.results:
            if r.action != "create":
                sys.stdout.write("  %d행 %s: %s\n" % (r.line, r.action, r.message))
        if args.apply:
            written = apply_report(rep, args.out)
            total_written += len(written)
            sys.stdout.write("자산 파일 %d개 작성\n" % len(written))
        sys.stdout.write(rep.summary() + "\n")
        _vendor_coverage_notice(rep)

    if args.apply:
        _audit(args, "import_applied", subject=str(source),
               detail={"created": total_written,
                       "sheets": [n for n, _h, _r in reports if n]})
    else:
        _audit(args, "import_dry_run", subject=str(source),
               detail={"rows": sum(r.rows for _n, _h, r in reports),
                       "created": sum(r.created for _n, _h, r in reports)})

    if args.save_profile:
        prof = ImportProfile(
            name=args.save_profile,
            mapping={h: f for _n, _h, rep in reports for h, f in rep.mapping.items()},
            sheets={n: h for n, h, _r in reports if n},
            note=profile.note if profile else None)
        where = save_profile(prof)
        sys.stdout.write("\n매핑을 %s 에 저장했습니다 — 다음 달에는 "
                         "`--profile %s` 만 주시면 됩니다.\n"
                         % (where, args.save_profile))
    return 0


def _choose_sheets(sheets, args, profile):
    """어느 시트를 어느 머리글 행으로 읽을지 정한다. **짐작하지 않는다.**

    순서: ① 프로파일에 적혀 있으면 그대로 ② `--sheet 이름:행` 으로 주면 그대로
    ③ 아무것도 없으면 **후보만 보여주고 멈춘다.** 자동으로 고르면, 병합된 제목
    행이나 데이터 행을 머리글로 삼은 채 800대가 들어온다.
    """
    pinned = {}
    if profile and profile.sheets:
        pinned.update(profile.sheets)
    for spec in (args.sheet or ()):
        if ":" not in spec:
            sys.stderr.write("--sheet 는 '시트이름:머리글행' 형식입니다: %s\n" % spec)
            return None
        name, _, row = spec.rpartition(":")
        try:
            pinned[name] = int(row)
        except ValueError:
            sys.stderr.write("머리글 행이 숫자가 아닙니다: %s\n" % spec)
            return None

    found = {s.name: s for s in sheets}
    if pinned:
        bad = [n for n in pinned if n not in found]
        if bad:
            sys.stderr.write("그런 시트가 없습니다: %s (있는 것: %s)\n"
                             % (", ".join(bad), ", ".join(found)))
            return None
        return [(n, pinned[n]) for n in pinned]

    sys.stdout.write("시트 %d개를 봤습니다. **머리글 행을 짐작하지 않습니다** — "
                     "후보를 보여드립니다.\n\n" % len(sheets))
    for s in sheets:
        if not s.candidates:
            sys.stdout.write("  [%s] 아는 머리글이 없습니다 — 열 이름을 확인해 "
                             "주세요\n" % s.name)
            continue
        for c in s.candidates[:3]:
            sys.stdout.write("  [%s] %2d행  %-3s  걸린 열 %d개: %s\n"
                             % (s.name, c.row, c.stars, c.score,
                                ", ".join(c.recognized)))
    best = [(s.name, s.best.row) for s in sheets if s.best]
    sys.stdout.write("\n이대로 읽으려면:\n  %s\n"
                     % " ".join("--sheet %s:%d" % (n, r) for n, r in best))
    sys.stdout.write("그리고 `--save-profile <이름>` 을 붙이면 다음 달에는 "
                     "`--profile <이름>` 만으로 끝납니다.\n")
    return None


#: 공개 권고문이 거의 없는 제조사. **숫자는 실측이다** (`scripts/inventory.py`).
#: 이 사실을 말하지 않으면 '알려진 일치 없음' 이 '안전' 으로 읽힌다 (불변 규칙 1).
THIN_COVERAGE_HINT = (
    "LS ELECTRIC", "LSIS", "Omron", "Keyence", "Panasonic", "Hyundai",
    "Doosan", "Hanwha", "HD현대", "오므론", "엘에스",
)


def _vendor_coverage_notice(rep) -> None:
    """공개 권고문이 희박한 제조사가 들어오면 **그 사실을 말한다.**

    CVE 축이 비어 있는 것과 안전한 것은 다르다. 이 안내가 없으면 현업자가
    '우리 설비는 깨끗하다' 로 읽는다 — 이 제품이 막으려는 바로 그 오독이다.
    """
    seen = {}
    for r in rep.results:
        if r.action != "create" or not r.asset:
            continue
        v = ((r.asset.get("identity") or {}).get("vendor_raw") or "").strip()
        if not v:
            continue
        for hint in THIN_COVERAGE_HINT:
            if hint.lower() in v.lower():
                seen[v] = seen.get(v, 0) + 1
                break
    if not seen:
        return
    sys.stdout.write("\n주의 — 공개 권고문이 희박한 제조사가 있습니다\n")
    for v, n in sorted(seen.items(), key=lambda kv: -kv[1]):
        sys.stdout.write("  %s %d대\n" % (v, n))
    sys.stdout.write(
        "  이 제조사는 기계 판독 가능한 권고문(CSAF)을 거의 내지 않습니다. "
        "그래서 CVE 축은\n"
        "  비어 있을 수 있고 **안전하다는 뜻이 아닙니다.** 이 설비는 통신 방식 "
        "위험·공격 경로·\n"
        "  점검 항목 근거로 봅니다 — 그 축은 권고문 없이도 돕니다.\n")



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
    q.add_argument("--data", type=Path, default=None,
                   help="정책 디렉터리 (기본: ./data). 승인된 정책으로 판정한다")
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

    zk = _audited(sub.add_parser(
        "zeek", help="Zeek·ICSNPP 로그에서 토폴로지와 관측 식별 (장비 접속 안 함)"))
    zk.add_argument("--logs", required=True, nargs="+", type=Path,
                    help="Zeek 로그 디렉터리 또는 파일 (.log · .log.gz · JSON)")
    zk.add_argument("--zones", type=Path, default=None,
                    help="구역 선언 — 레벨·구역·진입점을 사람이 적은 것")
    zk.add_argument("--assets", type=Path, default=None,
                    help="자산을 선언한 토폴로지. 주면 관측 식별을 그 자산에 제안한다")
    zk.add_argument("--out", type=Path, default=None, help="토폴로지 JSON 출력 경로")
    zk.add_argument("--as-of", required=True, dest="as_of")
    zk.set_defaults(func=_cmd_zeek)

    tp = _audited(sub.add_parser(
        "topology", help="자산대장의 구역으로 토폴로지 골격 만들기"))
    tp.add_argument("--assets", required=True, nargs="+", type=Path,
                    help="자산 JSON 파일 또는 디렉터리")
    tp.add_argument("--site", type=Path, default=None,
                    help="사이트 프로파일 — 구역의 레벨·안전 중요도·구역 간 연결")
    tp.add_argument("--site-template", type=Path, default=None,
                    dest="site_template",
                    help="대장에 보이는 구역으로 빈 서식을 만든다 (값은 비워 둔다)")
    tp.add_argument("--out", type=Path, default=Path("out/topology.json"))
    tp.add_argument("--as-of", required=True, dest="as_of")
    tp.set_defaults(func=_cmd_topology)

    rp = _audited(sub.add_parser(
        "report", help="보고서 — 엑셀·인쇄용 HTML·CSV (확장자로 고릅니다)"))
    rp.add_argument("--assets", required=True, nargs="+", type=Path,
                    help="자산 JSON 파일 또는 디렉터리")
    rp.add_argument("--advisory", nargs="+", type=Path, default=None,
                    help="CSAF 2.0 권고 JSON (파일 또는 디렉터리)")
    rp.add_argument("--topology", type=Path, default=None,
                    help="없으면 도달성은 미상으로 남는다")
    rp.add_argument("--kev", type=Path, default=None,
                    help="KEV 스냅샷 (기본: data/kev 의 최신)")
    rp.add_argument("--lens", default="default", choices=sorted(LENS_PRESETS),
                    help="렌즈는 같은 등급 안의 순서만 바꿉니다")
    rp.add_argument("--data", type=Path, default=None,
                    help="정책 디렉터리 (기본: ./data)")
    rp.add_argument("--out", required=True, type=Path,
                    metavar="보고서.xlsx|.html|.csv")
    rp.add_argument("--as-of", required=True, dest="as_of")
    rp.set_defaults(func=_cmd_report)

    ct = _audited(sub.add_parser(
        "controls", help="점검 항목에 근거를 댄다 (준수 판정 아님)"))
    ct.add_argument("--asset", required=True, type=Path, help="자산 JSON 1건")
    ct.add_argument("--advisory", nargs="+", type=Path, default=None,
                    help="CSAF 2.0 권고 JSON (파일 또는 디렉터리)")
    ct.add_argument("--topology", type=Path, default=None,
                    help="없으면 도달성은 미상으로 남는다 — '분리됐다' 가 아니다")
    ct.add_argument("--capture", type=Path, default=None,
                    help="pcap·pcapng — 그 시간 창에 통신한 끝점을 근거로 쓴다")
    ct.add_argument("--kev", type=Path, default=None,
                    help="KEV 스냅샷 경로 (기본: data/kev 의 최신). H01 의 전제조건이다")
    ct.add_argument("--standards", type=Path, default=Path("data/controls"),
                    help="점검 항목 표 디렉터리 (기본: data/controls)")
    ct.add_argument("--standard", default=None,
                    help="표준 하나만 (예: kisa, nist). 기본은 실린 전부")
    ct.add_argument("--all", action="store_true",
                    help="도구가 답할 수 없는 항목까지 전부 표시")
    ct.add_argument("--json", action="store_true")
    ct.add_argument("--as-of", required=True, dest="as_of")
    ct.set_defaults(func=_cmd_controls)

    cap = _audited(sub.add_parser(
        "capture", help="캡처(pcap·pcapng)에서 토폴로지 만들기 (기본 dry-run)"))
    cap.add_argument("--file", required=True, type=Path, help="pcap 또는 pcapng")
    cap.add_argument("--out", type=Path, default=None, help="토폴로지 JSON 출력 경로")
    cap.add_argument("--topology", type=Path, default=None,
                     help="자산을 선언한 토폴로지. 주면 캡처가 본 주소를 그 자산에 제안한다")
    cap.add_argument("--assets", type=Path, default=None, help="자산 JSON 디렉터리")
    cap.add_argument("--apply-addresses", action="store_true", dest="apply_addresses",
                     help="제안한 주소를 자산 파일에 실제로 더한다 (기본은 dry-run)")
    cap.add_argument("--zones", type=Path, default=None,
                     help="구역 선언 파일 — Purdue 레벨·구역·진입점을 사람이 적은 것")
    cap.add_argument("--zones-template", type=Path, default=None,
                     dest="zones_template",
                     help="보이는 대역으로 빈 선언 서식을 만든다 (값은 비워 둔다)")
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

    im = _audited(sub.add_parser(
        "import", help="자산대장 Import — CSV·엑셀 (기본 dry-run)"))
    im.add_argument("--csv", type=Path, default=None,
                    help="CSV 자산대장. UTF-8 과 CP949 를 모두 읽습니다")
    im.add_argument("--xlsx", type=Path, default=None,
                    help="엑셀 자산대장(.xlsx). 머리글 행은 짐작하지 않고 후보를 보여줍니다")
    im.add_argument("--sheet", action="append", default=None, metavar="시트:행",
                    help="읽을 시트와 머리글 행 (여러 번 줄 수 있습니다)")
    im.add_argument("--profile", default=None,
                    help="저장해 둔 매핑 프로파일 이름 또는 경로")
    im.add_argument("--save-profile", default=None, dest="save_profile",
                    metavar="이름", help="이번 매핑과 시트 선택을 그 이름으로 저장")
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
